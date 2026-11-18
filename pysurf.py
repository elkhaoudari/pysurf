#!/usr/bin/env python3
import json
import os
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request

__author__ = "@elkhaoudari_abdelilah"

BANNER = f"""
  pysurf - transparent Tor routing
  by {__author__}
"""

TRANS_PORT, DNS_PORT, CONTROL_PORT = 9040, 5353, 9051
VIRT_NET = "10.192.0.0/10"
LAN = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

TORRC = "/etc/tor/pysurf.torrc"
DATA_DIR = "/var/lib/tor/pysurf"
LOG = f"{DATA_DIR}/tor.log"
PIDFILE = "/run/pysurf.pid"

STATE_DIR = "/var/lib/pysurf"
STATE_FILE = f"{STATE_DIR}/state.json"
RESOLV = "/etc/resolv.conf"
RESOLV_BACKUP = f"{STATE_DIR}/resolv.conf.bak"
IPV6_KEYS = ("all", "default")
CHECK_URL = "https://check.torproject.org/api/ip"

NAT_CHAIN, FILTER_CHAIN, FILTER6_CHAIN = "PYSURF_NAT", "PYSURF_FILTER", "PYSURF_FILTER6"


def sh(*args, check=True):
    try:
        r = subprocess.run(args, capture_output=True, text=True)
    except FileNotFoundError:
        if check:
            raise RuntimeError(f"{args[0]} not found")
        return 127
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}\n{r.stderr.strip()}")
    return r.returncode


def tor_user():
    for name in ("debian-tor", "tor", "toranon", "_tor"):
        try:
            return pwd.getpwnam(name)
        except KeyError:
            continue
    sys.exit("Could not find the Tor system user (is tor installed?)")


def is_running():
    try:
        pid = int(open(PIDFILE).read())
        os.kill(pid, 0)
        return True
    except (FileNotFoundError, ValueError, ProcessLookupError):
        return False


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {}


def save_state(state):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def read_ipv6():
    values = {}
    for key in IPV6_KEYS:
        try:
            with open(f"/proc/sys/net/ipv6/conf/{key}/disable_ipv6") as f:
                values[key] = f.read().strip()
        except FileNotFoundError:
            return {}
    return values


def write_ipv6(values):
    for key, value in values.items():
        try:
            with open(f"/proc/sys/net/ipv6/conf/{key}/disable_ipv6", "w") as f:
                f.write(value)
        except OSError:
            pass


def disable_ipv6(state):
    state["ipv6"] = read_ipv6()
    write_ipv6({key: "1" for key in IPV6_KEYS})
    save_state(state)
    print("[+] IPv6 disabled")


def restore_ipv6(state):
    if state.get("ipv6"):
        write_ipv6(state["ipv6"])
        print("[+] IPv6 restored")


def lock_dns(state):
    if os.path.islink(RESOLV):
        state["resolv"] = {"type": "link", "target": os.readlink(RESOLV)}
        os.unlink(RESOLV)
    elif os.path.exists(RESOLV):
        shutil.copy2(RESOLV, RESOLV_BACKUP)
        state["resolv"] = {"type": "file"}
    else:
        state["resolv"] = {"type": "none"}
    save_state(state)
    with open(RESOLV, "w") as f:
        f.write("nameserver 127.0.0.1\n")
    print("[+] DNS locked to Tor")


def restore_dns(state):
    info = state.get("resolv")
    if not info:
        return
    if os.path.lexists(RESOLV):
        os.unlink(RESOLV)
    if info["type"] == "link":
        os.symlink(info["target"], RESOLV)
    elif info["type"] == "file" and os.path.exists(RESOLV_BACKUP):
        shutil.copy2(RESOLV_BACKUP, RESOLV)
        os.remove(RESOLV_BACKUP)
    print("[+] DNS restored")


def stop_system_tor(state):
    if sh("systemctl", "is-active", "--quiet", "tor", check=False) == 0:
        sh("systemctl", "stop", "tor", check=False)
        state["system_tor"] = True
        save_state(state)
        print("[*] Stopped system tor service (will be restarted on stop)")


def busy_port():
    for port, kind in ((TRANS_PORT, socket.SOCK_STREAM),
                       (CONTROL_PORT, socket.SOCK_STREAM),
                       (DNS_PORT, socket.SOCK_DGRAM)):
        s = socket.socket(socket.AF_INET, kind)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return port
        finally:
            s.close()
    return None


def start_tor(user):
    os.makedirs(DATA_DIR, exist_ok=True)
    shutil.chown(DATA_DIR, user=user.pw_name)
    os.chmod(DATA_DIR, 0o700)
    open(LOG, "w").close()
    with open(TORRC, "w") as f:
        f.write(
            f"User {user.pw_name}\n"
            f"DataDirectory {DATA_DIR}\n"
            f"Log notice file {LOG}\n"
            "SocksPort 0\n"
            f"TransPort 127.0.0.1:{TRANS_PORT}\n"
            f"DNSPort 127.0.0.1:{DNS_PORT}\n"
            f"ControlPort 127.0.0.1:{CONTROL_PORT}\n"
            "CookieAuthentication 1\n"
            f"VirtualAddrNetworkIPv4 {VIRT_NET}\n"
            "AutomapHostsOnResolve 1\n"
            "ClientUseIPv6 0\n"
        )
    p = subprocess.Popen(["tor", "-f", TORRC], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    with open(PIDFILE, "w") as f:
        f.write(str(p.pid))
    print("[*] Waiting for Tor to bootstrap...")
    for _ in range(90):
        if p.poll() is not None:
            raise RuntimeError(f"Tor exited early, check {LOG}")
        with open(LOG) as f:
            if "Bootstrapped 100%" in f.read():
                print("[+] Tor is ready")
                return
        time.sleep(1)
    raise RuntimeError("Tor bootstrap timed out")


def stop_tor():
    try:
        os.kill(int(open(PIDFILE).read()), signal.SIGTERM)
    except (FileNotFoundError, ValueError, ProcessLookupError):
        pass
    if os.path.exists(PIDFILE):
        os.remove(PIDFILE)


def remove_rules():
    for tool, table, chain in (("iptables", "nat", NAT_CHAIN),
                               ("iptables", None, FILTER_CHAIN),
                               ("ip6tables", None, FILTER6_CHAIN)):
        base = [tool] + (["-t", table] if table else [])
        while sh(*base, "-D", "OUTPUT", "-j", chain, check=False) == 0:
            pass
        sh(*base, "-F", chain, check=False)
        sh(*base, "-X", chain, check=False)


def apply_rules(uid):
    uid = str(uid)
    remove_rules()

    sh("iptables", "-t", "nat", "-N", NAT_CHAIN)
    nat = lambda *a: sh("iptables", "-t", "nat", "-A", NAT_CHAIN, *a)
    nat("-m", "owner", "--uid-owner", uid, "-j", "RETURN")
    nat("-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", str(DNS_PORT))
    nat("-p", "tcp", "--dport", "53", "-j", "RETURN")
    nat("-d", VIRT_NET, "-p", "tcp", "-j", "REDIRECT", "--to-ports", str(TRANS_PORT))
    for net in LAN:
        nat("-d", net, "-j", "RETURN")
    nat("-p", "tcp", "--tcp-flags", "FIN,SYN,RST,ACK", "SYN",
        "-j", "REDIRECT", "--to-ports", str(TRANS_PORT))
    sh("iptables", "-t", "nat", "-I", "OUTPUT", "1", "-j", NAT_CHAIN)

    sh("iptables", "-N", FILTER_CHAIN)
    flt = lambda *a: sh("iptables", "-A", FILTER_CHAIN, *a)
    flt("-m", "owner", "--uid-owner", uid, "-j", "ACCEPT")
    flt("-p", "tcp", "--dport", "53", "-j", "REJECT", "--reject-with", "tcp-reset")
    flt("-p", "udp", "--dport", "53", "-j", "REJECT")
    for net in LAN:
        flt("-d", net, "-j", "ACCEPT")
    flt("-j", "REJECT")
    sh("iptables", "-I", "OUTPUT", "1", "-j", FILTER_CHAIN)

    sh("ip6tables", "-N", FILTER6_CHAIN, check=False)
    sh("ip6tables", "-A", FILTER6_CHAIN, "-o", "lo", "-j", "ACCEPT", check=False)
    sh("ip6tables", "-A", FILTER6_CHAIN, "-j", "REJECT", check=False)
    sh("ip6tables", "-I", "OUTPUT", "1", "-j", FILTER6_CHAIN, check=False)
    print("[+] Firewall rules applied")


def tor_check():
    with urllib.request.urlopen(CHECK_URL, timeout=30) as r:
        return json.load(r)


def verify(retries=3):
    for _ in range(retries):
        try:
            if tor_check().get("IsTor"):
                return True
        except Exception:
            pass
        time.sleep(3)
    return False


def control(commands):
    with open(f"{DATA_DIR}/control_auth_cookie", "rb") as f:
        cookie = f.read().hex()
    with socket.create_connection(("127.0.0.1", CONTROL_PORT), timeout=5) as s:
        s.sendall((f"AUTHENTICATE {cookie}\r\n" + commands + "QUIT\r\n").encode())
        time.sleep(1)
        return s.recv(4096).decode()


def cmd_start():
    if is_running():
        sys.exit("Already running. Use 'restart' or 'stop'.")
    if os.path.exists(STATE_FILE):
        print("[*] Leftover state from an unclean session found, restoring first")
        cmd_stop()
    for binary in ("tor", "iptables"):
        if shutil.which(binary) is None:
            sys.exit(f"{binary} is not installed")
    user = tor_user()
    state = {}
    try:
        stop_system_tor(state)
        port = busy_port()
        if port:
            raise RuntimeError(f"Port {port} is already in use")
        disable_ipv6(state)
        start_tor(user)
        apply_rules(user.pw_uid)
        lock_dns(state)
        if not verify():
            raise RuntimeError("Could not confirm the Tor connection")
    except Exception as e:
        print(f"[!] {e}")
        print("[*] Rolling back to the normal network state")
        cmd_stop()
        sys.exit(1)
    print("[+] All traffic now goes through Tor")
    cmd_status()


def cmd_stop():
    state = load_state()
    remove_rules()
    stop_tor()
    restore_dns(state)
    restore_ipv6(state)
    if state.get("system_tor"):
        sh("systemctl", "start", "tor", check=False)
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)
    print("[+] Stopped, normal network state restored")


def cmd_change():
    if not is_running():
        sys.exit("pysurf is not running")
    reply = control("SIGNAL NEWNYM\r\n")
    if reply.count("250") >= 2:
        print("[+] New identity requested")
    else:
        print(f"[!] Unexpected reply from Tor: {reply.strip()}")
    time.sleep(5)
    cmd_status()


def cmd_status():
    if not is_running():
        print("[-] pysurf is not running")
        return
    v6 = read_ipv6()
    v6_off = bool(v6) and all(value == "1" for value in v6.values())
    try:
        with open(RESOLV) as f:
            dns_locked = f.read().split() == ["nameserver", "127.0.0.1"]
    except FileNotFoundError:
        dns_locked = False
    print(f"[i] IPv6 disabled : {v6_off}")
    print(f"[i] DNS locked    : {dns_locked}")
    try:
        info = tor_check()
        print(f"[i] Through Tor   : {info.get('IsTor')}  (exit IP {info.get('IP')})")
    except Exception as e:
        print(f"[!] Could not verify Tor connection: {e}")


if __name__ == "__main__":
    print(BANNER)
    if os.geteuid() != 0:
        sys.exit("Run as root: sudo ./pysurf.py <command>")
    actions = {
        "start": cmd_start,
        "stop": cmd_stop,
        "status": cmd_status,
        "change": cmd_change,
        "restart": lambda: (cmd_stop(), cmd_start()),
    }
    if len(sys.argv) != 2 or sys.argv[1] not in actions:
        sys.exit("Usage: pysurf.py {start|stop|restart|change|status}")
    actions[sys.argv[1]]()
