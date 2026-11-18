# pysurf
AnonSurf-style transparent Tor routing in Python (Linux, root).
- Routes all TCP and DNS through Tor, blocks UDP and IPv6 leaks
- Disables IPv6 on start, restores IPv6, DNS and firewall on stop

Usage: `sudo python3 pysurf.py {start|stop|restart|change|status}`

By @elkhaoudari_abdelilah
