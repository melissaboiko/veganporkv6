Simple but convenient, and most importantly ipv6-aware, script to update your
Porkbun DNS.  Can get your IP from a network interface, Porkbun ping, or a
cmdline arg.  See `--help` for usage.

Untested, but I'm using it on my OpenWRT router and it's working so far.

Dependencies (apt, opkg or pip):

 - netifaces
 - requests

Example manual call:

    $ ./veganporkv6.py --v6 dyn.example.com -i pppoe-wan --dry-run
    $ ./veganporkv6.py --v6 dyn.example.com -i pppoe-wan

Example cron (after you configured your .json and tested):

```
*/5 * * * * /path/to/veganporkv6.py --v4 dyn.example.com --v6 dyn.example.com -i pppoe-wan --quiet
```

--Melissa
