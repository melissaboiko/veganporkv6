#!/usr/bin/env python3
import os
import sys
import re
import pathlib
import socket
import argparse
import logging as l
import logging.handlers
import json
import json.decoder
from copy import copy
from ipaddress import ip_address, IPv6Address, IPv4Address

import netifaces
import requests
import requests.packages.urllib3.util.connection as urllib3_cn

CONFFILE = 'veganporkv6.json'
EXAMPLE_CONFFILE='''
--------------------------------------------------------------------------------
{
  "endpoint":"https://porkbun.com/api/json/v3",
  "apikey": "<your_api_key_here>",
  "secretapikey": "<your_secret_api_key>"
  "rootdomain": "https://yourdomain.example.com",
}
--------------------------------------------------------------------------------
'''

def setup():
    setup_logging()
    l.debug('Running veganporkv6.')
    args = setup_arguments()

    if args.quiet:
        l.getLogger().setLevel(l.ERROR)
    elif args.debug:
        l.getLogger().setLevel(l.DEBUG)
    l.debug('Command-line args: %s', args)

    fill_in_args(args)
    return(args)

def run(args):
    get_ips(args)
    records = get_records(args)
    if args.v6domains:
        for domain in args.v6domains:
            update_address(domain, args.ipv6, records, args, dnstype='AAAA')
    if args.v4domains:
        for domain in args.v4domains:
            update_address(domain, args.ipv4, records, args, dnstype='A')


def setup_logging():
    l.basicConfig(
        level=l.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            l.StreamHandler(sys.stdout),
            logging.handlers.SysLogHandler()
        ]
    )


def setup_arguments():
    parser = argparse.ArgumentParser(
        description='Porkbun API Dynamic DNS updates for IPv6 (and, ugh, IPv4).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
 
All options can be provided in the configuration JSON file.
Mandatory information:
 - root domain of your account.
 - API keys (obligatorily in configuration file).
 - a list of v6 subdomains to update, v4, or both.
 - A method to find out our current external IPs.  It is recommended to run this
   on the border gateway, and use `-i` to inspect the Linux interfaces.
   Alternatively, determine the target IP through a reliable method and pass it
   via `--ipv6` / `--ipv4`.

Example conffile:
''' + EXAMPLE_CONFFILE
)
    parser.add_argument(
        '-c', '--conffile', type=pathlib.Path,
        help='location of json config '
        f' (default: search for `{CONFFILE}\') in standard dirs',
    )

    parser.add_argument(
        '-i', '--interface',
        help='look for the IPv6/IPv4 addresses in this interface'
        ' (will ignore private/local/multicast addresses)',
    )
    parser.add_argument(
        '-a', '-6', '--ipv6', '--AAAA', type=IPv6Address,
        help='set the IPv6 to this address',
    )
    parser.add_argument(
        '-A', '-4', '--ipv4', type=IPv4Address,
        help='set the IPv4 to this address',
    )
    parser.add_argument(
        '-t', '--TTL', type=int, default=300,
        help='Time-to-live DNS setting (default: 300)',
    )

    parser.add_argument(
        '--auto-ipv6', action='store_true',
        help='Ask the Porkbun API for our external IPv6'
        ' (notice this might get one you didn\'t mean).'
    )
    parser.add_argument(
        '--auto-ipv4', action='store_true',
        help='Ask the Porkbun API for our external IPv4'
        ' (notice this might get one you didn\'t mean).'
    )
    parser.add_argument(
        '--v6domains', type=lambda s: s.split(','),
        help='comma-separated list of v6 subdomains to update',
    )
    parser.add_argument(
        '--v4domains', type=lambda s: s.split(','),
        help='comma-separated list of v4 subdomains to update',
    )
    parser.add_argument(
        'rootdomain', nargs='?',
        help='the root domain of your account (not what you\'re updating!'
    )

    parser.add_argument(
        '-q', '--quiet', action='store_true',
        help='only print messages when there are errors'
    )
    parser.add_argument(
        '-d', '--debug', action='store_true',
        help='print a programmer\'s step-by-step'
    )
    parser.add_argument(
        '--dry-run', action='store_true',
        help='Don\'t change the data, just show what would\'ve been done.',
    )

    return parser.parse_args()


def fill_in_args(args):
    if not args.conffile:
        args.conffile = find_conffile()
        if not args.conffile:
            l.error('No conffile found.')
            sys.stderr.write(f'''
Couldn't find a `{CONFFILE}` file anywhere!
Please create one in your home or current dir, or pass a path with `-c`.
Fill in the contents with your API keys like this:
''' + EXAMPLE_CONFFILE + '''
You can create keys by signing in to Porkbun, then clicking the 'Account' menu.
All long options described in --help can also be set via the conffile.
'''
                             )
            sys.exit(2)

    l.info('Loading "%s".', args.conffile)
    with open(args.conffile, 'rt') as f:
        try:
            json_config = json.load(f)
        except json.decoder.JSONDecodeError as e:
            l.error("Error parsing JSON syntax in %s:", args.conffile)
            sys.stderr.write(str(e))
            sys.exit(2)

    argsdict = vars(args)
    for json_key, json_val in json_config.items():
        if json_key not in argsdict or argsdict[json_key] is None:
            # last minute adjust log levels
            if 'debug' not in argsdict and json_key == 'quiet' and json_val:
                l.getLogger().setLevel(l.ERROR)
            elif 'quiet' not in argsdict and json_key == 'debug' and json_val:
                l.getLogger().setLevel(l.DEBUG)

            l.debug("Setting '%s' from conffile.", json_key)
            setattr(args, json_key, json_val)
        else:
            l.debug("Ignoring conffile option '{json_key}' "
                    "in favour of command-line.",
                   json_key)

    l.debug("Merged args: %s", safe_print(vars(args)))


def safe_print(adict):
    d = copy(adict)
    keys = d.keys()
    if 'apikey' in keys:
        d['apikey'] =  '"<private>"'
    if 'secretapikey' in keys:
        d['secretapikey'] = '"<private>"'
    return str(d)


def find_conffile():
    home = os.environ.get('HOME')
    default_config_paths = [
        home,
        '/etc',
        '.'
    ]
    try:
        from xdg import xdg_config_home, xdg_config_dirs
        xdg_config_dirs = [str(path) for path in [xdg_config_home()] + xdg_config_dirs()]
        if not xdg_config_dirs:
            xdg_config_dirs = (home + '/.config')
        default_config_paths = xdg_config_dirs + default_config_paths
    except Exception as e:
        default_config_paths.insert(0, home + '/.config')

    default_config_paths.append(str(pathlib.Path(__file__).parent))
    l.debug('Searching for conffile in: %s', default_config_paths)
    for path in default_config_paths:
        attempt = path + '/' + CONFFILE
        if os.path.isfile(attempt):
            return(attempt)
    return None


def get_ips(args):
    if not args.v6domains and not args.v4domains:
        l.error('No domain given to update.')
        sys.stderr.write("""
Please use the `v6domains' and/or `v4domains' options
to define what subdomains to update.
""")
        sys.exit(2)

    if (args.v6domains
        and not args.ipv6
        and not args.interface
        and not args.auto_ipv6):
        l.error('v6domains with no method to find address.')
        sys.stderr.write("""
Please pick a method to determine the current IPv6, either
--ipv6, --interface or (not recommended) --auto-ipv6.
""")
        sys.exit(2)

    if (args.v4domains
        and not args.ipv4
        and not args.interface
        and not args.auto_ipv4):
        l.error('v4domains with no method to find address.')
        sys.stderr.write("""
Please pick a method to determine the current IPv4, either
--ipv4, --interface or (not recommended) --auto-ipv4.
""")
        sys.exit(2)

    if args.v6domains and not args.ipv6:
        if args.interface:
            l.debug("Picking ipv6 from interface %s", args.interface)
            args.ipv6 = ip_from_interface(args, family='ipv6')
        elif args.auto_ipv6:
            l.debug("Fetching ipv6 from Porkbun API")
            args.ipv6 = ip_from_porkbun(args, family='ipv6')
        if not args.ipv6:
            l.error("Could not determine our external ipv6, sorry!")
            sys.exit(2)

    if args.v4domains and not args.ipv4:
        if args.interface:
            l.debug("Picking ipv4 from interface %s", args.interface)
            args.ipv4 = ip_from_interface(args, family='ipv4')
        elif args.auto_ipv4:
            l.debug("Fetching ipv4 from Porkbun API")
            args.ipv4 = ip_from_porkbun(args, family='ipv4')
        if not args.ipv4:
            l.error("Could not determine our external ipv6, sorry!")
            sys.exit(2)


def ip_from_interface(args, family='ipv6'):
    if family == 'ipv6':
        ipfamily = netifaces.AF_INET6
        iptype = IPv6Address
    elif family == 'ipv4':
        ipfamily = netifaces.AF_INET
        iptype = IPv4Address
    else:
        raise(ArgumentError(family))

    addrs = netifaces.ifaddresses(args.interface)

    if ipfamily in addrs:
        ips = [iptype(a['addr']) for a in addrs[ipfamily]]
        l.debug('%s addresses: %s', family, ips)
        global_addrs = [ip for ip in ips
                        if ip.is_global and not ip.is_multicast]
        if not global_addrs:
            l.error("No global unicast %s addresses found in %s!",
                    family, args.interface)
            sys.exit(2)
        elif len(global_addrs) > 1:
            l.warning("More than one global %s address in %s: %s",
                      family, args.interface, global_addrs)
        l.info("Picking %s as target %s.", str(global_addrs[0]), family)
        return str(global_addrs[0])


def ip_from_socket(server, port=443, family='ipv6'):
    if family == 'ipv6':
        sfamily = socket.AF_INET6
    elif family == 'ipv4':
        l.warning("Using socket IP with IPv4 won't work behind NATs!")
        sfamily = socket.AF_INET
    else:
        raise(ArgumentError(family))

    s = socket.socket(sfamily, socket.SOCK_DGRAM)
    s.connect((server, port))
    return s.getsockname()[0]


def with_requests_family(family, callback):
    l.debug('requests monkey patch called with %s', family)

    if family == 'ipv4':
        family = socket.AF_INET
    elif family == 'ipv6':
        family = socket.AF_INET6


    def patch():
        return family

    l.debug('overriding urllib3_cn.allowed_gai_family to %s', patch())
    allowed_gai_family_orig = urllib3_cn.allowed_gai_family
    urllib3_cn.allowed_gai_family = patch

    ret = callback()

    l.debug('resetting urllib3_cn.allowed_gai_family')
    urllib3_cn.allowed_gai_family = allowed_gai_family_orig

    return ret


def porkcall(args, path, data={}, family=None):
    senddata = copy(data)
    argsdict = vars(args)
    for key in ('endpoint', 'apikey', 'secretapikey', 'rootdomain'):
        if key not in senddata:
            senddata[key] = argsdict[key]
    l.debug("Joining endpoint '%s' to path '%s'", senddata['endpoint'], path)
    if senddata['endpoint'][-1] == '/':
        senddata['endpoint'] = senddata['endpoint'][:-1]
    if path[0] == '/':
        path = path[1:]
    url = senddata['endpoint'] + '/' + path

    l.debug('Calling API on %s with request: %s', url, safe_print(senddata))
    if family:
        response = with_requests_family(
            family,
            lambda: requests.post(url, data=json.dumps(senddata))
        )
    else:
        response = requests.post(url, data=json.dumps(senddata))

    l.debug('Response: %s, text: %s', response, response.text)
    response.raise_for_status()
    if response.text:
        return json.loads(response.text)
    else:
        return None


def ip_from_porkbun(args, family):
    response = porkcall(args, '/ping/', family=family)
    l.info('Porkbun says our external %s is %s', family, response['yourIp'])
    return response['yourIp']


def ip_equal(addr1, addr2):
    if type(addr1) not in (IPv6Address, IPv4Address):
        addr1 = ip_address(addr1)
    if type(addr2) not in (IPv6Address, IPv4Address):
        addr2 = ip_address(addr2)

    if type(addr1) != type(addr2):
        return False
    else:
        return addr1 == addr2


def update_address(domain, address, records, args, dnstype='AAAA'):
    domainmatch = [r for r in records if r['name'] == domain and r['type'] == dnstype]
    if not domainmatch:
        l.info("Will create brand new domain record: %s %s", domain, dnstype)
        # for r in records:
        #     print(f"{r['name']}\t{r['type']}")
        create_record(domain, dnstype, address, args)
    else:
        if len(domainmatch) > 1:
            l.error("Domain %s has multiple %s address records.", domain, address)
            sys.exit(1)
        ipmatch = [r for r in domainmatch if ip_equal(r['content'], address)]
        if ipmatch:
            l.info("Ip %s already in %s %s record, passing.", address, domain, dnstype)
        else:
            for r in domainmatch:
                l.info("To update, will ~delete~ existing record for %s %s!", domain, dnstype)
                delete_record(r, args)
                create_record(domain, dnstype, address, args)

def args_to_json(args):
    keys =  ('endpoint', 'apikey', 'secretapikey', 'rootdomain')
    jsonargs = dict((key, getattr(args, key)) for key in keys)
    jsonargs['TTL'] = args.TTL
    return jsonargs

def get_records(args):
    path = f'/dns/retrieve/{args.rootdomain}'
    response = porkcall(args, path)
    l.debug('Status: %s, records: %s', response['status'],
            json.dumps(response['records'], sort_keys=True, indent=4))
    records = response['records']
    l.info("Fetched %d records for root domain %s", len(records), args.rootdomain)
    return(records)

def create_record(domain, dnstype, dnscontent, args):
    data = args_to_json(args)
    # porkbun returns 'name=foo.example.com' in the JSON for 'example.com', but when
    # creating a record you're required  to send just 'name=foo'
    data['name'] = re.sub(f'\.{args.rootdomain}$', '', 'dyn')

    data['type'] = dnstype
    data['content'] = dnscontent

    path = f'/dns/create/{args.rootdomain}'

    if args.dry_run:
        l.info("(Would have created record here via: '%s')", path)
        response = None
    else:
        response = porkcall(args, path, data=data)


    l.info("Created a record for: %s %s %s", domain, dnstype, dnscontent)
    return(response)

def delete_record(record, args):
    path = f'/dns/delete/{args.rootdomain}/{record["id"]}'
    try:
        l.info("Deleting existing record %s: %s %s: %s",
               record['id'], record['name'], record['type'], record['content'],
               )
    except KeyError:
        l.info("Deleting existing record %s", record)

    if args.dry_run:
        l.info("(Would have deleted old record here via: '%s')", path)
        response = None
    else:
        response = porkcall(args, path)
    return(response)


args = setup()
run(args )

# ipv4 = get_ipv4()
# ipv6 = get_ipv6()
