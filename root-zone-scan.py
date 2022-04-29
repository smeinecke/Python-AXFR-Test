#!/usr/bin/python3
import argparse
import socket
import logging
import dns.resolver
import dns.rdatatype
import requests
import tempfile
import subprocess
import shutil
import json
import re

from multiprocessing import Pool

skip_zones = ['com', 'net', 'asia', 'biz', 'org', 'info', 'biz', 'museum', 'us', 'arpa']
output_prefix = ""
zone_match_re = re.compile(r"""IN\s+NS\s+""", re.I)
logging.basicConfig(format='[%(asctime)s][%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)


def fetchaxfr(domain, nsitem, is_sub_call=None):
    global output_prefix
    try:
        tf = tempfile.NamedTemporaryFile()
        sp = subprocess.Popen(['dig', '@' + nsitem[1], domain, 'AXFR', '+time=35'], stdout=tf, stderr=None)
        sp.communicate()
        if sp.returncode != 0:
            logging.error("Failed: %s @ %s (%s): Statuscode: %s", domain, nsitem[0], nsitem[1], sp.returncode)
            return False

        end = None
        try:
            tf.seek(-100, 2)
            end = tf.read(100).decode('utf8')
        except Exception as e:
            logging.error(e)

        if not end or 'XFR size' not in end:
            logging.debug("Failed: %s @ %s (%s): %s", domain, nsitem[0], nsitem[1], end)
            return False

        logging.info("Success: %s @ %s (%s): %s", domain, nsitem[0], nsitem[1], tf.tell())
        shutil.copy(tf.name, f'{output_prefix}{domain}_{nsitem[0]}.zone')

        if is_sub_call:
            return True

        ns_match = re.compile(r'\\s+NS\\s+' + re.escape(nsitem[0]) + r'\\.', re.I)
        try:
            tf.seek(0)
            line = 1
            sub_zones = []
            while line:
                line = tf.readline().decode('utf8')
                if not ns_match.search(line):
                    continue

                cols = re.sub(r'\s+', '\t', line.lower()).split('\t')
                subtld = cols[0].strip('.')
                if subtld != domain and subtld not in sub_zones:
                    sub_zones.append(subtld)

            if len(sub_zones) < 15:
                for subtld in sub_zones:
                    fetchaxfr(subtld, nsitem, True)
        except Exception as e:
            logging.exception(e)
        return True
    except Exception as e:
        logging.exception(e)


def checkaxfr(item):
    (domain, nshosts) = item
    domain = domain.strip()
    try:
        nsset = []
        for ns in nshosts:
            try:
                nsset.extend((ns, x[4][0]) for x in socket.getaddrinfo(ns, 53, 0, socket.SOCK_DGRAM, 0, socket.AI_PASSIVE))
            except Exception as e:
                logging.error("NS: %s", ns)
                logging.exception(e)

        logging.info("Zone: %s", domain)
        success_hosts = []
        for nsitem in nsset:
            if nsitem[0] in success_hosts:
                continue

            logging.debug("%s: %s", domain, nsitem)
            if fetchaxfr(domain, nsitem):
                success_hosts.append(nsitem[0])
    except Exception as e:
        logging.exception(e)


def fetchNTLDs():
    r = requests.get('https://api.ntldstats.net/i/tlds/csv')
    skip = []
    for y, line in enumerate(r.text.split('\n')):
        if y < 2 or not line:
            continue
        skip.append(line.split(',')[0].strip())
    return skip


def fetchRoot():
    r = requests.get('https://www.internic.net/domain/root.zone')
    zones = {}
    for line in r.text.split('\n'):
        if not line or not zone_match_re.search(line):
            continue

        cols = re.sub('\t+', '\t', line.lower()).split('\t')

        cols[0] = cols[0].strip('.')
        if cols[0] == '':
            continue

        if cols[0] not in zones:
            zones[cols[0]] = [cols[-1].strip('.')]
        elif cols[-1].strip('.') not in zones[cols[0]]:
            zones[cols[0]].append(cols[-1].strip('.'))

    return zones


def fetchPublicList() -> list:
    r = requests.get('https://publicsuffix.org/list/public_suffix_list.dat')
    icann_domains = []
    start = False
    for line in r.text.split('\n'):
        if '// ===BEGIN ICANN DOMAINS===' in line:
            start = True
            continue
        elif '// ===END ICANN DOMAINS===' in line:
            break
        elif not line or not start or line.startswith('//'):
            continue
        icann_domains.append(line.strip().replace('*.', '').replace('!', '').encode("idna").decode('ascii'))

    return icann_domains


def saveCache(tld_list: dict):
    with open('cache.json', 'w') as f:
        json.dump(tld_list, f)


def readCache() -> dict:
    try:
        with open('cache.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def main():
    global output_prefix
    parser = argparse.ArgumentParser(description='Check domains\' nameservers for public AXFR')
    parser.add_argument('-p', '--processes', type=int, nargs="?", default=20, help='Processes to use. Default: 20')
    parser.add_argument('-f', '--folder', type=str, nargs="?", default="zones/", help='Prefix to save to')
    args = parser.parse_args()

    output_prefix = args.folder

    tld_list = readCache()
    tld_list.setdefault('_invalid', [])

    ntlds = fetchNTLDs()
    for (tld, nsset) in fetchRoot().items():
        if tld in ntlds or tld in skip_zones or any(tld.endswith(f'.{s}') for s in skip_zones) or tld in tld_list:
            continue

        tld_list[tld] = (tld, nsset)

    for tld in fetchPublicList():
        if tld in ntlds or \
                tld in skip_zones or \
                any(tld.endswith(f'.{s}') for s in skip_zones) or \
                tld in tld_list or \
                tld in tld_list.get('_invalid', []):
            continue

        try:
            ns_query = dns.resolver.query(tld + '.', dns.rdatatype.NS)
            nsset = set()
            for ns in ns_query.rrset:
                nameserver = str(ns)[:-1]
                if nameserver is None or nameserver == "":
                    continue
                nsset.add(nameserver)

            tld_list[tld] = (tld, list(nsset))
        except Exception as e:
            tld_list['_invalid'].append(tld)
            logging.exception(e)

    saveCache(tld_list)

    del tld_list['_invalid']

    logging.info("Checking %s tlds", len(tld_list))

    pool = Pool(processes=args.processes)
    pool.map(checkaxfr, tld_list.values())


if __name__ == '__main__':
    main()
