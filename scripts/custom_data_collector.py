import re
from datetime import datetime
import json
import sys
import socket
import getdns
import pandas as pd
import ipaddress
import pytricia
import pickle
import math
import csv

import os 
import traceback
import urllib.request
import shutil
import argparse
import time
import gzip

import geoip2.database

import tarfile

import country_converter as coco


KNOWN_FORMATS = [
    '%d-%b-%Y',                 # 02-jan-2000
    '%d-%B-%Y',                 # 11-February-2000
    '%d-%m-%Y',                 # 20-10-2000
    '%Y-%m-%d',                 # 2000-01-02
    '%d.%m.%Y',                 # 2.1.2000
    '%Y.%m.%d',                 # 2000.01.02
    '%Y/%m/%d',                 # 2000/01/02
    '%Y%m%d',                   # 20170209
    '%d/%m/%Y',                 # 02/01/2013
    '%Y. %m. %d.',              # 2000. 01. 02.
    '%Y.%m.%d %H:%M:%S',        # 2014.03.08 10:28:24
    '%d-%b-%Y %H:%M:%S %Z',     # 24-Jul-2009 13:20:03 UTC
    '%a %b %d %H:%M:%S %Z %Y',  # Tue Jun 21 23:59:59 GMT 2011
    '%Y-%m-%dT%H:%M:%SZ',       # 2007-01-26T19:10:31Z
    '%Y-%m-%dT%H:%M:%S.%fZ',    # 2018-12-01T16:17:30.568Z
    '%Y-%m-%dT%H:%M:%S%z',      # 2013-12-06T08:17:22-0800
    '%Y-%m-%d %H:%M:%SZ',       # 2000-08-22 18:55:20Z
    '%Y-%m-%d %H:%M:%S',        # 2000-08-22 18:55:20
    '%d %b %Y %H:%M:%S',        # 08 Apr 2013 05:44:00
    '%d/%m/%Y %H:%M:%S',     # 23/04/2015 12:00:07 EEST
    '%d/%m/%Y %H:%M:%S %Z',     # 23/04/2015 12:00:07 EEST
    '%d/%m/%Y %H:%M:%S.%f %Z',  # 23/04/2015 12:00:07.619546 EEST
    '%B %d %Y',                 # August 14 2017
    '%d.%m.%Y %H:%M:%S',        # 08.03.2014 10:28:24
]

ZONEMASTER_CLI = '/usr/bin/zonemaster-cli'
ZONEMASTER_LEVELS = {
    0: 'CRITICAL', 
    1: 'ERROR', 
    2: 'WARNING', 
    3: 'NOTICE'
}


class PywhoisError(Exception):
    pass


def datetime_parse(s):
    for known_format in KNOWN_FORMATS:
        try:
            s = datetime.strptime(s, known_format)
            break
        except ValueError as e:
            pass  # Wrong format, keep trying
    return s


def cast_date(s, dayfirst=False, yearfirst=False):
    """Convert any date string found in WHOIS to a datetime object.
    """
    return datetime_parse(s)


class WhoisEntry(dict):

    dayfirst = False
    yearfirst = False

    def __init__(self, domain, text, regex=None):
        if 'This TLD has no whois server, but you can access the whois database at' in text:
            raise PywhoisError(text)
        else:
            self.domain = domain
            self.text = text
            self._regex = regex
            self.parse()

    def parse(self):
        """The first time an attribute is called it will be calculated here.
        The attribute is then set to be accessed directly by subsequent calls.
        """
        for attr, regex in list(self._regex.items()):
            if regex:
                values = []
                for data in re.findall(regex, self.text, re.IGNORECASE | re.M):
                    matches = data if isinstance(data, tuple) else [data]
                    for value in matches:
                        value = self._preprocess(attr, value)
                        if value and value not in values:
                            # avoid duplicates
                            values.append(value)
                if values and attr in ('registrar', 'whois_server', 'referral_url'):
                    values = values[-1]  # ignore junk
                if len(values) == 1:
                    values = values[0]
                elif not values:
                    values = None

                self[attr] = values
                

    def _preprocess(self, attr, value):
        value = value.strip()
        return value

    
    def __setitem__(self, name, value):
        super(WhoisEntry, self).__setitem__(name, value)

    
    def __getattr__(self, name):
        return self.get(name)

    def __str__(self):
        def handler(e): return str(e)
        return json.dumps(self, indent=2, default=handler)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, state):
        self.__dict__ = state
    

    @staticmethod
    def load(domain, text):
        """Given whois output in ``text``, return an instance of ``WhoisEntry``
        that represents its parsed contents.
        """
        if text.strip() == 'No whois server is known for this kind of object.':
            raise PywhoisError(text)

        return WhoisIANA(domain, text.decode())


class WhoisIANA(WhoisEntry):
    """Whois parser for TLD."""

    regex = {
        'domain_name': 'domain: *(.+)',
        'organisation': 'organisation: *(.+)',
        #'admin': 'organisation: *(.+)',
        'addresses': 'address: *(.+)',
        'phones': 'phone: *(.+)',
        'e-mails': 'e-mail:  *(.+)',
        'creation_date': 'created: *(.+)',
        'change_date': 'changed: *(.+)',
        'status': 'status:  *(.+)',
        'whois': 'whois:  *(.+)',
        'name_servers': 'nserver: *(.+)',  # list of name servers
        'dnssec': 'ds-rdata:  *(.+)',
        'remarks': r'(https?://[^\s]+)',
        'status': 'Domain Status: *(.+)',
    }

    def __init__(self, domain, text):
        if 'No match for "' in text:
            raise PywhoisError(text)
        else:
            WhoisEntry.__init__(self, domain, text, self.regex)

class WhoisClient(object) :
    # Adapted from https://gist.github.com/carmaa/3686059
    def __init__(self):
        self.whois_server = "whois.iana.org"

    def whois(self, query, hostname):
        """Perform initial lookup with TLD whois server
        then, if the quick flag is false, search that result 
        for the region-specifc whois server and do a lookup
        there for contact details
        """
        #pdb.set_trace()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((hostname, 43))
        s.send((query + "\r\n").encode())
        response = b""
        while True:
            d = s.recv(4096)
            response += d
            if not d:
                break
        s.close()
        return WhoisEntry.load(query, response)

    def whois_lookup(self, query_arg):
        return self.whois(query_arg, self.whois_server)


class GetDns():
    
    getdns_result = {
        getdns.RESPSTATUS_GOOD: "GOOD",
        getdns.RESPSTATUS_NO_NAME: "NO_NAME",
        getdns.RESPSTATUS_ALL_TIMEOUT: "ALL_TIMEOUT",
        getdns.RESPSTATUS_NO_SECURE_ANSWERS: "NO_SECURE_ANSWERS",
        getdns.RESPSTATUS_ALL_BOGUS_ANSWERS: "ALL_BOGUS_ANSWERS"
    }

    def __init__(self):
        self.ctx = getdns.Context()
        self.recursive_servers = [
            [{ "address_type": "IPv4",  "address_data": '8.8.8.8' }],
            [{ "address_type": "IPv4",  "address_data": '9.9.9.9' }],
            [{ "address_type": "IPv4",  "address_data": '1.1.1.1' }],
        ]
        self.result_extension = { 
            "dnssec_return_status" :  getdns.EXTENSION_TRUE,
        }
        self.ctx.resolution_type = getdns.RESOLUTION_STUB
        self.request_type = 2
        self.result = {}
        self.result_complete = {}

    def query_ns(self, tld):
        try:
            self.result[tld] = {}
            for resolver in self.recursive_servers:
                self.ctx.upstream_recursive_servers = resolver
                ns_list = set()
                dnssec_list = set()
                result = self.ctx.general(name=tld, request_type=self.request_type, extensions=self.result_extension)
                if result.status == getdns.RESPSTATUS_GOOD:
                    for reply in result.replies_tree:
                        answer = reply['answer']
                        # print(answer)
                        for rdata in answer:
                            if 'nsdname' in rdata['rdata']:
                                ns_list.add(rdata['rdata']['nsdname'].upper().rstrip('.'))
                            if 'algorithm' in rdata['rdata']:
                                dnssec_list.add(rdata['rdata']['algorithm'])

                    row = {'nss':list(ns_list),'dnssec':list(dnssec_list)}

                    self.result[tld][resolver[0]['address_data']] = row
        except Exception as e:
            print("Error "+ str(e))

    def query_ip(self, tld):
        try:
            self.result[tld] = {}
            for resolver in self.recursive_servers:
                self.ctx.upstream_recursive_servers = resolver
                ip_list = set()
                result = self.ctx.address(name=tld, extensions=self.result_extension)
                if result.status == getdns.RESPSTATUS_GOOD:
                    for answer in result.just_address_answers:
                        ip_list.add(answer['address_data'])
                    self.result[tld][resolver[0]['address_data']] = list(ip_list)

        except Exception as e:
            print("Error "+ str(e))


    def get_common_ns(self, tld):
        self.query_ns(tld)
        data = {}
        for tld, resolver in self.result.items():
            tld_ns = set()
            for k, v in resolver.items():
                if not tld_ns:
                    tld_ns.update(v)
                else:
                    tld_ns = tld_ns & set(v)
            data[tld] = tld_ns
        return data

    def get_common_ns_complete(self, tld):
        try:
            self.query_ns(tld)
            data = {}
            for tld, resolver in self.result.items():
                row = {}
                for k, v in resolver.items():
                    for k2, v2 in v.items():
                        values = set()
                        if not values:
                            values.update(v2)
                        else:
                            values = values & set(v2)
                        row[k2] = values
                    data[tld] = row
            return data
        except Exception as e:
            print(e)



    def get_common_ip(self, tld):
        self.query_ip(tld)
        data = {}
        for tld, resolver in self.result.items():
            tld_ns = set()
            for k, v in resolver.items():
                if not tld_ns:
                    tld_ns.update(v)
                else:
                    tld_ns = tld_ns & set(v)
            data[tld] = tld_ns
        return data


class IpAllocation():
    def __init__(self, pyt4=None, pyt6=None):
        try:
            self.pyt6 = pytricia.PyTricia(128)
            self.pyt4 = pytricia.PyTricia()
            self.pyt = None
            if pyt4:
                self._restore(self.pyt4, pyt4)
            if pyt6:
                self._restore(self.pyt6, pyt6)
        except Exception as err:
            print("Error in init: "+ str(err))
            sys.exit(2)

    def _restore(self, key, val):
        for v in val:
            key[v] = val[v]

    def add_net(self, net, data, kind=True):
        try:
            prefix = ipaddress.ip_network(net, strict=kind)
            if prefix.version == 6:
                self.pyt = self.pyt6
            else:
                self.pyt = self.pyt4
            if self.pyt.has_key(prefix):
                self.pyt.delete(prefix)
            self.pyt.insert(prefix, data) 

        except Exception as err:
            print("Error in add_net: "+ str(err))
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            print(exc_obj)
            traceback.print_exc(file=sys.stdout)
    
    def has_ip(self, net):
        try:
            if net:
                prefix = ipaddress.ip_address(net)
                if prefix.version == 6:
                    self.pyt = self.pyt6
                else:
                    self.pyt = self.pyt4
                return prefix in self.pyt
            else:
                return False
        except Exception as err:
            print("Error in has_ip: "+ str(err))
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            print(exc_obj)
            traceback.print_exc(file=sys.stdout)
            sys.exit(2)

    def has_net(self, net):
        try:
            if net:
                prefix = ipaddress.ip_network(net)
                if prefix.version == 6:
                    self.pyt = self.pyt6
                else:
                    self.pyt = self.pyt4
                return prefix in self.pyt
            else:
                return False
        except Exception as err:
            print("Error in has_net: "+ str(err))
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            print(exc_obj)
            traceback.print_exc(file=sys.stdout)
            sys.exit(2)

    def get_net(self, prefix):
        try:
            prefix = ipaddress.ip_network(prefix)
            if prefix.version == 6:
                self.pyt = self.pyt6
            else:
                self.pyt = self.pyt4
            return self.pyt.get(prefix)
        except Exception as err:
            print("Error in get_net: "+ str(err))
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)
            print(exc_obj)
            traceback.print_exc(file=sys.stdout)

    def get_pytricia(self):
        return (self.pyt4, self.pyt6)
    
    def __reduce__(self):
        ipv4dict = {}
        ipv6dict = {}
        for prefix in self.pyt4:
            ipv4dict[prefix] = self.pyt4[prefix]
        for prefix in self.pyt6:
            ipv6dict[prefix] = self.pyt6[prefix]
        return (self.__class__, (ipv4dict, ipv6dict)) 



def get_allocation(filename, allocation_pyt):
    with open(filename) as f:
        for line in f:
            if line.startswith('#'):
                continue
            if 'assigned' in line:
                try:
                    if 'ipv4' in line:
                        line_data = line.split("|")
                        prefix = 32 - (math.log(int(line_data[4]))/math.log(2))
                        prefix = str(line_data[3])+"/"+str(int(prefix)) 
                        # print(line_data) 
                        # print(prefix)
                        data = {'region': line_data[0], 'cc': line_data[1], 'af': 4, 'prefix': prefix}
                        allocation_pyt.add_net(prefix, data, kind=False)
                    if 'ipv6' in line:
                        line_data = line.split("|")
                        prefix = str(line_data[3])+"/"+str(int(line_data[4]))
                        # print(line_data) 
                        # print(prefix)
                        data = {'region': line_data[0], 'cc': line_data[1], 'af': 6, 'prefix': prefix}
                        allocation_pyt.add_net(prefix, data, kind=False)
                except Exception as err:
                    print("Error in get_allocation: "+ str(err))
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    print(line_data) 
                    print(exc_type, fname, exc_tb.tb_lineno)
                    print(exc_obj)
                    traceback.print_exc(file=sys.stdout)


def get_caida_anycast(filename_caida, filename_greedy, allocation_pyt):
    with open(filename_caida) as caida, open(filename_greedy) as greedy:
        try:
            for line in caida:
                if line.startswith('#'):
                    continue
                record = line.split('\t')
                prefix = record[0]
                anycast = record[1].strip('\n')
                
                if anycast == 'Anycast':
                    allocation_pyt.add_net(prefix, 'caida')
            for line in greedy:
                if line.startswith('#'):
                    continue
                prefix = line.strip('\n')
                if not allocation_pyt.has_net(prefix):
                    allocation_pyt.add_net(prefix, 'greedy')
        except Exception as err:
            print("Error in get_caida_anycast: "+ str(err))
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(line) 
            print(exc_type, fname, exc_tb.tb_lineno)
            print(exc_obj)
            traceback.print_exc(file=sys.stdout)

def run_zonemaster(tld, output_file):
    cmd = ZONEMASTER_CLI
    myCmd = cmd + " " + tld + " --json --show_module > " + output_file
    os.system(myCmd)

def get_zonemaster(tld, in_file):
    result = {}
    dataframe = []
    with open(in_file) as f:
        data = json.load(f)
        for line in data['results']:
            frame_row = {}
        
            frame_row['cc'] = tld
            frame_row['level'] = line['level']
            frame_row['category'] = line['module']
            frame_row['test'] = line['tag']
            frame_row['data'] = line['args']
            dataframe.append(frame_row)

            if line['level'] not in result.keys():
                result[line['level']] = {}
                if line['module'] not in result[line['level']].keys():
                    result[line['level']][line['module']] = [{
                        'tag': line['tag'],
                        'args': line['args']
                    }]
                else:
                    result[line['level']][line['module']].append({
                        'tag': line['tag'],
                        'args': line['args']
                    })
            else:
                if line['module'] not in result[line['level']].keys():
                    result[line['level']][line['module']] = [{
                            'tag': line['tag'],
                            'args': line['args']
                        }]
                else:
                    result[line['level']][line['module']].append({
                            'tag': line['tag'],
                            'args': line['args']
                        })
            
    return (result, dataframe)


def get_deploy_dnssec(filename):
    result = []
    with open(filename) as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row)!= 8:
                continue
            if row[1].strip() not in ['DS in Root', 'Operational']:
                continue
            
            result.append(row[0].strip())
    return result

def get_dnssec_algo(filename):
    result = {}
    with open(filename) as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            result[row[0]] = row[1]
    return result
            
def save_to_file(filename, record):
    try:
        new_data = []
        with open(filename) as result_file_handle:
            data = json.load(result_file_handle)
            if isinstance(data, list):
                new_data.extend(data)
            else:
                new_data.append(data)
    except Exception:
        with open(filename, 'w') as result_file_handle:
            json.dump(record, result_file_handle)
    if new_data:
        if isinstance(record, list):
            new_data.extend(record)
        else:
            new_data.append(record)
        with open(filename, 'w') as result_file_handle:
            json.dump(new_data, result_file_handle)

def get_remote_file(url, output_file):
    try:
        with urllib.request.urlopen(url) as response, open(output_file, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
    except Exception as err:
        print('Error in get_remote_file '+ str(err))


def get_new_files(url, output_file):
    INTERVAL = 4
    INTERVAL_TIMESTAMP = INTERVAL * 60 * 60
    
    now = time.time()
    
    if not os.path.isfile(output_file):
        with urllib.request.urlopen(url) as response, open(output_file, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
    else:
        stat = os.stat(output_file)
        if now > (stat.st_mtime + INTERVAL_TIMESTAMP):
            with urllib.request.urlopen(url) as response, open(output_file, 'wb') as out_file:
                shutil.copyfileobj(response, out_file)

def get_new_files_new(url, output_file):
    INTERVAL = 4
    INTERVAL_TIMESTAMP = INTERVAL * 60 * 60
    
    cmd = "wget --max-redirect 100 -O"
    myCmd = cmd + " " + output_file + " " + url
    
    now = time.time()
    
    if not os.path.isfile(output_file):
        os.system(myCmd)
    else:
        # print('File exists!')
        return
        # stat = os.stat(output_file)
        # if now > (stat.st_mtime + INTERVAL_TIMESTAMP):
        #     os.system(myCmd)

def get_file_raw_wget(cmd, url, output_file):
    INTERVAL = 4
    INTERVAL_TIMESTAMP = INTERVAL * 60 * 60
    
    myCmd = cmd + " -O " + output_file + " " + url
    
    now = time.time()
    # stat = os.stat(output_file)

    # print(myCmd)
    
    if (not os.path.isfile(output_file)):
        # print(myCmd)
        os.system(myCmd)
    else:
        return
        # stat = os.stat(output_file)
        # if now > (stat.st_mtime + INTERVAL_TIMESTAMP):
        #     os.system(myCmd)

def get_last_prefixas_filename(logfile):
    with open(logfile) as f:
        last = [line for line in f ][-1]
        last = last.split("\t")
        return last[-1]

def get_prefix_asn_mapping(folder, pyt):
    try:
        for root, _, files in os.walk(folder):
            files = [ x for x in files if x.endswith('.gz')]
            for name in files:
                
                filename = os.path.join(root, name)
                with gzip.open(filename, 'r') as bz_file:
                    for line in bz_file:
                        if line.startswith(b'#'):
                            continue
                        data = re.split(r'\t+', line.decode("utf-8").rstrip('\n'))

                        prefix = "/".join(data[:2])
                        asn = data[2].split(',')
                        asn = [int(x) for x in asn]
                        if len(asn) == 1:
                            pyt.add_net(prefix, asn[0])
                        else:
                            pyt.add_net(prefix, asn)
    except Exception as err:
        print('Error in get_prefix_asn_mapping' + str(err))


def get_anycast_provider(cc, name, ip):
    dns_anycast_provider = ['afrinic','pch', 'dnsnode', 'ripe', 'irondns']
    freenom = ['ML','GA', 'CF', 'GQ']
    anycast = False
    if cc in freenom:
        anycast = True
        return 'freenom'
    if not anycast:
        if cc == 'SC':
            anycast = True
            return 'afilias'
    if not anycast:
        for anyc in dns_anycast_provider:
            if anyc in name.lower():
                anycast = True
                return anyc
    if not anycast:
        AFRINIC_DNS_SUPPORT_ASN_v4 = ['196.216.168.0/24', '196.216.169.0/24']
        AFRINIC_DNS_SUPPORT_ASN_v6 = ['2001:43f8:110::/48','2001:43f8:120::/48']

        PCH_DNS_SUPPORT_ASN_v4 = ['204.61.216.0/23']
        PCH_DNS_SUPPORT_ASN_v6 = ['2001:500:14::/47']

        DNSNODE_DNS_SUPPORT_ASN_v4 = ['194.146.106.0/24','77.72.224.0/21']
        DNSNODE_DNS_SUPPORT_ASN_v6 = ['2001:67c:1010::/48','2a01:3f0::/32']

        IRONDN_DNS_SUPPORT_ASN_v4 = ['195.253.64.0/24']
        IRONDN_DNS_SUPPORT_ASN_v6 = ['2a01:5b0:4::/48']

        RIPE_DNS_SUPPORT_ASN_v4 = ['193.0.9.0/24']
        RIPE_DNS_SUPPORT_ASN_v6 = ['2001:67c:e0::/48']
        af = ipaddress.ip_address(ip).version
        if af == 6:
            for net in AFRINIC_DNS_SUPPORT_ASN_v6:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(net):
                    return 'afrinic'
            for net in PCH_DNS_SUPPORT_ASN_v6:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(net):
                    return 'pch' 
            for net in DNSNODE_DNS_SUPPORT_ASN_v6:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(net):
                    return 'dnsnode' 
            for net in IRONDN_DNS_SUPPORT_ASN_v6:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(net):
                    return 'irondns' 
            for net in RIPE_DNS_SUPPORT_ASN_v6:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(net):
                    return 'ripe' 
        else:
            for net in AFRINIC_DNS_SUPPORT_ASN_v4:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(net):
                    return 'afrinic'
            for net in PCH_DNS_SUPPORT_ASN_v4:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(net):
                    return 'pch' 
            for net in DNSNODE_DNS_SUPPORT_ASN_v4:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(net):
                    return 'dnsnode' 
            for net in IRONDN_DNS_SUPPORT_ASN_v4:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(net):
                    return 'irondns' 
            for net in RIPE_DNS_SUPPORT_ASN_v4:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(net):
                    return 'ripe' 
               
    return 'other'

def extract_maxmind_db(folderpath, targz_file, output_file):
    shutil.unpack_archive(targz_file,folderpath)  # Unpack raw file
    
    for path in os.listdir(folderpath):
        if os.path.isdir(folderpath+path):
            for file in os.listdir(folderpath+path+'/'):
                if file.endswith('mmdb'):
                    shutil.move(folderpath+path+'/'+file, output_file) # rename and move mmdb file

def get_ip_country(mmdb_file,ip):
    with geoip2.database.Reader(mmdb_file) as reader:
        response = reader.country(ip)
        return response.country.iso_code



# Break link
# INTERNET_SOCIETY_DNSSEC_MAP_URL = 'https://elists.isoc.org/pipermail/dnssec-maps/attachments/20200713/dc23dbf4/attachment-0003.csv'

NRO_DELEGATION_URL = 'https://www.nro.net/wp-content/uploads/apnic-uploads/delegated-extended'
DNSSEC_ALGO_NUMBER_FILE = 'https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers-1.csv'
PASSIVE_ANYCAST_RESULT_FILE = 'https://raw.githubusercontent.com/bianrui0315/ccr_Anycast/master/data/Anycast_detection/results_prefix.txt'
GREEDY_ANYCAST_RESULT_FILE = 'https://anycast.telecom-paristech.fr/list/2017-04'
GREEDY_ANYCAST_RESULT_FILE = 'https://raw.githubusercontent.com/bgptools/anycast-prefixes/master/anycatch-v4-prefixes.txt'

CAIDA_PREFIX4_2AS_LOG = 'http://data.caida.org/datasets/routing/routeviews-prefix2as/pfx2as-creation.log'
CAIDA_PREFIX6_2AS_LOG = 'http://data.caida.org/datasets/routing/routeviews6-prefix2as/pfx2as-creation.log'
CAIDA_PREFIX4_2AS_URL = 'http://data.caida.org/datasets/routing/routeviews-prefix2as/'
CAIDA_PREFIX6_2AS_URL = 'http://data.caida.org/datasets/routing/routeviews6-prefix2as/'

COUNTRY_TO_REGION_URL = 'https://raw.githubusercontent.com/lukes/ISO-3166-Countries-with-Regional-Codes/master/all/all.csv'
IANA_ROOT_DB_URL = 'https://www.iana.org/domains/root/db'

MAXMIND_IP2COUNTRY_URL = 'https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz'
MAXMIND_ACCOUNT_ID = ''
MAXMIND_ACCOUNT_KEY = ''
MAXMIND_CONFIG = 'wget --content-disposition --user=\''+ MAXMIND_ACCOUNT_ID + '\' --password=\'' + MAXMIND_ACCOUNT_KEY + '\''

if __name__ == "__main__":
    now = datetime.now()
    today = now.strftime("%Y%m%d")
    base_path = "../custom-datasets/raw"
    nro_alloactions_folder = base_path + '/' + str(today) + '/nro_delegated/' 
    nro_alloactions_file = nro_alloactions_folder + '/nro_delegated_extended.txt'
    deploy360_dnssec_folder = base_path + '/'  + str(today) + '/deploy360_dnssec/'
    # deploy360_dnssec_file = deploy360_dnssec_folder + '/deploy360_dnssec_last.csv'
    deploy360_dnssec_file = '../datasets/raw/deploy360_dnssec_last20200713.csv'
    allocation_file = nro_alloactions_folder + '/nro_prefix_region_delegated.pickle'
    dnssec_algo_folder = base_path + '/' + str(today) +  '/dnssec_algo/' 
    dnssec_algo_file = dnssec_algo_folder + '/dnssec_algo_file.csv'
    zonemaster_folder = base_path + '/' + str(today) + '/zonemaster_result/'
    results_folder = base_path + '/' + str(today) + '/results/'
    anycast_dataset_folder = base_path + '/' + str(today) + '/anycast_dataset/'
    anycast_dataset_caida_file = anycast_dataset_folder + '/anycast_caida_dataset.txt'
    anycast_dataset_greedy_file = anycast_dataset_folder + '/anycast_greedy_dataset.txt'
    anycast_filtered_file = anycast_dataset_folder + '/anycast_dataset.pickle'
    
    maxmind_folder = base_path + '/' + str(today) + '/maxmind_ip2country/'
    maxmind_targz_file = maxmind_folder + '/maxmind_ip2country.tar.gz'
    maxmind_mmdb_file = maxmind_folder + '/maxmind_ip2country.mmdb'

    prefixes_asn_folder =  base_path + '/' + str(today) +'/prefixes_asn/' 
    prefix4_asn_file_log = prefixes_asn_folder + "/pfx42as-creation.log" 
    prefix6_asn_file_log = prefixes_asn_folder + "/pfx62as-creation.log" 
    prefix4_asn_mapping_file = prefixes_asn_folder + "/pfx42as.gz" 
    prefix6_asn_mapping_file = prefixes_asn_folder + "/pfx62as.gz" 
    prefix_asn_pytricia_file = prefixes_asn_folder + "/prefix_asn_pytricia.pickle"   

    # Get Arguments
    parser = argparse.ArgumentParser(description='Get RFC metas.')
    parser.add_argument('-k', '--kind', help='Kind of measurement', required=True, choices=["afri", "top_cctld", "all", "custom"])
    parser.add_argument('-i', '--input', help='Input file for custom measurement', required=False)

    args = vars(parser.parse_args())
    kind = args['kind']
    input_file = args['input']

    if kind == 'custom':
        try:
            custom_list = pd.read_csv(input_file, header=None).dropna()
        except Exception as e:
            print('Bad input file! Use one column csv format without header!')
            print(e)
            sys.exit()
    

    AFRINIC_DNS_SUPPORT_ASN = 37181,37177
    AFRINIC_DNS_SUPPORT_ASN_v4 = ['196.216.168.0/24', '196.216.169.0/24']
    AFRINIC_DNS_SUPPORT_ASN_v6 = ['2001:43f8:110::/48','2001:43f8:120::/48']

    PCH_DNS_SUPPORT_ASN = 42
    PCH_DNS_SUPPORT_ASN_v4 = ['204.61.216.0/23']
    PCH_DNS_SUPPORT_ASN_v6 = ['2001:500:14::/47']

    DNSNODE_DNS_SUPPORT_ASN = 8674
    DNSNODE_DNS_SUPPORT_ASN_v4 = ['194.146.106.0/24','77.72.224.0/21']
    DNSNODE_DNS_SUPPORT_ASN_v6 = ['2001:67c:1010::/48','2a01:3f0::/32']

    IRONDN_DNS_SUPPORT_ASN = 8561
    IRONDN_DNS_SUPPORT_ASN_v4 = ['195.253.64.0/24']
    IRONDN_DNS_SUPPORT_ASN_v6 = ['2a01:5b0:4::/48']


    dns_anycast_provider = ['afrinic','pch', 'dnsnode', 'ripe', 'any']
    # https://www.ripe.net/analyse/dns/authdns/

    

    if not os.path.exists(nro_alloactions_folder):
        os.makedirs(nro_alloactions_folder)

    if not os.path.exists(deploy360_dnssec_folder):
        os.makedirs(deploy360_dnssec_folder)
    
    if not os.path.exists(dnssec_algo_folder):
        os.makedirs(dnssec_algo_folder)

    if not os.path.exists(zonemaster_folder):
        os.makedirs(zonemaster_folder)

   
    if not os.path.exists(results_folder):
        os.makedirs(results_folder)

    if not os.path.exists(anycast_dataset_folder):
        os.makedirs(anycast_dataset_folder)

    if not os.path.exists(prefixes_asn_folder):
        os.makedirs(prefixes_asn_folder)

    if not os.path.exists(maxmind_folder):
        os.makedirs(maxmind_folder)

    print('Getting DNS Security Algorithm Numbers ')
    get_new_files(DNSSEC_ALGO_NUMBER_FILE, dnssec_algo_file)
    
    print('Getting NRO Extended Allocation and Assignment Reports')
    get_new_files_new(NRO_DELEGATION_URL, nro_alloactions_file)
    # get_file_raw_wget('wget ',NRO_DELEGATION_URL, nro_alloactions_file)

    print('Getting DNSSEC Deployment Maps')
    # Break link
    # get_new_files(INTERNET_SOCIETY_DNSSEC_MAP_URL,deploy360_dnssec_file)

    print('Getting PASSIVE ANYCAST result file')
    get_new_files(PASSIVE_ANYCAST_RESULT_FILE,anycast_dataset_caida_file) 

    print('Getting GREEDY ANYCAST result file')
    get_new_files(GREEDY_ANYCAST_RESULT_FILE,anycast_dataset_greedy_file) 

    print('Getting CAIDA IPv4 prefixes to ASN log   ' + prefix4_asn_file_log)
    get_new_files(CAIDA_PREFIX4_2AS_LOG , prefix4_asn_file_log)
    last_prefix42s_file  = get_last_prefixas_filename(prefix4_asn_file_log)
    last_prefix42s_file = CAIDA_PREFIX4_2AS_URL + '/' + last_prefix42s_file
    print('Getting CAIDA IPv4 prefixes to ASN mapping file   ' + prefix4_asn_mapping_file)
    get_new_files(last_prefix42s_file , prefix4_asn_mapping_file)

    print('Getting CAIDA IPv6 prefixes to ASN log   ' + prefix6_asn_file_log)
    get_new_files(CAIDA_PREFIX6_2AS_LOG , prefix6_asn_file_log)
    last_prefix62s_file = get_last_prefixas_filename(prefix6_asn_file_log)
    last_prefix62s_file = CAIDA_PREFIX6_2AS_URL + '/' + last_prefix62s_file
    print('Getting CAIDA IPv6 prefixes to ASN mapping file   ' + prefix6_asn_mapping_file)
    get_new_files(last_prefix62s_file , prefix6_asn_mapping_file)

    print('Getting Maxmind IP2Country database')
    get_file_raw_wget(MAXMIND_CONFIG, MAXMIND_IP2COUNTRY_URL, maxmind_targz_file)
    extract_maxmind_db(maxmind_folder, maxmind_targz_file, maxmind_mmdb_file)

    if os.path.isfile(nro_alloactions_file) and os.path.isfile(anycast_dataset_caida_file) and os.path.isfile(anycast_dataset_greedy_file):

        print('Getting DNSSEC Algos')
        dnssec_algo_dict = get_dnssec_algo(dnssec_algo_file)

        print('Formating DNSSEC Deployment Maps dataframe')
        af_deploy360 = get_deploy_dnssec(deploy360_dnssec_file)
        
        if not os.path.isfile(allocation_file):
            allocation_pyt = IpAllocation()
            print('Formating NRO allocation to file')
            get_allocation(nro_alloactions_file, allocation_pyt)
            with open(allocation_file, 'wb') as handle:
                pickle.dump(allocation_pyt, handle, protocol=pickle.HIGHEST_PROTOCOL)
        else:
            print('Reading NRO allocation from file')
            with open(allocation_file, 'rb') as handle:
                allocation_pyt = pickle.load(handle)

        allocationpyt4, alloacationpyt6 = allocation_pyt.get_pytricia()

        print("IPv4 allocations " + str(len(allocationpyt4)))
        print("IPv6 allocations " + str(len(alloacationpyt6)))


        if os.path.isfile(prefix_asn_pytricia_file):
            print("Reading Prefix:ASN mapping from file " + prefix_asn_pytricia_file)
            with open(prefix_asn_pytricia_file, 'rb') as handle:
                prefixes_asn_pyt = pickle.load(handle)
                
        else:
            prefixes_asn_pyt = IpAllocation()
            # Get Prefixes ASN mapping
            print("Getting Prefix:ASN mapping...")
            get_prefix_asn_mapping(prefixes_asn_folder, prefixes_asn_pyt)

            print("Saving Prefix:ASN mapping to file " + prefix_asn_pytricia_file)
            with open(prefix_asn_pytricia_file, 'wb') as handle:
                pickle.dump(prefixes_asn_pyt, handle, protocol=pickle.HIGHEST_PROTOCOL)
        
        asnpyt4, asnpyt6 = prefixes_asn_pyt.get_pytricia()


        if not os.path.isfile(anycast_filtered_file):
            anycast_pyt = IpAllocation()
            print('Formating ANYCAST to file')
            get_caida_anycast(anycast_dataset_caida_file, anycast_dataset_greedy_file, anycast_pyt)
            for pref in AFRINIC_DNS_SUPPORT_ASN_v4:
                anycast_pyt.add_net(pref, 'afrinic')
            for pref in AFRINIC_DNS_SUPPORT_ASN_v6:
                anycast_pyt.add_net(pref, 'afrinic')

            for pref in PCH_DNS_SUPPORT_ASN_v4:
                anycast_pyt.add_net(pref, 'pch')
            for pref in PCH_DNS_SUPPORT_ASN_v6:
                anycast_pyt.add_net(pref, 'pch')

            for pref in DNSNODE_DNS_SUPPORT_ASN_v4:
                anycast_pyt.add_net(pref, 'dnsnode')
            for pref in DNSNODE_DNS_SUPPORT_ASN_v6:
                anycast_pyt.add_net(pref, 'dnsnode')

            with open(anycast_filtered_file, 'wb') as handle:
                pickle.dump(anycast_pyt, handle, protocol=pickle.HIGHEST_PROTOCOL)
        else:
            print('Reading ANYCAST  from file')
            with open(anycast_filtered_file, 'rb') as handle:
                anycast_pyt = pickle.load(handle)


        anycast4, anycast6 = anycast_pyt.get_pytricia()

        print("IPv4 anycast " + str(len(anycast4)))
        print("IPv6 anycast " + str(len(anycast6)))

        # Add reserved IPv6 network for anycast
        
        
        nic_client = WhoisClient()

        af_cc = {
            'Algeria': 'DZ',
            'Angola': 'AO',
            'Benin': 'BJ',
            'Botswana': 'BW',
            'Burkina Faso': 'BF',
            'Burundi': 'BI',
            'Cameroon': 'CM',
            'Cape Verde': 'CV',
            'Central African Republic': 'CF',
            'Chad': 'TD',
            'Comoros': 'KM',
            'Democratic Republic of the Congo': 'CD',
            'Republic of the Congo': 'CG',
            'Djibouti': 'DJ',
            'Egypt': 'EG',
            'Equatorial Guinea': 'GQ',
            'Eritrea': 'ER',
            'Eswatini': 'SZ',
            'Ethiopia': 'ET',
            'Gabon': 'GA',
            'The Gambia': 'GM',
            'Ghana': 'GH',
            'Guinea': 'GN',
            'Guinea-Bissau': 'GW',
            'Ivory Coast': 'CI',
            'Kenya': 'KE',
            'Lesotho': 'LS',
            'Liberia': 'LR',
            'Libya': 'LY',
            'Madagascar': 'MG',
            'Malawi': 'MW',
            'Mali': 'ML',
            'Mauritania': 'MR',
            'Mauritius': 'MU',
            'Morocco': 'MA',
            'Mozambique': 'MZ',
            'Namibia': 'NA',
            'Niger': 'NE',
            'Nigeria': 'NG',
            'Rwanda': 'RW',
            #'Sahrawi Arab Democratic Republic (Western Sahara)': 'EH',
            'São Tomé and Príncipe': 'ST',
            'Senegal': 'SN',
            'Seychelles': 'SC',
            'Sierra Leone': 'SL',
            'Somalia': 'SO',
            'South Africa': 'ZA',
            'South Sudan': 'SS',
            'Sudan': 'SD',
            'Tanzania': 'TZ',
            'Togo': 'TG',
            'Tunisia': 'TN',
            'Uganda': 'UG',
            'Zambia': 'ZM',
            'Zimbabwe': 'ZW'
        }

        try:
            # retrieve live root db
            all_tlds_iana = pd.read_html(IANA_ROOT_DB_URL,encoding='utf8')[0]
        except Exception as e:
            print(e)
        
        # filter ccTLDs and exclude IDN
        cctlds = all_tlds_iana.query('Type == "country-code"')['Domain'].rename('ccTLD')[lambda x:x.map(str.isascii)]
        # strip the dot and turn to uppercase
        cctlds = cctlds.str.strip('.').str.upper()
        # cctlds['ccTLD'] = cctlds['ccTLD'].str.strip('.')
        # cctlds = cctlds[cctlds['ccTLD'].map(str.isascii)]

        
        
        freenom = ['ML','GA', 'CF', 'GQ']
        if kind == 'afri':
            ccs = sorted(set(af_cc.values()))
        elif kind == 'top_cctld':
            ccs = ['TK', 'CN', 'DE', 'UK', 'NL', 'RU', 'BR', 'EU', 'FR', 'IT']
        elif kind == 'all':
            ccs = sorted(set(cctlds.to_list()))
        elif kind == 'custom':
            # print(custom_list)
            ccs = custom_list.iloc[:,0].to_list()
            
        df = pd.DataFrame(columns=['cc','dnssec', 'dnssec_algo', 'deploy360', 
                                   'ns', 'authoritative', 'ip', 'af', 'asn4', 
                                   'asn6','region','anycast_provider', 'anycast_provider_ratio', 
                                   'ip_country'])
        zdf = pd.DataFrame(columns=['cc','level', 'module', 'tag'])
        zonemaster_data_df = pd.DataFrame(columns=['cc','level', 'category', 'test', 'data'])
        
        out_region_list = []
        out_region_list_4 = []
        out_region_list_6 = []
        anycast_list = []
        anycast_list_4 = []
        anycast_list_6 = []

        # exclude some ccTLDs with connection problems
        excluded_cc = ['BJ', 'CI']

        chunk_size = 30
        max_chunk = len(ccs) // chunk_size # start from 0
        chunk = 0

        cc_id = 0
    
        for cc in ccs:
            print(cc_id)

            # if cc is in excluded list, skip it
            # if cc in excluded_cc:
            #     continue

            # skip zonemaster analysis for now
            '''
            output_file = zonemaster_folder +"/zonemaster_" +str(cc)+".json"
            if not os.path.isfile(output_file):
                print("Getting zone master results for " + str(cc))
                run_zonemaster(cc, output_file)
            
            
            zonemaster_result, dataframe = get_zonemaster(cc, output_file)
            zonemaster_data_df = pd.concat([zonemaster_data_df, pd.DataFrame.from_records(dataframe)], ignore_index=True)
            

            zonemaster_level = None
            zonemaster_modules = []
            if ZONEMASTER_LEVELS[0] in  zonemaster_result.keys():
                zonemaster_level = ZONEMASTER_LEVELS[0]
                zonemaster_data = zonemaster_result[ZONEMASTER_LEVELS[0]]
                zonemaster_modules = list(zonemaster_data.keys())
            elif ZONEMASTER_LEVELS[1] in  zonemaster_result.keys():
                zonemaster_level = ZONEMASTER_LEVELS[1]
                zonemaster_data = zonemaster_result[ZONEMASTER_LEVELS[1]]
                zonemaster_modules = list(zonemaster_data.keys())
            elif ZONEMASTER_LEVELS[2] in  zonemaster_result.keys():
                zonemaster_level = ZONEMASTER_LEVELS[2]
                zonemaster_data  = zonemaster_result[ZONEMASTER_LEVELS[2]]
                zonemaster_modules = list(zonemaster_data.keys())
            elif ZONEMASTER_LEVELS[3] in  zonemaster_result.keys():
                zonemaster_level = ZONEMASTER_LEVELS[3]
                zonemaster_data = zonemaster_result[ZONEMASTER_LEVELS[3]]
                zonemaster_modules = list(zonemaster_data.keys())

            for zmodule in zonemaster_modules:
                for tagdata in zonemaster_data[zmodule]:
                    row = [{
                            'cc': cc,
                            'level': zonemaster_level,
                            'module': zmodule,
                            'tag': tagdata['tag']
                        }]
                    zdf = pd.concat([zdf,pd.DataFrame(row)], ignore_index=True)
            '''
            
            get_nss = GetDns()
            print("Checking NS records for " + str(cc))

            # check if cc is a tld
            is_tld = len(cc.strip('.').split('.')) == 1
            
            # to accommodate connection timed out, try n times
            trial = 0
            dns_data = None
            while trial<5:
                try:
                    if is_tld:
                        tld_nss = get_nss.get_common_ns(cc)
                        result = nic_client.whois_lookup(cc)
                        nss = result['name_servers']
                        dnssec = True if result['dnssec'] else False
                        dnskey_algo = None
                        whois_server = result['whois'] if result['whois'] else None
                        break
                    else:
                        result = get_nss.get_common_ns_complete(cc)
                        nss = result[cc]['nss']
                        dnssec = True if result[cc]['dnssec'] else False
                        dnskey_algo = None
                        break
                        
                except Exception as e:
                    # if connection timed out
                    trial = trial + 1
                    print(f'getdns failed! Try again!')
                    print(e)
                    continue


            if dnssec:
                print("Checking DS records for " + str(cc))
                
                if is_tld:
                    if isinstance(result['dnssec'], list):
                        dsset = result['dnssec'][0].split(" ")
                    else:
                        dsset = result['dnssec'].split(" ")
                    dnskey_algo = dnssec_algo_dict[dsset[1]]
                    
                else:
                    dnskey_algo = dnssec_algo_dict[str(list(result[cc]['dnssec'])[0])]

            else:
                print(f'No DNSSEC. Skip DS records query for {cc}')
                    
            deploy360 = cc in af_deploy360

            get_ips = GetDns()
            
            if nss:
                ip4_count = 0
                ip6_count = 0
                ip4_out_region = 0
                ip6_out_region = 0
                ip4_anycast = 0
                ipv6_anycast = 0
                cost = 0
                asn6 = None
                asn4 = None
                provider = None
                provider_ratio = 0
                provider_list = []
                # print(provider_list)
                for nsr in nss:
                    if is_tld:
                        ns_data = nsr.split(" ")
                        ns = ns_data[0]
                        ips = ns_data[1:]
                    else:
                        ns = nsr
                        ips = get_ips.get_common_ip(ns)[ns]
                    
                    autoritative_ns = True
                    # if ns not in tld_nss[cc]:
                    #     autoritative_ns = False
                    for nsip in ips:

                        af = ipaddress.ip_address(nsip).version
                        region = allocation_pyt.get_net(nsip)['region']
                        # prefix = allocation_pyt.get_net(nsip)['prefix']
                        ip_country = get_ip_country(maxmind_mmdb_file,nsip)
                        ns_anycast = [ x in ns.lower() for x in dns_anycast_provider]
                        ns_anycast = [x for x in ns_anycast if x]
                        
                        if af == 6:
                            asn6 = prefixes_asn_pyt.get_net(nsip)
                            ip6_count += 1
                            ''' NEED CODE UPDATE '''
                            if region != 'afrinic':
                                ip6_out_region += 1

                            if anycast_pyt.get_net(nsip) or ns_anycast or cc in freenom:
                                ipv6_anycast += 1
                                provider = get_anycast_provider(cc, ns, nsip)
                                provider_list.append(provider)
                            # else:
                                # print('No anycast ' + str(nsip))
                                
                            
                        else:
                            asn4 = prefixes_asn_pyt.get_net(nsip)
                            ip4_count += 1
                            ''' NEED CODE UPDATE '''
                            if region != 'afrinic':
                                ip4_out_region += 1
                            
                            if anycast_pyt.get_net(nsip) or ns_anycast or cc in freenom:
                                ip4_anycast += 1
                                provider = get_anycast_provider(cc, ns, nsip)
                                provider_list.append(provider)
                            # else:
                            #     print('No anycast ' + str(nsip))

                        row = [{
                            'cc': cc,
                            'dnssec': dnssec,
                            'dnssec_algo': dnskey_algo,
                            'deploy360': deploy360,
                            'ns': ns,
                            'ip': nsip,
                            'af': af,
                            'ip_country': ip_country,
                            'asn4': asn4,
                            'asn6': asn6,
                            'region': region,
                            'authoritative': autoritative_ns,
                            'anycast_provider': provider,
                            'anycast_provider_ratio': ','.join(provider_list)
                        }]

                        df = pd.concat([df,pd.DataFrame(row)],ignore_index=True)
                    

                out_region = [((ip6_out_region + ip4_out_region)/(ip4_count + ip6_count))*100]  * (ip4_count + ip6_count)
                anycast = [((ipv6_anycast + ip4_anycast)/(ip4_count + ip6_count))*100]  * (ip4_count + ip6_count)

                out_region4 = [((ip4_out_region)/(ip4_count))*100]  * (ip4_count + ip6_count)
                anycast4 = [((ip4_anycast)/(ip4_count))*100]  * (ip4_count + ip6_count)

                if ip6_count != 0:
                    out_region6 = [((ip6_out_region)/(ip6_count))*100]  * (ip4_count + ip6_count)
                    anycast6 = [((ipv6_anycast)/(ip6_count))*100]  * (ip4_count + ip6_count)
                else:
                    out_region6 = [0] * (ip4_count + ip6_count)
                    anycast6 = [0] * (ip4_count + ip6_count)
                

                out_region_list.extend(out_region)
                out_region_list_4.extend(out_region4)
                out_region_list_6.extend(out_region6)

                anycast_list.extend(anycast)
                anycast_list_4.extend(anycast4)
                anycast_list_6.extend(anycast6)

            
            else:
                # print(f'No NS records found for {cc}!')
                row = [{
                    'cc': cc,
                    'dnssec': False,
                    'dnssec_algo': None,
                    'deploy360': deploy360,
                    'ns': 0,
                    'ip': 0,
                    'af': 0,
                    'ip_country': None,
                    'asn4': None,
                    'asn6': None,
                    'region': 0,
                    'authoritative': False,
                    'anycast_provider': ' ',
                    'anycast_provider_ratio': ''
                }]

                df = pd.concat([df,pd.DataFrame(row)],ignore_index=True)
                
                
                out_region_list.append(0)
                out_region_list_6.append(0)
                out_region_list_4.append(0)
                anycast_list.append(0)
                anycast_list_4.append(0)
                anycast_list_6.append(0)
            
            cc_id = cc_id + 1

            if cc_id >= chunk_size:
                cc_id = 0
                chunk = chunk + 1
                df['out_region'] = out_region_list
                df['out_region_4'] = out_region_list_4
                df['out_region_6'] = out_region_list_6
                df['anycast'] = anycast_list
                df['anycast_4'] = anycast_list_4
                df['anycast_6'] = anycast_list_6
                df.to_csv(results_folder + '/' + kind + '_cctld_ns_' + str(chunk) + '.csv')
                df = pd.DataFrame(columns=['cc','dnssec', 'dnssec_algo', 'deploy360', 'ns', 'authoritative', 'ip', 'af', 'asn4', 'asn6','region','anycast_provider', 'anycast_provider_ratio', 'ip_country'])
                
                out_region_list = []
                out_region_list_4 = []
                out_region_list_6 = []
                anycast_list = []
                anycast_list_4 = []
                anycast_list_6 = []
    
    # save the remaining data as csv
        df.to_csv(results_folder + '/' + kind + '_cctld_ns_' + chunk + '.csv')
    
        # zdf.to_csv(results_folder + '/' + kind + '_cctld_zonemaster_result.csv')
        # zonemaster_data_df.to_csv(results_folder + '/' + kind + '_cctld_zonemaster_data.csv')
        
    
