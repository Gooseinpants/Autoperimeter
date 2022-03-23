import netlas
import re
import sys
import json


def parse_args(argv):
    if argv[1][0] != '-':
        args = [argv[1]]
        print("arg = ", args[0])
    elif len(argv) == 2:
        args = [argv[1]]
        print("flags = ", args[0])
    else:
        args = [argv[1], argv[2]]
        print("flags = ", args[0])
        print("arg = ", args[1])
    # TODO: добавить обработку случая, когда нет параметров
    return args


def print_help():
    print("Usage: python3 main.py [flags] [target] \n")
    print("Target specification: Domain names or IP-addresses\n")
    print("Flags:")
    print("    -h: Print this page")
    print("    -c: Enter Netlas API key: main.py -c \'API key\'")


def is_ip(s):
    match = re.fullmatch(r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', s)
    if match:
        return 1
    else:
        return 0


def is_domain(s):
    match = re.fullmatch(r'\b[a-zA-Z0-9\.\/\?\:@\-_=#]+\.([a-zA-Z]){2,6}([a-zA-Z0-9\.\&\/\?\:@\-_=#])*', s)
    if match:
        return 1
    else:
        return 0


def is_uri(s):
    match = re.fullmatch(
        r'((http|https)\:\/\/){1}[a-zA-Z0-9\.\/\?\:@\-_=#]+\.([a-zA-Z]){2,6}([a-zA-Z0-9\.\&\/\?\:@\-_=#])*', s)
    if match:
        return 1
    else:
        return 0


def is_subnet(s):
    match = re.fullmatch(
        r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([1-3]?\d)', s)
    if match:
        return 1
    else:
        match = re.fullmatch(
            r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)-((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
            s)
        if match:
            return 1
        return 0


def is_as(s):
    match = re.fullmatch(r'AS\d{1,5}', s)
    if match:
        return 1
    else:
        return 0


def is_flags(s):
    if s[0] == '-':
        return 1
    else:
        return 0


def domain_research(domain_name):
    direct_dns_records(domain_name)
    subdomains(domain_name)
    sidedomains(domain_name)
    dif_lvl_domains(domain_name)


def direct_dns_records(domain_name):
    sQuery = "domain:" + domain_name
    query_res = netlas_connection.query(query=sQuery, datatype='domain')
    items = (query_res['items'])
    for i in range(len(items)):
        records_of_domain = items[i]['data']
        if 'txt' in records_of_domain:
            txt_record = records_of_domain['txt']
            print(txt_record)
        if 'a' in records_of_domain:
            a_record = records_of_domain['a']
            for a in range(len(a_record)):
                IPs.add(a_record[a])
        if 'ns' in records_of_domain:
            ns_record = records_of_domain['ns']
            for ns in range(len(ns_record)):
                domains.add(ns_record[ns])
                # print(ns_record[ns])
        if 'mx' in records_of_domain:
            mx_record = records_of_domain['mx']
            for mx in range(len(mx_record)):
                domains.add(mx_record[mx])
                # print(mx_record[mx])
        if 'cname' in records_of_domain:
            cname_record = records_of_domain['cname']
            for cname in range(len(cname_record)):
                domains.add(cname_record[cname])
                # print(cname_record[cname])


def subdomains(domain_name):  # *.domain.name
    sQuery = "domain:" + "*." + domain_name
    query_res = netlas_connection.query(query=sQuery, datatype='domain')
    items = (query_res['items'])
    for item in items:
        domains.add(item['data']['domain'])



def sidedomains(domain_name):    # domain.[ru|com|cz|...]
    sQuery = "domain:" + domain_name.split('.')[0]+".*"
    query_res = netlas_connection.query(query=sQuery, datatype='domain')
    items = (query_res['items'])
    for item in items:
        domains.add(item['data']['domain'])


def dif_lvl_domains(domain_name):  # domain.*.[ru|com|cz|...]
    pass
    # print('tbd')


def IP_research():
    pass
    # print("tbd")


def enter_api_key():
    for i in args:
        if is_flags(i) == 0:
            global api_key
            api_key = i
            f = open('config', 'w')
            f.write(i)
            f.close()
            break


def parse_flags(flags):
    for i in flags:
        if i == 'h':
            print_help()
        elif i == 'c':
            enter_api_key()


api_key = ''
args = parse_args(sys.argv)
for i in args:
    if is_flags(i):
        parse_flags(i)

if api_key != '':
    sys.exit()

f = open('config')
api_key = f.read()
if api_key == '':
    print('Enter your Netlas API key')
    sys.exit()
else:
    netlas_connection = netlas.Netlas(api_key=api_key)

IPs = set()
domains = set()
for i in args:
    if is_uri(i):
        print("URI\n")
        break
    elif is_domain(i):
        domain_research(i)
        break
    elif is_ip(i):
        print("IP\n")
        break
    elif is_subnet(i):
        print("subnet\n")
        break
    elif is_as(i):
        print("AS\n")
        break
    elif is_flags(i):
        continue
    else:
        print(i, 'is not a valid target')
        break

for IP in IPs:
    print(IP)
for domain in domains:
    print(domain)
