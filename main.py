import netlas
import re
import sys
import networkx as nx
import matplotlib.pyplot as plt
import json


def parse_args(argv):
    if len(argv) == 1:
        print("Please enter search parameters")
        sys.exit()
    elif argv[1][0] != '-':
        args = [argv[1]]
        print("arg = ", args[0])
    elif len(argv) == 2:
        args = [argv[1]]
        print("flags = ", args[0])
    else:
        args = [argv[1], argv[2]]
        print("flags = ", args[0])
        print("arg = ", args[1])
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


G = nx.MultiGraph()  # Our main graph


def domain_research(domain_name):
    direct_dns_records(domain_name)
    subdomains(domain_name)
    sidedomains(domain_name)
    #services_dom(domain_name)

def services_dom(domain_name):
    #Попытка найти сервисы на домене, дело не пошло. Махров В.Д.
    sQuery = "host:" + domain_name
    cnt_of_res = netlas_connection.count(query=sQuery, datatype='host')
    number_of_page = 0

    while cnt_of_res['count'] > 0:
        query_res = netlas_connection.query(query=sQuery, datatype='host', page=number_of_page)

        #print("/////////")
        #print(query_res)
        #print("/////////")

        items = query_res['items']
        #уточнить про вид полученной записи и кол-во коинов, допилить. Махров В.Д.


def direct_dns_records(domain_name):
    sQuery = "domain:" + domain_name
    cnt_of_res = netlas_connection.count(query=sQuery, datatype='domain')
    number_of_page = 0

    while cnt_of_res['count'] > 0:
        query_res = netlas_connection.query(query=sQuery, datatype='domain', page=number_of_page)
        items = query_res['items']

        for item in items:
            records_of_domain = item['data']
            if 'txt' in records_of_domain:
                txt_record = records_of_domain['txt']
                G.add_edge(f'{domain_name}', f'{txt_record}', key='txt_record', txt_record=True)
                print(txt_record)
            if 'a' in records_of_domain:
                a_record = records_of_domain['a']
                for a in a_record:
                    #Проверка на айпи массовой регистрации. Не фонтан, но лучше я не придумал. Махров В.Д.
                    sQuery2 = "a:" + a
                    cnt_of_res2 = netlas_connection.count(query=sQuery2, datatype='domain')
                    if cnt_of_res2['count'] > 10:
                        G.add_edge(f'{domain_name}', f'{a}', key='a_record', a_record=False)
                    else:
                        G.add_edge(f'{domain_name}', f'{a}', key='a_record', a_record=True)
                    IPs.add(a)
            if 'ns' in records_of_domain:
                ns_record = records_of_domain['ns']
                for ns in ns_record:
                    G.add_edge(f'{domain_name}', f'{ns}', key='ns_record', ns_record=True)
                    domains.add(ns)
            if 'mx' in records_of_domain:
                mx_record = records_of_domain['mx']
                for mx in mx_record:
                    G.add_edge(f'{domain_name}', f'{mx}', key='mx_record', mx_record=True)
                    domains.add(mx)
            if 'cname' in records_of_domain:
                cname_record = records_of_domain['cname']
                for cname in cname_record:
                    G.add_edge(f'{domain_name}', f'{cname}', key='cname_record', cname_record=True)
                    domains.add(cname)

        cnt_of_res['count'] -= 20  # number of results on one page
        number_of_page += 1


def subdomains(domain_name):  # *.domain.name
    sQuery = "domain:" + "*." + domain_name
    cnt_of_res = netlas_connection.count(query=sQuery, datatype='domain')
    number_of_page = 0

    while cnt_of_res['count'] > 0:
        query_res = netlas_connection.query(query=sQuery, datatype='domain', page=number_of_page)
        items = (query_res['items'])

        for item in items:
            tmp = item['data']['domain']
            G.add_edge(f'{domain_name}', f'{tmp}', key='subdomain', subdomain=True)
            domains.add(item['data']['domain'])

        cnt_of_res['count'] -= 20  # number of results on one page
        number_of_page += 1


def sidedomains(domain_name):  # domain.[ru|com|cz|...]
    sQuery = "domain:" + domain_name.split('.')[0] + ".*"
    cnt_of_res = netlas_connection.count(query=sQuery, datatype='domain')
    number_of_page = 0

    while cnt_of_res['count'] > 0:
        query_res = netlas_connection.query(query=sQuery, datatype='domain', page=number_of_page)
        items = (query_res['items'])

        for item in items:
            side_domain = item['data']['domain']

            if side_domain == domain_name:
                continue

            G.add_edge(f'{domain_name}', f'{side_domain}', key='side-domain', side_domain=True)
            domains.add(side_domain)

        cnt_of_res['count'] -= 20  # number of results on one page
        number_of_page += 1


def IP_research():
    pass


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


def Finder(args):
    for arg in args:
        if is_uri(arg):
            print("URI\n")
            break
        elif is_domain(arg):
            domain_research(arg)
            break
        elif is_ip(arg):
            print("IP\n")
            break
        elif is_subnet(arg):
            print("subnet\n")
            break
        elif is_as(arg):
            print("AS\n")
            break
        elif is_flags(arg):
            continue
        else:
            print(arg, 'is not a valid target')
            break


if __name__ == "__main__":
    Finder(args)

for IP in IPs:
    print(IP)
for domain in domains:
    print(domain)

# Examples of output of our graph
#  print(G)
#  print(G.adj)
#  nx.draw_networkx(G)
#  plt.show()  # necessary

fh = open("output.adjlist", "wb")
nx.write_multiline_adjlist(G, fh)
fh.close()
