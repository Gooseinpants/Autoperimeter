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


G = nx.DiGraph()  # Our main graph


def domain_research(domain_name):
    direct_dns_records(domain_name)
    subdomains(domain_name)
    sidedomains(domain_name)
    services_dom(domain_name)


def services_dom(domain_name):
    # Попытка найти сервисы на домене, дело продвигается. Махров В.Д.
    sQuery = "host:" + domain_name
    cnt_of_res = netlas_connection.count(query=sQuery, datatype='response')
    number_of_page = 0

    while cnt_of_res['count'] > 0:
        query_res = netlas_connection.query(query=sQuery, datatype='response', page=number_of_page)
        items = query_res['items']
        for item in items:
            # print('///////////')
            # print(json.dumps(item, sort_keys=True, indent=4))
            # print('///////////')
            high = item['highlight']
            data = item['data']
            http = data['http']
            header = http['headers']

            if 'host' in high:
                hs = high['host']
                if 'status_code' in http:
                    sc = http['status_code']
                    print('Service on domain: ' + hs + ', Status code: ', + sc)

            # header = high['headers']
            # if 'status_code' in header:
            # sc = high['status_code']
            # print(sc)
            # print('///////////')
        cnt_of_res['count'] -= 20  # number of results on one page
        number_of_page += 1


def check_and_add_Descr(graph, u_node, v_node, msg):
    if graph[f'{u_node}'][f'{v_node}'].get('Description') is not None:
        graph[f'{u_node}'][f'{v_node}']['Description'] = graph[f'{u_node}'][f'{v_node}'][
                                                             'Description'] + msg
    else:
        graph[f'{u_node}'][f'{v_node}']['Description'] = msg


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
                G.add_edge(f'{domain_name}', f'{txt_record}', txt_record=True)
                check_and_add_Descr(G, domain_name, txt_record, f'This is a txt-record received from {domain_name}. ')

                print(txt_record)

            if 'a' in records_of_domain:
                a_record = records_of_domain['a']
                for a in a_record:
                    # Проверка на айпи массовой регистрации. Не фонтан, но лучше я не придумал. Махров В.Д.
                    sQuery2 = "a:" + a
                    cnt_of_res2 = netlas_connection.count(query=sQuery2, datatype='domain')
                    if cnt_of_res2['count'] > 30:
                        G.add_edge(f'{domain_name}', f'{a}', a_record=False)
                    else:
                        G.add_edge(f'{domain_name}', f'{a}', a_record=True)
                        check_and_add_Descr(G, domain_name, a, f'This is an a-record received from {domain_name}. ')
                        ports_and_protocols(f'{a}')
                    IPs.add(a)

            if 'ns' in records_of_domain:
                ns_record = records_of_domain['ns']
                for ns in ns_record:
                    G.add_edge(f'{domain_name}', f'{ns}', ns_record=True)

                    check_and_add_Descr(G, domain_name, ns, f'This is an ns-record received from {domain_name}. ')

                    domains.add(ns)

            if 'mx' in records_of_domain:
                mx_record = records_of_domain['mx']
                for mx in mx_record:
                    G.add_edge(f'{domain_name}', f'{mx}', mx_record=True)

                    check_and_add_Descr(G, domain_name, mx, f'This is an mx-record received from {domain_name}. ')

                    domains.add(mx)

            if 'cname' in records_of_domain:
                cname_record = records_of_domain['cname']
                for cname in cname_record:
                    G.add_edge(f'{domain_name}', f'{cname}', cname_record=True)

                    check_and_add_Descr(G, domain_name, cname, f'This is a cname-record received from {domain_name}. ')

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
            G.add_edge(f'{domain_name}', f'{tmp}', subdomain=True)

            check_and_add_Descr(G, domain_name, tmp, f'This is a subdomain of the {domain_name} domain. ')

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

            G.add_edge(f'{domain_name}', f'{side_domain}', side_domain=True)

            check_and_add_Descr(G, domain_name, side_domain, f'This is a side-domain of the {domain_name} domain. ')

            domains.add(side_domain)

        cnt_of_res['count'] -= 20  # number of results on one page
        number_of_page += 1


def IP_research(IP):
    rDNS(IP)  # Domains
    ports_and_protocols(IP)  # Ports and protocols just as targets
    whois_info(IP)  # Subnets, AS and whois stuff


def rDNS(IP):  # Link if a-record of ptr-record is IP
    pass


def ports_and_protocols(IP):  # Check via responses records
    sQuery = "host:" + IP
    cnt_of_res = netlas_connection.count(query=sQuery)
    number_of_page = 0

    while cnt_of_res['count'] > 0:
        query_res = netlas_connection.query(query=sQuery, page=number_of_page)
        items = (query_res['items'])

        for item in items:
            port = item['data']['port']
            protocol = item['data']['protocol']
            prot7 = item['data']['prot7']

            #  Возможно есть лишние условия
            if G.nodes[IP].get('a_record') is not None and G.nodes[IP]['a_record'] == 'True':
                if G.nodes[IP].get('port') is not None:
                    G.nodes[IP]['port'].add(port)
                else:
                    G.nodes[IP]['port'] = {port}

                if G.nodes[IP].get('protocol') is not None:
                    G.nodes[IP]['protocol'].add(protocol)
                else:
                    G.nodes[IP]['protocol'] = {protocol}

                if G.nodes[IP].get('prot7') is not None:
                    G.nodes[IP]['prot7'].add(prot7)
                else:
                    G.nodes[IP]['prot7'] = {prot7}

            elif G.nodes[IP].get('a_record') is None:
                if G.nodes[IP].get('port') is not None:
                    G.nodes[IP]['port'].add(port)
                else:
                    G.nodes[IP]['port'] = {port}

                if G.nodes[IP].get('protocol') is not None:
                    G.nodes[IP]['protocol'].add(protocol)
                else:
                    G.nodes[IP]['protocol'] = {protocol}

                if G.nodes[IP].get('prot7') is not None:
                    G.nodes[IP]['prot7'].add(prot7)
                else:
                    G.nodes[IP]['prot7'] = {prot7}

        cnt_of_res['count'] -= 20  # number of results on one page
        number_of_page += 1


def whois_info(IP):  # Will be done later
    pass


def call_from_results(s):
    if is_uri(s):
        print("URI\n")
    elif is_domain(s):
        domain_research(s)
    elif is_ip(s):
        IP_research(s)
    elif is_subnet(s):
        print("subnet\n")
    elif is_as(s):
        print("AS\n")


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
            IP_research(arg)
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

# for IP in IPs:
#     print(IP)
# for domain in domains:
#     print(domain)

# Examples of output of our graph
print(G)
#  nx.draw_networkx(G)
#  plt.show()  # necessary

fh = open("test.edgelist", "wb")
nx.write_edgelist(G, fh)
# nx.write_multiline_adjlist(G, fh)

fh.close()
