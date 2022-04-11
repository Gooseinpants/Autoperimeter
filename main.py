import netlas
import re
import sys
import networkx as nx
import urlextract
from urlextract import URLExtract
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
        match2 = re.fullmatch(
            r'((http|https)\:\/\/){1}[a-zA-Z0-9\.\/\?\:@\-_=#]+\.([a-zA-Z]){2,6}([a-zA-Z0-9\.\&\/\?\:@\-_=#])*', s)
        if not match2:
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
    # Нахождение сервисов на домене, всё работает. Махров В.Д.
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
            uri = data['uri']
            header = http['headers']

            if 'status_code' in http:
                sc = http['status_code']
                if sc == 301 or sc == 302:
                    if 'location' in header:
                        locs = header['location']
                        for loc in locs:
                            print('Service on domain (' + str(domain_name) + '): ' + uri + ', Status code: ' + str(sc) + ', Redirected to: ' + loc)
                else:
                    print('Service on domain (' + str(domain_name) + '): ' + uri + ', Status code: ' + str(sc))

#09.04.22 - добавлен поиск ссылок на сервисе. Немножко наговнокодил, чтобы не выводились картинки
#и js-шлак. В поиске сервисов на айпи та же фигня. Исправлю на человеческий код, как только будет возможность. Махров В.Д.
            if 'body' in http:
                print('Links on service:')
                body = http['body']
                extractor = URLExtract()
                urls = extractor.find_urls(body, check_dns=True)
                for url in urls:
                    mark = 1

                    index = str(url).find(".png")
                    if index == -1 and mark == 1:
                        mark = 1
                    else:
                        mark = 0

                    index = str(url).find(".ico")
                    if index == -1 and mark == 1:
                        mark = 1
                    else:
                        mark = 0

                    index = str(url).find(".css")
                    if index == -1 and mark == 1:
                        mark = 1
                    else:
                        mark = 0

                    index = str(url).find(".svg")
                    if index == -1 and mark == 1:
                        mark = 1
                    else:
                        mark = 0

                    index = str(url).find(".jpg")
                    if index == -1 and mark == 1:
                        mark = 1
                    else:
                        mark = 0

                    index = str(url).find(".pdf")
                    if index == -1 and mark == 1:
                        mark = 1
                    else:
                        mark = 0

                    index = str(url).find(".js")
                    if index == -1 and mark == 1:
                        mark = 1
                    else:
                        mark = 0

                    if mark == 1:
                        print(str(url))

            print('////////')

        cnt_of_res['count'] -= 20  # number of results on one page
        number_of_page += 1


def check_and_add_Descr(graph, u_node, v_node, msg):
    if 'Description' in graph[f'{u_node}'][f'{v_node}']:
        graph[f'{u_node}'][f'{v_node}']['Description'] = graph[f'{u_node}'][f'{v_node}'][
                                                             'Description'] + msg
    else:
        graph[f'{u_node}'][f'{v_node}']['Description'] = msg


def direct_dns_records(domain_name):
    G.add_node(f'{domain_name}', Checked=True)
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
                if 'Checked' not in G.nodes[f'{txt_record}']:
                    G.nodes[f'{txt_record}']['Checked'] = False

            if 'a' in records_of_domain:
                a_record = records_of_domain['a']
                for a in a_record:
                    # Проверка на айпи массовой регистрации. Не фонтан, но лучше я не придумал. Махров В.Д.
                    sQuery2 = "a:" + a
                    cnt_of_res2 = netlas_connection.count(query=sQuery2, datatype='domain')
                    if cnt_of_res2['count'] > 30:
                        G.add_edge(f'{domain_name}', f'{a}', a_record=False)
                        G.nodes[f'{a}']['Checked'] = True  # нужно ли дальше исследовать такой айпи?
                    else:
                        G.add_edge(f'{domain_name}', f'{a}', a_record=True)
                        check_and_add_Descr(G, domain_name, a, f'This is an a-record received from {domain_name}. ')
                        if 'Checked' not in G.nodes[f'{a}']:
                            G.nodes[f'{a}']['Checked'] = False

            if 'ns' in records_of_domain:
                ns_record = records_of_domain['ns']
                for ns in ns_record:
                    G.add_edge(f'{domain_name}', f'{ns}', ns_record=True)

                    check_and_add_Descr(G, domain_name, ns, f'This is an ns-record received from {domain_name}. ')
                    if 'Checked' not in G.nodes[f'{ns}']:
                        G.nodes[f'{ns}']['Checked'] = False

            if 'mx' in records_of_domain:
                mx_record = records_of_domain['mx']
                for mx in mx_record:
                    G.add_edge(f'{domain_name}', f'{mx}', mx_record=True)

                    check_and_add_Descr(G, domain_name, mx, f'This is an mx-record received from {domain_name}. ')
                    if 'Checked' not in G.nodes[f'{mx}']:
                        G.nodes[f'{mx}']['Checked'] = False

            if 'cname' in records_of_domain:
                cname_record = records_of_domain['cname']
                for cname in cname_record:
                    G.add_edge(f'{domain_name}', f'{cname}', cname_record=True)

                    check_and_add_Descr(G, domain_name, cname, f'This is a cname-record received from {domain_name}. ')
                    if 'Checked' not in G.nodes[f'{cname}']:
                        G.nodes[f'{cname}']['Checked'] = False

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
            subdomain = item['data']['domain']
            G.add_edge(f'{domain_name}', f'{subdomain}', subdomain=True)

            check_and_add_Descr(G, domain_name, subdomain, f'This is a subdomain of the {domain_name} domain. ')
            G.nodes[f'{subdomain}']['Checked'] = False

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
            G.nodes[f'{side_domain}']['Checked'] = False

        cnt_of_res['count'] -= 20  # number of results on one page
        number_of_page += 1


def IP_research(IP):
    URI_search(IP)  # Ports and protocols just as targets
    whois_info(IP)  # Subnets, AS and whois stuff
    # services_IP(IP)
    G.nodes[f'{IP}']['Checked'] = True


def services_IP(IP):
    # Нахождение сервисов на айпи, выдаёт ошибку, но работает, разобраться. Махров В.Д.
    sQuery = "host:" + IP
    cnt_of_res = netlas_connection.count(query=sQuery, datatype='response')
    number_of_page = 0

    while cnt_of_res['count'] > 0:
        query_res = netlas_connection.query(query=sQuery, datatype='response', page=number_of_page)
        items = query_res['items']
        for item in items:

            # print('///////////')
            # print(json.dumps(item, sort_keys=True, indent=4))
            # print('///////////')

            data = item['data']
            http = data['http']
            uri = data['uri']
            header = http['headers']

            if 'status_code' in http:
                sc = http['status_code']
                if sc == 301 or sc == 302:
                    if 'location' in header:
                        locs = header['location']
                        for loc in locs:
                            print('Service on IP (' + str(IP) + '): ' + uri + ', Status code: ' + str(sc) + ', Redirected to: ' + loc)
                else:
                    print('Service on IP (' + str(IP) + '): ' + uri + ', Status code: ' + str(sc))

            if 'body' in http:
                print('Links on service:')
                body = http['body']
                extractor = URLExtract()
                urls = extractor.find_urls(body, check_dns=True)
                for url in urls:
                    mark = 1

                    index = str(url).find(".png")
                    if index == -1 and mark == 1:
                        mark = 1
                    else:
                        mark = 0

                    index = str(url).find(".ico")
                    if index == -1 and mark == 1:
                        mark = 1
                    else:
                        mark = 0

                    index = str(url).find(".css")
                    if index == -1 and mark == 1:
                        mark = 1
                    else:
                        mark = 0

                    index = str(url).find(".svg")
                    if index == -1 and mark == 1:
                        mark = 1
                    else:
                        mark = 0

                    index = str(url).find(".jpg")
                    if index == -1 and mark == 1:
                        mark = 1
                    else:
                        mark = 0

                    index = str(url).find(".pdf")
                    if index == -1 and mark == 1:
                        mark = 1
                    else:
                        mark = 0

                    index = str(url).find(".js")
                    if index == -1 and mark == 1:
                        mark = 1
                    else:
                        mark = 0

                    if mark == 1:
                        print(str(url))

            print('////////')
        cnt_of_res['count'] -= 20  # number of results on one page
        number_of_page += 1


def URI_search(IP):  # Check via responses records
    sQuery = "host:" + IP
    cnt_of_res = netlas_connection.count(query=sQuery)
    number_of_page = 0

    while cnt_of_res['count'] > 0:
        query_res = netlas_connection.query(query=sQuery, page=number_of_page)
        items = (query_res['items'])

        for item in items:
            uri = item['data']['uri']
            G.add_edge(f'{IP}', f'{uri}', URI=True)
            msg = f'This is an URI received from {IP}. '

            if 'Checked' not in G.nodes[f'{uri}']:
                G.nodes[f'{uri}']['Checked'] = False

            if 'Description' in G[f'{IP}'][f'{uri}']:
                G[f'{IP}'][f'{uri}']['Description'] = G[f'{IP}'][f'{uri}']['Description'] + msg
            else:
                G[f'{IP}'][f'{uri}']['Description'] = msg
        cnt_of_res['count'] -= 20  # number of results on one page
        number_of_page += 1


def whois_info(IP):  # Will be done later
    pass


# нужна ли?
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
            with open('config', 'w') as f:
                f.write(i)
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


def Dispatcher(depth=3):
    if depth == 0:
        return
    print(f'In dispatcher. {depth} iteration')
    with open('test.edgelist', 'r') as f:
        while True:
            tmp = f.readline().split(' ')
            if tmp[0] == '':
                break
            # для дальнейшего развития: для поддоменов стоит искать только записи.
            if is_domain(tmp[1]) == 1 and G.nodes[f'{tmp[1]}']['Checked'] is False:
                direct_dns_records(tmp[1])
                G.nodes[f'{tmp[1]}']['Checked'] = True
            if is_ip(tmp[1]) == 1 and G.nodes[f'{tmp[1]}']['Checked'] is False:
                IP_research(tmp[1])
                G.nodes[f'{tmp[1]}']['Checked'] = True

    print(G)
    with open('test.edgelist', 'wb') as f:
        nx.write_edgelist(G, f)
    # nx.write_multiline_adjlist(G, fh)

    Dispatcher(depth - 1)


if __name__ == "__main__":
    Finder(args)
    with open('test.edgelist', 'wb') as f:
        nx.write_edgelist(G, f)
    print("Dispatcher was launched")
    Dispatcher(3)

    with open('test.edgelist', 'r') as f:
        print(*f.readlines())
    print(G)

# Graphical output of the graph
#  nx.draw_networkx(G)
#  plt.show()  # necessary


# возможные взаимосвяи:
# поддомены точно входят в скоуп.
# в тхт записях поискать домены и айпи. Они будут входить в скоуп.
# Если есть перекрёстные ссылки на сайтах, то они входят в скоуп.
# Если у доменов/поддоменов и тд общая mx- запись, то входит в скоуп
