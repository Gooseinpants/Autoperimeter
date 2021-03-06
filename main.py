import sys
import time
import re

import netlas
import json
import networkx as nx
from pyvis.network import Network
from urlextract import URLExtract
from tlds import arr_tlds

import check as ch
import service as sv

DEPTH_OF_SEARCH = 3
CERTAINLY = 1
PROBABLY = 0.5
UNLIKELY = 0.2
HIGHLY_UNLIKELY = 0.1
NOT_IN_SCOPE = 0

G = nx.DiGraph()  # Our main graph


def check_and_add_Descr(graph, u_node, v_node, msg):
    if 'Description' in graph[f'{u_node}'][f'{v_node}']:
        graph[f'{u_node}'][f'{v_node}']['Description'] = graph[f'{u_node}'][f'{v_node}'][
                                                             'Description'] + msg
    else:
        graph[f'{u_node}'][f'{v_node}']['Description'] = msg


def check_and_add_Weight(graph, node, weight):
    if weight == NOT_IN_SCOPE:
        graph.nodes[f'{node}']['Scope'] = weight
        return
    if 'Scope' in graph.nodes[f'{node}']:
        graph.nodes[f'{node}']['Scope'] = graph.nodes[f'{node}']['Scope'] + weight
    else:
        graph.nodes[f'{node}']['Scope'] = weight


def cross_links(domain_name, domain_name_orig):
    result = 0
    finisheds = 0
    sQuery = "(host:" + domain_name + ") AND ((protocol:http) OR (protocol:https))"
    cnt_of_res = netlas_connection.count(query=sQuery, datatype='response')
    number_of_page = 0
    while cnt_of_res['count'] > 0:
        query_res = netlas_connection.query(query=sQuery, datatype='response', page=number_of_page)
        items = query_res['items']
        for item in items:
            data = item['data']
            http = data['http']

            if 'status_code' in http:
                sc = http['status_code']
                if sc == 200:
                    if 'body' in http:
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
                                index = str(url).find(str(domain_name_orig))
                                if index != -1:
                                    mark = 1
                                else:
                                    mark = 0

                                if mark == 1:
                                    result = 1
                                    return result

        cnt_of_res['count'] -= 20  # number of results on one page
        number_of_page += 1
        finisheds += 20
        if finisheds == 100:
            break
    return result


def services_dom(domain_name):
    """Нахождение сервисов на домене."""
    sQuery = "(host:" + domain_name + ") AND ((protocol:http) OR (protocol:https))"
    cnt_of_res = netlas_connection.count(query=sQuery, datatype='response')
    number_of_page = 0

    while cnt_of_res['count'] > 0:
        query_res = netlas_connection.query(query=sQuery, datatype='response', page=number_of_page)
        items = query_res['items']
        for item in items:
            data = item['data']
            http = data['http']
            uri = data['uri']
            ip = data['ip']

            if 'status_code' in http:
                sc = http['status_code']
                if sc != 301 and sc != 302:
                    sQuery2 = "a:" + ip
                    cnt_of_res2 = netlas_connection.count(query=sQuery2, datatype='domain')

                    if cnt_of_res2['count'] < 30:
                        G.add_edge(f'{domain_name}', f'{uri}', service_on_domain=True)

                        G.nodes[f'{uri}']['Checked'] = True
                        msg = f'This is a service on domain ({domain_name}) with status code: {sc}. '
                        check_and_add_Descr(G, domain_name, uri, msg)
                        check_and_add_Weight(G, uri, CERTAINLY)

            # Поиск по g-тэгам
            if 'tag' in data:
                tags = data['tag']
                for tag in tags:
                    if 'google_tag_manager' in tag:
                        body = http['body']
                        google_tags(str(body), domain_name)

            # 09.04.22 - добавлен поиск ссылок на сервисе. Немножко наговнокодил, чтобы не выводились картинки
            # и js-шлак. В поиске сервисов на айпи та же фигня. Исправлю на человеческий код, как только будет возможность. Махров В.Д.
            if 'body' in http:
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
                        # 12.04.22 - поиск перекрёстных ссылок. Регулярные выражения это не мой случай. Махров В.Д.
                        index = str(url).find("www.")
                        if index != -1:
                            index_save = index + 4
                            index = str(url).find("/", index_save)
                            if index != -1:
                                new_dom = str(url)[index_save:index]
                            else:
                                new_dom = str(url)[index_save:]
                        else:
                            index = str(url).find("://")
                            index_save = index + 3
                            index = str(url).find("/", index_save)
                            if index != -1:
                                new_dom = str(url)[index_save:index]
                            else:
                                new_dom = str(url)[index_save:]

                        mark = cross_links(new_dom, domain_name)
                        if mark == 1:
                            G.add_edge(f'{domain_name}', f'{new_dom}', service_on_domain=True)
                            if 'Checked' not in G.nodes[f'{new_dom}']:
                                G.nodes[f'{new_dom}']['Checked'] = False
                            msg = f'This is a domain which has cross-links with main domain: {domain_name}. '
                            check_and_add_Descr(G, domain_name, new_dom, msg)
                            check_and_add_Weight(G, new_dom, CERTAINLY)

        cnt_of_res['count'] -= 20  # number of results on one page
        number_of_page += 1


def direct_dns_records(domain_name):
    """Поиск записей у DNS сервера"""
    G.add_node(f'{domain_name}', Checked=True)
    sQuery = "domain:" + domain_name
    cnt_of_res = netlas_connection.count(query=sQuery, datatype='domain')
    if cnt_of_res['count'] == 0:
        return
    downloaded_query = netlas_connection.download(query=sQuery, datatype='domain', size=cnt_of_res['count'])

    for query_res in downloaded_query:
        item = json.loads(query_res)

        records_of_domain = item['data']

        if 'txt' in records_of_domain:
            txt_record = records_of_domain['txt']
            G.add_edge(f'{domain_name}', f'{txt_record}', txt_record=True)
            check_and_add_Descr(G, domain_name, txt_record, f'This is a txt-record received from {domain_name}. ')
            G.nodes[f'{txt_record}']['Checked'] = True

            ip_regex = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', f'{txt_record}')  # находим айпишники в txt записи

            for found_ip in ip_regex:
                G.add_edge(f'{domain_name}', f'{found_ip}', URI=True)
                msg = f'This is an IPv4 address found in a txt-record of the {domain_name} domain. '
                check_and_add_Descr(G, domain_name, found_ip, msg)
                check_and_add_Weight(G, found_ip, CERTAINLY)
                if 'Checked' not in G.nodes[f'{found_ip}']:
                    G.nodes[f'{found_ip}']['Checked'] = False

            for tld in arr_tlds:  # находим все домены в txt записи
                tlds_regex = re.findall(r'(?:[0-9A-Za-z-]*\.){1,61}' + f'(?:{tld}[^0-9A-Za-z-.]|{tld}$)',
                                        f'{txt_record}')
                for found_domain in tlds_regex:
                    if not found_domain[-1:].isalpha():
                        found_domain = found_domain[:-1]
                        # устранение лишнего не алфавитного символа(регулярное выражение на пару строк выше иногда выдает строку с лишним символом)
                    G.add_edge(f'{domain_name}', f'{found_domain}', domain_in_txt=True)
                    msg = f'This is an domain found in a txt-record of the {domain_name} domain. '
                    check_and_add_Descr(G, domain_name, found_domain, msg)
                    check_and_add_Weight(G, found_domain, HIGHLY_UNLIKELY)
                    if 'Checked' not in G.nodes[f'{found_domain}']:
                        G.nodes[f'{found_domain}']['Checked'] = False

        if 'a' in records_of_domain:
            a_record = records_of_domain['a']
            for a in a_record:
                # Проверка на айпи массовой регистрации. Махров В.Д.
                sQuery2 = "a:" + a
                cnt_of_res2 = netlas_connection.count(query=sQuery2, datatype='domain')
                # вес пока добавляется а-записи, которая не является айпи массовой регистрации
                if cnt_of_res2['count'] > 50:
                    # является айпи массовой регистрации -> не является а-записью
                    G.add_edge(f'{domain_name}', f'{a}', a_record=False)
                    check_and_add_Descr(G, domain_name, a, f'This is an a-record received from {domain_name}. ')
                    G.nodes[f'{a}']['Checked'] = True
                else:
                    G.add_edge(f'{domain_name}', f'{a}', a_record=True)
                    check_and_add_Descr(G, domain_name, a, f'This is an a-record received from {domain_name}. ')
                    check_and_add_Weight(G, a, PROBABLY)
                    if 'Checked' not in G.nodes[f'{a}']:
                        G.nodes[f'{a}']['Checked'] = False

        if 'ns' in records_of_domain:
            ns_record = records_of_domain['ns']
            for ns in ns_record:
                G.add_edge(f'{domain_name}', f'{ns}', ns_record=True)

                check_and_add_Descr(G, domain_name, ns, f'This is an ns-record received from {domain_name}. ')
                check_and_add_Weight(G, ns, HIGHLY_UNLIKELY)
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


def subdomains(domain_name):
    """Поиск поддоменов"""
    sQuery = "domain:" + "*." + domain_name
    cnt_of_res = netlas_connection.count(query=sQuery, datatype='domain')
    if cnt_of_res['count'] == 0:
        return
    downloaded_query = netlas_connection.download(query=sQuery, datatype='domain', size=cnt_of_res['count'])

    for query_res in downloaded_query:
        item = json.loads(query_res)

        subdomain = item['data']['domain']
        G.add_edge(f'{domain_name}', f'{subdomain}', subdomain=True)

        check_and_add_Descr(G, domain_name, subdomain, f'This is a subdomain of the {domain_name} domain. ')
        check_and_add_Weight(G, subdomain, CERTAINLY)
        if 'Checked' not in G.nodes[f'{subdomain}']:
            G.nodes[f'{subdomain}']['Checked'] = False


def sidedomains(domain_name, original_domain=''):
    """Поиск доменов вида domain.[ru|com|cz|...]"""
    sQuery = "domain:" + domain_name.split('.')[0] + ".*"
    cnt_of_res = netlas_connection.count(query=sQuery, datatype='domain')
    if cnt_of_res['count'] == 0:
        return
    downloaded_query = netlas_connection.download(query=sQuery, datatype='domain', size=cnt_of_res['count'])

    for query_res in downloaded_query:
        item = json.loads(query_res)

        side_domain = item['data']['domain']

        if side_domain == domain_name or side_domain == original_domain:
            continue

        cross = cross_links(side_domain, domain_name)

        if cross == 1:
            G.add_edge(f'{domain_name}', f'{side_domain}', side_domain=True)
            check_and_add_Descr(G, domain_name, side_domain, f'This is a side-domain of the {domain_name} domain. ')
            check_and_add_Weight(G, side_domain, CERTAINLY)
            if 'Checked' not in G.nodes[f'{side_domain}']:
                G.nodes[f'{side_domain}']['Checked'] = False
            G.nodes[f'{side_domain}']['side_domain'] = True
        else:
            continue
            # с этим большие проблемы

            # G.add_edge(f'{domain_name}', f'{side_domain}', side_domain=True)
            # check_and_add_Descr(G, domain_name, side_domain, f'This is a side-domain of the {domain_name} domain. ')
            # check_and_add_Weight(G, side_domain, 0.3)  # возможно стоит поменять и сделать константу с весом
            # if 'Checked' not in G.nodes[f'{side_domain}']:
            #     G.nodes[f'{side_domain}']['Checked'] = False
            # G.nodes[f'{side_domain}']['side_domain'] = True


def domain_research(domain_name, original_domain=''):
    """Функция для исследования домена"""
    direct_dns_records(domain_name)
    subdomains(domain_name)
    sidedomains(domain_name, original_domain)
    services_dom(domain_name)


def google_tags(body, domain):
    """Поиск сервисов с одинаковым google-тэгом"""
    index = body.find("GTM-")
    if index != -1:
        index2 = index + 11
    else:
        return

    tag = body[index:index2]

    sQuery = "(tag.google_tag_manager:*) AND (http.body:" + tag + ")"
    cnt_of_res = netlas_connection.count(query=sQuery, datatype='response')
    if cnt_of_res['count'] == 0:
        return
    downloaded_query = netlas_connection.download(query=sQuery, datatype='response', size=cnt_of_res['count'])

    for query_res in downloaded_query:
        item = json.loads(query_res)

        data = item['data']
        uri = data['uri']
        G.add_edge(f'{domain}', f'{uri}', Same_g_tag=True)

        G.nodes[f'{uri}']['Checked'] = True
        msg = f'This is an URI received from {domain}. '
        check_and_add_Descr(G, domain, uri, msg)
        check_and_add_Weight(G, uri, CERTAINLY)


def services_IP(IP):
    """Поиск сервисов на IP"""
    sQuery = "(host:" + IP + ") AND ((protocol:http) OR (protocol:https))"
    cnt_of_res = netlas_connection.count(query=sQuery, datatype='response')
    if cnt_of_res['count'] == 0:
        return
    downloaded_query = netlas_connection.download(query=sQuery, datatype='response', size=cnt_of_res['count'])

    for query_res in downloaded_query:
        item = json.loads(query_res)

        data = item['data']
        http = data['http']
        uri = data['uri']

        if 'status_code' in http:
            sc = http['status_code']
            if sc != 301 and sc != 302:
                G.add_edge(f'{IP}', f'{uri}', service_on_IP=True)

                G.nodes[f'{uri}']['Checked'] = True
                msg = f'This is a service on IP ({IP}): with status code: {sc}. '
                check_and_add_Descr(G, IP, uri, msg)
                check_and_add_Weight(G, uri, CERTAINLY)




def URI_search(IP):
    """Check via response records"""
    sQuery = "host:" + IP
    cnt_of_res = netlas_connection.count(query=sQuery, datatype='response')
    if cnt_of_res['count'] == 0:
        return
    downloaded_query = netlas_connection.download(query=sQuery, datatype='response', size=cnt_of_res['count'])

    for query_res in downloaded_query:
        item = json.loads(query_res)
        uri = item['data']['uri']
        G.add_edge(f'{IP}', f'{uri}', URI=True)
        msg = f'This is an URI received from {IP}. '
        check_and_add_Descr(G, IP, uri, msg)
        check_and_add_Weight(G, uri, CERTAINLY)
        if 'Checked' not in G.nodes[f'{uri}']:
            G.nodes[f'{uri}']['Checked'] = False


def whois_info(IP):  # Will be done later
    pass


def IP_research(IP):
    """Функция исследования IP"""
    URI_search(IP)  # Ports and protocols just as targets
    whois_info(IP)  # Subnets, AS and whois stuff
    services_IP(IP)
    G.nodes[f'{IP}']['Checked'] = True


def Finder(arguments):
    """Функция первичного поиска"""
    for arg in arguments:
        if ch.is_uri(arg):
            print("URI\n")
            break
        elif ch.is_domain(arg):
            G.add_node(f'{arg}', Scope=CERTAINLY)
            domain_research(arg, arg)
            return arg  # original domain
        elif ch.is_ip(arg):
            G.add_node(f'{arg}', Scope=CERTAINLY)
            IP_research(arg)
            return ''
        elif ch.is_subnet(arg):
            print("subnet\n")
            break
        elif ch.is_as(arg):
            print("AS\n")
            break
        elif ch.is_flags(arg):
            continue
        else:
            print(arg, 'is not a valid target')
            break


def Researcher(depth=3, original_domain=''):
    """Функция для увеличения количества исследуемых объектов"""
    if depth == 0:
        return
    print(f'\nIn researcher. {depth} iteration.')
    with open('graph.edgelist', 'r') as f:
        while True:
            tmp = f.readline().split(' ')
            if tmp[0] == '':
                break
            if ch.is_domain(tmp[1]) == 1 and G.nodes[f'{tmp[1]}']['Checked'] is False:
                if 'side_domain' in G.nodes[f'{tmp[1]}'] and G.nodes[f'{tmp[1]}']['side_domain'] is True:
                    domain_research(tmp[1], original_domain)
                else:
                    direct_dns_records(tmp[1])
                G.nodes[f'{tmp[1]}']['Checked'] = True
            if ch.is_ip(tmp[1]) == 1 and G.nodes[f'{tmp[1]}']['Checked'] is False:
                IP_research(tmp[1])
                G.nodes[f'{tmp[1]}']['Checked'] = True

    print(G)
    with open('graph.edgelist', 'wb') as f:
        nx.write_edgelist(G, f)
    # nx.write_multiline_adjlist(G, fh)

    Researcher(depth - 1)


def Analyser():
    """Функция для анализа имеющихся объектов"""
    with open('graph.edgelist', 'r') as f:
        while True:
            tmp = f.readline().split(' ')
            if tmp[0] == '':
                break
            if ch.is_domain(tmp[1]) and 'mx_record' in G[f'{tmp[0]}'][f'{tmp[1]}']:
                for nbr, datadict in G.pred[f'{tmp[1]}'].items():
                    if nbr != tmp[0] and 'mx_record' in G[f'{nbr}'][f'{tmp[1]}']:
                        check_and_add_Weight(G, nbr, CERTAINLY)
                        # тут возможно стоит добавить вес и другой вершине (первое условие в ифе),
                        # но не возникнет ли лишнее добавление веса?
            if ch.is_ip(tmp[1]) and 'a_record' in G[f'{tmp[0]}'][f'{tmp[1]}'] and G[f'{tmp[0]}'][f'{tmp[1]}'][
                'a_record'] is False:
                for nbr, datadict in G.pred[f'{tmp[1]}'].items():
                    if 'a_record' in G[f'{nbr}'][f'{tmp[1]}']:
                        check_and_add_Weight(G, nbr, NOT_IN_SCOPE)
                        # тут исключается тот объект у которого а-запись является айпи массовой регистрации


def dfs_possible(u_node, used, dict_for_scope_probably):
    """Функция для поиска объектов, которые маловероятно входят в периметр"""
    used[f'{u_node}'] = True
    for nbr, datadict in G.succ[f'{u_node}'].items():
        if 'Scope' in G.nodes[f'{nbr}'] and 0.5 <= G.nodes[nbr]['Scope'] < 1 and used[nbr] is False:
            dfs_possible(nbr, used, dict_for_scope_probably)
    if 0.5 <= G.nodes[f'{u_node}']['Scope'] < 1:
        G.nodes[f'{u_node}']['color'] = '#FFDB00'
        G.nodes[f'{u_node}']['title'] = 'Probably in scope'
        if ch.is_ip(u_node):
            dict_for_scope_probably[f'{u_node}'] = 'IP'
        if ch.is_domain(u_node):
            dict_for_scope_probably[f'{u_node}'] = 'domain'
        if ch.is_uri(u_node):
            dict_for_scope_probably[f'{u_node}'] = 'URI'


def dfs_for_sure(u_node, used, dict_for_scope_sure, dict_for_scope_probably):
    """Функция для поиска объектов, которые скорее всего входят в периметр"""
    used[f'{u_node}'] = True
    for nbr, datadict in G.succ[f'{u_node}'].items():
        if 'Scope' in G.nodes[f'{nbr}'] and G.nodes[nbr]['Scope'] >= 1 and used[nbr] is False:
            dfs_for_sure(nbr, used, dict_for_scope_sure, dict_for_scope_probably)
        elif 'Scope' in G.nodes[f'{nbr}'] and 0.5 <= G.nodes[nbr]['Scope'] < 1 and used[nbr] is False:
            dfs_possible(nbr, used, dict_for_scope_probably)
    if G.nodes[f'{u_node}']['Scope'] >= 1:
        G.nodes[f'{u_node}']['color'] = '#E8008D'
        G.nodes[f'{u_node}']['title'] = 'In scope for sure'
        if ch.is_ip(u_node):
            dict_for_scope_sure[f'{u_node}'] = 'IP'
        if ch.is_domain(u_node):
            dict_for_scope_sure[f'{u_node}'] = 'domain'
        if ch.is_uri(u_node):
            dict_for_scope_sure[f'{u_node}'] = 'URI'


if __name__ == "__main__":
    api_key = ''
    args = sv.parse_args(sys.argv)

    for i in args:
        if ch.is_flags(i):
            api_key = sv.parse_flags(i, args, api_key)
    if api_key != '':
        sys.exit()

    with open('config', 'r') as f:
        api_key = f.read()
        if api_key == '':
            print('Enter your Netlas API key')
            sys.exit()
        else:
            netlas_connection = netlas.Netlas(api_key=api_key)
    print(f"Program was launched.\nIt can be long enough but it's working.\n")
    t1 = time.time_ns()
    original_domain = Finder(args)
    with open('graph.edgelist', 'wb') as f:
        nx.write_edgelist(G, f)
    print('Researcher was launched.')

    if original_domain == '':
        Researcher(DEPTH_OF_SEARCH)
    else:
        Researcher(DEPTH_OF_SEARCH, original_domain)

    Analyser()

    t2 = time.time_ns()

    print(f"\nВычисление заняло {(t2 - t1) / 1e9:0.3f} секунд.\n")

    # For graphical output of graph
    for n in G.nodes():
        G.nodes[n]['title'] = 'Not in scope'

    with open('result.txt', 'w') as f:
        used = dict.fromkeys([n for n in G], False)
        scope_for_sure = {}
        scope_probably = {}
        print('In scope for sure:', file=f)
        print('In scope for sure:')

        dfs_for_sure(original_domain, used, scope_for_sure, scope_probably)
        
        print('\nIPs:')
        print('\nIPs:', file=f)
        for key, value in scope_for_sure.items():
            if value == 'IP':
                print(key, file=f)
                print(key)
        print('\nDomains:')
        print('\nDomains:', file=f)
        for key, value in scope_for_sure.items():
            if value == 'domain':
                print(key, file=f)
                print(key)
        print('\nURIs:')
        print('\nURIs:', file=f)
        for key, value in scope_for_sure.items():
            if value == 'URI':
                print(key, file=f)
                print(key)

        print('\nProbably in scope:', file=f)
        print('\nProbably in scope:')

        print('\nIPs:')
        print('\nIPs:', file=f)
        for key, value in scope_probably.items():
            if value == 'IP':
                print(key, file=f)
                print(key)
        print('\nDomains:')
        print('\nDomains:', file=f)
        for key, value in scope_probably.items():
            if value == 'domain':
                print(key, file=f)
                print(key)
        print('\nURIs:')
        print('\nURIs:', file=f)
        for key, value in scope_probably.items():
            if value == 'URI':
                print(key, file=f)
                print(key)
    print()

    # Graphical output of the graph
    # net = Network(height='100%', width='65%', bgcolor='#222222',
    #               font_color='white', notebook=True, directed=True)
    # net.from_nx(G, show_edge_weights=False)
    # net.show_buttons(filter_=['physics'])
    # net.show('nx.html')

# возможные взаимосвязи:
# favicon.hash_sha256
# Сертификаты
# Веса взаимосвязей
# 1. Поддомены    - 1.0 V
# 2. ns-записи    - 0.1 V
# 3. mx-записи    - 1.0 V
# 4. g-tag        - 1.0 V
# 5. favicon      - 0.6
# 6. сертификат   - 1.0
# 7. cross-link   - 0.7
# 8. side-domains - 0.3 слишком сложно реализовать
# 9. a-записи     - 0.5 V
# 10.ptr-записи   - 0.1
# 11.a+ptr        - 1.0
# 12.сервисы      - 1.0 V
# 13.cross-link + side domain - 1.0 V


# Дальнейшее развитие:
# 1) Можно поискать такие вещи как
# a.com     a.name
#      \  /
#     b.com

# 2) acribia... редиректится на какой-то mail...
#  netlas делает то же самое, но на другой mail
#  и у этих мэйлов общая а-запись

# 3) Можно сохранять редиректы (код 302, 301) и что-то с ними делать
# 4) Добавить проверку доменов такого вида acribia.spb.ru
# 5) Возможная взаимосвязь для domain.*  :общее наименование организации, общий домен такого-то уровня
# 6) из URI можно вытащить айпи/домен
# 7) в баннерах можно искать email
# 8) добавить другие метрики, аналитики помимо g-tag и может стоит их добавлять в граф
# 9) редиректы 301 и 302 возвращают URL там можно поискать что-то
# 10) пользоваться не только netlas
# 11) общий DNS сервер у двух доменов, разные домены ведут на один айпи, разные домены, но у одного провайдера
# 12) в тхт-записи могут храниться ключи верификации. С ними можно что-то поделать
# 13) для айпи искать ещё подсети, автономные системы, whois записи. Использовать  ipio.info
# 14) добавить обработку подсетей (ip входящие в подсеть могут быть связаны с другими ip; посмотреть сети влево-вправо)
# 15) Добавить обработку автономных систем (то же что и в подсетях + на кого зареган, что тоже может быть взаимосвязью)
