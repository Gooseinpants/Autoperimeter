import netlas
import re
import sys


def parse_args(argv):
    if argv[1][0] != '-':
        args = [argv[1]]
        print("arg = ",args[0])                
    elif len(argv) == 2:
        args = [argv[1]]
        print("flags = ",args[0])  
    else:
        args = [argv[1], argv[2]]
        print("flags = ",args[0])
        print("arg = ",args[1])
    return args

def print_help():
    print("Usage: python3 main.py [flags] [target] \n")
    print("Target specification: Domain names or IP-adresses\n")
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
    match = re.fullmatch(r'((http|https)\:\/\/){1}[a-zA-Z0-9\.\/\?\:@\-_=#]+\.([a-zA-Z]){2,6}([a-zA-Z0-9\.\&\/\?\:@\-_=#])*', s)
    if match:
        return 1
    else:
        return 0    

def is_subnet(s):
    match = re.fullmatch(r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([1-3]?\d)', s)
    if match:
        return 1
    else:
        match = re.fullmatch(r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)-((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', s)
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
    if (s[0] == '-'):
        return 1
    else:
        return 0

def domain_research(domain_name):
    sQuery = "domain:" + domain_name
    query_res = netlas_connection.query(query=sQuery, datatype='domain')
    print(query_res)

def IP_research():
    print("tbd")

def enter_api_key():
    for i in args:
        if (is_flags(i) == 0):
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

if (api_key != ''):
    sys.exit()

f = open('config')
api_key = f.read()
if (api_key == ''):
    print('Enter your Netlas API key')
    sys.exit()
else:    
    netlas_connection = netlas.Netlas(api_key=api_key)


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
    
    


