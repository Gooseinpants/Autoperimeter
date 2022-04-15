"""Этот файл содержит служебные функции, необходимые для корректной работы и запуска программы"""


def print_help():
    print("Usage: python3 main.py [flags] [target] \n")
    print("Target specification: Domain names or IP-addresses\n")
    print("Flags:")
    print("    -h: Print this page")
    print("    -c: Enter Netlas API key: main.py -c \'API key\'")


def parse_args(argv):
    import sys
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


def enter_api_key(args):
    import check as ch
    for i in args:
        if ch.is_flags(i) == 0:
            api_key = i
            with open('config', 'w') as f:
                f.write(api_key)
            return api_key


def parse_flags(flags, args, api_key):
    for i in flags:
        if i == 'h':
            print_help()
            return ''
        elif i == 'c':
            return enter_api_key(args)
