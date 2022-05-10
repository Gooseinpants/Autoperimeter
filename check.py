"""
В этом модуле хранятся функции для проверки входных параметров для программы.
"""
import re


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
    else:
        return 0


def is_uri(s):
    match = re.fullmatch(
        r'(http|https|smtp|smtps|imap|imaps|ftp|telnet|smtpstarttls|elasticsearch|memcached|mongodb|mssql|mysql|oracle|pop3|postgres|redis|smb|ssh|t3):(?:\/\/(?:((?:[a-z0-9-._~!$&\'()*+,;=:]|%[0-9A-F]{2})*)@)?((?:[a-z0-9-._~!$&\'()*+,;=]|%[0-9A-F]{2})*)(?::(\d*))?(\/(?:[a-z0-9-._~!$&\'()*+,;=:@\/]|%[0-9A-F]{2})*)?|(\/?(?:[a-z0-9-._~!$&\'()*+,;=:@]|%[0-9A-F]{2})+(?:[a-z0-9-._~!$&\'()*+,;=:@\/]|%[0-9A-F]{2})*)?)(?:\?((?:[a-z0-9-._~!$&\'()*+,;=:\/?@]|%[0-9A-F]{2})*))?(?:#((?:[a-z0-9-._~!$&\'()*+,;=:\/?@]|%[0-9A-F]{2})*))?$\/?', s)
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
