#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

MAX_BLOCK = 100000


def split_email(email):
    at_idx = email.find('@')
    if at_idx == -1:
        return email, '', '', ''
    username = email[:at_idx]
    full_domain = email[at_idx+1:]
    last_dot_idx = full_domain.rfind('.')
    if last_dot_idx == -1:
        return username, full_domain, full_domain, ''
    return username, full_domain, full_domain[:last_dot_idx], full_domain[last_dot_idx+1:]


def scan_file(file_name, source_id):
    data = []
    source_id = str(source_id)
    with open(file_name, 'r', errors='ignore') as fd:
        try:
            for line in fd:
                line_s = line.split(':', 1)
                if len(line_s) < 2:
                    continue
                email = line_s[0].replace('"', '""').replace('\0', '')
                username, full_domain, domain_no_tld, tld = split_email(email)
                csv_line = ','.join(['"%s"' % x for x in (email, username, full_domain, domain_no_tld, tld, line_s[1].rstrip('\n').replace('"', '""').replace('\0', ''), source_id)])
                data.append('%s\n' % csv_line)
                if len(data) >= MAX_BLOCK:
                    yield data
                    data = []
        except Exception as e:
            sys.stderr.write('error: %s\n' % e)
            sys.stderr.flush()
    if data:
        yield data
        data = []


def scan_dir(dirname, csv, start=0):
    source_name = os.path.basename(dirname)
    total = start

    source_id = 2

    for file_name in os.listdir(dirname):
        print('source %s file %s' % (source_name, file_name))
        sys.stdout.flush()
        for block in scan_file(os.path.join(dirname, file_name), source_id):
            total += len(block)
            csv.writelines(block)
        print('passwords so far: %d' % total)
        sys.stdout.flush()
    print('total passwords: %d' % total)
    return total


if __name__ == '__main__':
    csv = open('pwd.csv', 'a')
    total = 0
    for directory in sys.argv[1:]:
        total = scan_dir(directory, csv, start=total)

