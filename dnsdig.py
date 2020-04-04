#!/usr/bin/python3

# dnsdig.py by zizzu 2020
# extract dns responses bytes from recvfrom syscall buffer via sysdig
# parse the output via python and translate bytes to human readable form via dnslib
# remove the inner if inside the for loop to show all the responses instead of a summary

import shlex
import dnslib
import base64
import subprocess

server="8.8.8.8" # your dns server use: and  (fd.sip=... or fd.sip=...) for multiple dns addresses
command=f'sysdig -b -s 1000 -p"%evt.buffer" evt.type=recvfrom and fd.l4proto=udp and fd.sip={server} and fd.sport=53 and evt.dir=\<'

def run_command(cmd):
    mem = []
    process = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE)
    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            b64_string = output.strip().decode('ascii')
            b64_string += '=' * (-len(b64_string) % 4)
            hex_string = base64.b64decode(b64_string)
            try:
                d = dnslib.DNSRecord.parse(hex_string)
                for rr in d.rr:
                    if rr not in mem:
                        mem.append(rr)
                        print(rr)
            except Exception as e:
                print(str(e))
    rc = process.poll()
    return rc

run_command(command)
