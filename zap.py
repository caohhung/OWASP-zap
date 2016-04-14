#!/usr/bin/env python

import time
from zapv2 import ZAPv2
import os
import subprocess
import requests
from requests import exceptions
import socket
import json


def proxy_check(target=None, proxies=None):
    try:
        r = requests.get(url=target, proxies=proxies, timeout=3)
        if r.status_code == 200:
            return True
        else:
            return False
    except (exceptions.MissingSchema, exceptions.ConnectTimeout,
            exceptions.ReadTimeout, exceptions.ConnectionError):
        return False


# Random port from 40050 to 40100 and make sure that port is closing
def get_proxy_port():
    for port in range(40050, 40100):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if sock.connect_ex(('127.0.0.1', port)) != 0:
            return port

HTTP_PROXY_PORT = str(get_proxy_port())
HTTP_PROXY = 'http://127.0.0.1:' + HTTP_PROXY_PORT
proxies = {'http': HTTP_PROXY, 'https': HTTP_PROXY}
command_path = os.environ['ZAP_COMMAND_PATH']
target = os.environ['TARGET_HOST']

# Temporary disable api_key api.disablekey=true
zap_command = [command_path, '-daemon',
               '-host', 'localhost', '-port', HTTP_PROXY_PORT,
               '-config', 'api.disablekey=true']

zap_process = subprocess.Popen(zap_command, stdout=open(os.devnull,'w'))

# Check zap proxy before starting zap scan
while not proxy_check(target=target, proxies=proxies):
    print 'Starting ZAP ...'
    time.sleep(1)


# ZAP starts accessing the target.
zap = ZAPv2(proxies=proxies)
print 'Accessing target %s' % target
zap.urlopen(target)
time.sleep(1)

# Progress of spider
print 'Spidering target %s' % target
zap.spider.scan(target)
time.sleep(1)
print 'Status %s' % zap.spider.status()
while int(zap.spider.status() < 100):
    print 'Spider progress {0} %: '.format(zap.spider.status())
    time.sleep(2)
print 'Spider completed'

# Give the passive scanner a chance to finish
time.sleep(5)

# The active scanning starts
print 'Scanning target %s' % target
zap.ascan.scan(target)
while int(zap.ascan.status() < 100):
   print 'Scan progress {0} %: '.format(zap.ascan.status())
   time.sleep(10)

print 'Scan completed'

# Report the results
print 'Hosts: ' + ', '.join(zap.core.hosts)
with open('result.json', 'w') as f:
    json.dump(zap.core.alerts(), f)

# Do NOT use zap.core.shutdown(), It'll kill all zap proxy process.
zap_process.kill()

