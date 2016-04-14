#!/usr/bin/env python

import time
from zapv2 import ZAPv2
import os
import subprocess
import urllib2
from requests import exceptions
import socket
import json


class OWASP_ZAP:
    """
    Document
    """
    def __init__(self, zap_command_path=None):
        self.zap_command_path = zap_command_path if zap_command_path else os.environ['ZAP_COMMAND_PATH']
        self.http_proxies = dict()
        self.proxy_host = os.uname()[1]
        self.proxy_port = None
        self.get_proxy_port()
        self.set_http_proxy()
        self.zap_process = None
        self.zap = None
        self.lock_file = os.getcwd() + '/zap.lock'

    def run_proxy(self):
        self.zap_init()
        self.zap = ZAPv2(proxies=self.http_proxies)
        with open(self.lock_file, 'w') as f:
            f.write('Running')
        print os.getcwd() + '/zap_env.properties'
        with open(os.getcwd() + '/zap_env.properties', 'w') as f:
            f.write('NETWORK_PROXY_HTTP=%s\n' % self.proxy_host)
            f.write('NETWORK_PROXY_PORT=%s\n' % self.proxy_port)

        while self.get_lock_file_status() == 'Running':
            print 'Proxy is Running in %s:%s' % (self.proxy_host, self.proxy_port )
            time.sleep(1)
        self.get_result()
        self.zap_process.kill()

    def get_lock_file_status(self):
        with open(self.lock_file, 'r') as f:
            return f.read()

    def proxy_check(self):
        try:
            proxy = urllib2.ProxyHandler(self.http_proxies)
            opener = urllib2.build_opener(proxy)
            urllib2.install_opener(opener)
            r = urllib2.urlopen('https://support.gooddata.com/hc/en-us')
            if r.getcode()== 200:
                return True
            else:
                return False
        except:
            return False

    def get_proxy_port(self):
        for port in range(40050, 40100):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if sock.connect_ex(('127.0.0.1', port)) != 0:
                self.proxy_port = str(port)
                break

    def set_http_proxy(self):
        self.http_proxies = {
            'http': 'http://%s:%s' % (self.proxy_host, self.proxy_port),
            'https': 'http://%s:%s' % (self.proxy_host, self.proxy_port)
        }

    def zap_init(self):
        print 'Starting ZAP ...'
        zap_command = [self.zap_command_path, '-daemon',
                       '-host', self.proxy_host, '-port', self.proxy_port,
                       '-config', 'api.disablekey=true']
        self.zap_process = subprocess.Popen(zap_command,
                                            stdout=open(os.devnull, 'w'))
        # Wait for zap proxy started
        pooling = 1
        while not self.proxy_check():
            print 'Try to start zap after %s s' % pooling
            pooling += 2
            time.sleep(2)
            if pooling > 300:
                break
        print 'ZAP is now listening on %s:%s' % (self.proxy_host,
                                                 self.proxy_port)

    def get_result(self):
        print 'Hosts: ' + ', '.join(self.zap.core.hosts)
        with open('result.json', 'a') as f:
            for result in self.zap.core.alerts():
                f.write(json.dumps(result) + '\n')


z = OWASP_ZAP()
z.run_proxy()
