#!/usr/bin/env python

import time
from zapv2 import ZAPv2
import os
import subprocess
import requests
from requests import exceptions
import socket
import json


class OWASP_ZAP:
    """
    Document
    """
    def __init__(self, target_host=None, zap_command_path=None):
        self.target_host = target_host if target_host else os.environ['TARGET_HOST']
        self.zap_command_path = zap_command_path if zap_command_path else os.environ['ZAP_COMMAND_PATH']
        self.http_proxies = dict()
        self.proxy_host = '127.0.0.1'
        self.proxy_port = None
        self.get_proxy_port()
        self.set_http_proxy()
        self.zap_process = None
        self.zap = None

    def run(self):
        self.zap_init()
        try:
            self.zap = ZAPv2(proxies=self.http_proxies)
            print 'Accessing target %s' % self.target_host
            time.sleep(1)
            self.zap.urlopen(self.target_host)
            time.sleep(1)
            self.run_spider()
            time.sleep(5)
            self.run_ascan()
            self.get_result()
        except exceptions:
            pass
        # Do NOT use zap.core.shutdown(), It'll kill all zap proxy process.
        self.zap_process.kill()

    def proxy_check(self):
        try:
            r = requests.get(url=self.target_host,
                             proxies=self.http_proxies, timeout=3)
            if r.status_code == 200:
                return True
            else:
                return False
        except(exceptions.MissingSchema, exceptions.ConnectTimeout,
               exceptions.ReadTimeout, exceptions.ConnectionError):
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
                       '-host', 'localhost', '-port', self.proxy_port,
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

    def run_spider(self):
        print 'Spidering target %s' % self.target_host
        self.zap.spider.scan(self.target_host)
        time.sleep(1)
        print 'Status %s' % self.zap.spider.status()
        while int(self.zap.spider.status() < 100):
            print 'Spider progress {0} %: '.format(self.zap.spider.status())
            time.sleep(2)
        print 'Spider completed'

    def run_ascan(self):
        print 'Scanning target %s' % self.target_host
        self.zap.ascan.scan(self.target_host)
        while int(self.zap.ascan.status() < 100):
            print 'Scan progress {0} %: '.format(self.zap.ascan.status())
            time.sleep(10)
        print 'Scan completed'

    def get_result(self):
        print 'Hosts: ' + ', '.join(self.zap.core.hosts)
        with open('result.json', 'a') as f:
            for result in self.zap.core.alerts():
                f.write(json.dumps(result) + '\n')

z = OWASP_ZAP()
z.run()
