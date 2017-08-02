#!/usr/bin/env python

import re, os, sys, logging, SocketServer, requests

__version__ = '0.0.1a'

session = requests.Session()
session.headers.update({
    'X-APIAccessKey': os.environ['DOFLER_ACCESS'],
    'X-APISecretKey': os.environ['DOFLER_SECRET'],
    'User-Agent': 'NMSyslogHandler/{} Python/{}'.format(
        __version__, 
        '.'.join([str(i) for i in sys.version_info][0:3])
    )
})


rpvs = re.compile(r'pvs: (\d+\.\d+\.\d+\.\d+):(\d+)\|(\d+\.\d+\.\d+\.\d+):(\d+)\|(\d+)\|(\d+)\|([^\|]+)\|([^\|]+)\|([^\|]+)\|([^\n]+)')
host_rex = {
    7024: re.compile(r'^([^ ]+)'),
    7041: re.compile(r'Host: ([^\;]+)'),
    7033: re.compile(r'New domain: ([^ ]+)'),
    7039: re.compile(r'Server : ([^ ]+)'),
    7026: re.compile(r'The remote host ([^ ]+) resolves to')
}

risk_thresh = {
    'critical': ['CRITICAL'],
    'high':     ['CRITICAL', 'HIGH'],
    'medium':   ['CRITICAL', 'HIGH', 'MEDIUM'],
    'low':      ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
}


def postdata(etype, **kwargs):
    kwargs['type'] = 'nessus_monitor'
    kwargs['source'] = os.environ['HOSTNAME']
    session.post('{}/events/{}'.format(os.environ['DOFLER_ADDRESS'], etype), data=kwargs)


class PVSHandler(SocketServer.BaseRequestHandler):
    def post_address(self, event):
        if event['plugin_id'] in host_rex:
            postdata('dns', address=host_rex[event['plugin_id']].findall(event['text_2'])[0])

    def post_mobile(self, event):
        if event['plugin_id'] == 7178:
            postdata('mobile', device=event['text_2'])          

    def post_user_agent(self, event):
        if event['plugin_id'] == 7023:
            postdata('user_agent', device=event['text_2'])

    def post_vuln(self, event):
        if event['risk'] in risk_thresh[event['risk']]:
            postdata('vuln', **event)

    def gen_event_pkt(self, line):
        p = rpvs.findall(data)[0]
        return {
            'src_ip': p[0],
            'src_port': int(p[1]),
            'dst_ip': p[2],
            'dst_port': int(p[3]),
            'protocol': int(p[4]),
            'plugin_id': int(p[5]),
            'plugin_name': p[6],
            'text_1': p[7],
            'text_2': p[8],
            'risk': p[9]
        }

    def handle(self):
        host = None 
        mobile = None 
        ua = None 
        event = self.gen_event_pkt(bytes.decode(self.request[0].strip()))
        self.get_address(event)
        self.get_mobile(event)
        self.get_user_agent(event)


server = SocketServer.UDPServer(('127.0.0.1', 9514), PVSHandler)
server.serve_forever()