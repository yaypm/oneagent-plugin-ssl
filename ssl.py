import requests
import json
import logging
import socket
import ssl
import datetime
from ruxit.api.base_plugin import BasePlugin
from ruxit.api.snapshot import pgi_name


class SSLPlugin(BasePlugin):
    def query(self, **kwargs):

        pgi = self.find_single_process_group(pgi_name('Windows System'))
        pgi_id = pgi.group_instance_id

        hostname = "dynatrace.com"

        ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'

        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=hostname,
        )
    
        # 3 second timeout because Lambda has runtime limitations
        conn.settimeout(3.0)

        conn.connect((hostname, 443))
        ssl_info = conn.getpeercert()
        
        # parse the string from the certificate into a Python datetime object
        ssl_expiry_datetime = datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)

        raw_diff = ssl_expiry_datetime - datetime.datetime.utcnow()

        result_seconds = raw_diff.total_seconds()

        result = result_seconds / 60 / 60 / 24

        self.results_builder.absolute(key='days_remaining', value=result, entity_id=pgi_id)
