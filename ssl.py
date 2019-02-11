import datetime
import fileinput
import logging
import os
import socket
import ssl
import time
import requests
import json
import logging
from ruxit.api.base_plugin import BasePlugin
from ruxit.api.snapshot import pgi_name


class SslExpiryPlugin(BasePlugin):
    def ssl_expiry_datetime(self,hostname: str) -> datetime.datetime:
        ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'

        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname="dynatrace.com",
        )
        # 3 second timeout because Lambda has runtime limitations
        conn.settimeout(3.0)

        conn.connect(("dynatrace.com", 443))
        ssl_info = conn.getpeercert()
        # parse the string from the certificate into a Python datetime object
        return datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)


    def ssl_valid_time_remaining(hostname: str) -> datetime.timedelta:
        """Get the number of days left in a cert's lifetime."""
        expires = ssl_expiry_datetime(hostname)

        return expires - datetime.datetime.utcnow()    
    
    def query(self, **kwargs):

        pgi = self.find_single_process_group(pgi_name('Windows System'))
        pgi_id = pgi.group_instance_id

        daysRemaining = ssl_valid_time_remaining("dynatrace.com")

        self.results_builder.relative(key='daysRemaining', value=daysRemaining, entity_id=pgi_id)       