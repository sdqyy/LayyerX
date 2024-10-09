import ssl
import sys
import base64
import argparse
import logging
import gzip
import time
import io
import gc
import sys
from typing import Optional, List, Union


import httpx
import traceback
import dns.edns
import dns.name
import dns.query
import dns.exception
import dns.message
from netaddr import IPAddress, AddrFormatError


import requests
import pandas as pd
from requests.packages import urllib3
urllib3.disable_warnings()
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
LOG_FILE = "doh_client.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("client")

def gen_doh_header(hostname):
    header = {
        "content-type": "application/dns-message",
        "accept": "application/dns-message",
        "user-agent": "Chrome",
        "accept-encoding": "identity"
    }
    return header

def gen_dns_query(qname: Union[dns.name.Name, str] = "www.google.com", rtype="A", rclass="IN"):
    """
    Generate a DNS request message.

    Args:
        qname (str): The domain name to query.
        rtype (str): The type of the query.

    Returns:
        dns.message.Message: The DNS request message.
    """
    return dns.message.make_query(qname=qname, rdtype=rtype, rdclass=rclass)


def check_host_type(input_str):
    try:
        ip = IPAddress(input_str)
    except AddrFormatError:
        return -1
    else:
        return ip.version

def send_doh_queries(hostname, port, path, query_name, query_type, query_class, is_post, verify_mode, timeout=3):
    doh_header = gen_doh_header("")
    server = ''
    with httpx.Client(http1=True, http2=True, verify=verify_mode, timeout=timeout, headers=doh_header) as client:
        host_type = check_host_type(hostname)
        if host_type == 6:
            doh_url = "https://[{}]:{}{}".format(hostname, port, path)
        else:
            doh_url = "https://{}:{}{}".format(hostname, port, path)
        # print(doh_url)
        doh_query = gen_dns_query(query_name, rtype=query_type, rclass=query_class)
        doh_body = doh_query.to_wire()
        # print('*'*20)
        # print(doh_query)
        try:
            if is_post:
                with client.stream(
                            "post",
                            doh_url,
                            content=doh_body,
                        ) as response:

                            response.read()

            else:
                dns_base64_format = (
                    base64.urlsafe_b64encode(doh_body).rstrip(b"=").decode()
                )
                response = client.get(
                    doh_url,
                    headers=doh_header,
                    params={"dns": dns_base64_format},
                    timeout=timeout,
                )

        except httpx.ProtocolError as exc:
            traceback.print_exc()
        except httpx.InvalidURL as exc:
            print(exc)
        except httpx.ConnectTimeout as exc:
            print(f"{hostname} timeout - {exc}")
        except httpx.ConnectError as exc:
            print(f"{hostname} ConnectError - {exc}")
        except httpx.ReadTimeout as exc:
            print(f"{hostname} timeout - {exc}")
        except ssl.SSLError as exc:
            print(f"SSL Exception - {exc}")
        else:
            pass
            print(f"IP: {hostname} http_Server: {response.headers.get('Server')}")
            header = dict(response.headers)
            content = response.content
            print(header)
            server = response.headers.get('Server')
            fun2(content)
            return header, content
    return '',''

def fun2(data):
    from dnslib import DNSRecord
    # 你提供的数据
    # data =  b'T\xc6\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01,\x00\x04\xac\xd9\xa0D'
    # 解析DNS记录
    record = DNSRecord.parse(data)
    # 打印解析后的结果
    print(record)
port = 8443
# target = 'ns0.fdn.fr'
# target = '47.90.203.57'
target = '8.217.254.174'
def fun3_header_get():
    # 获取字典格式的doh响应指纹
    fp_header,_ =  send_doh_queries(
        hostname = target,
        port = port,
        query_name='google.com',
        query_type='A',
        query_class='IN',
        path='/dns-query',
        is_post=False,
        verify_mode=False
    )
    print(fp_header)


if __name__ == "__main__":
    # main()
    # fun2()
    fun3_header_get()
