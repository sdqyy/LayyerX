import json
import time
import random
from urllib.parse import urlparse
import re
import ssl
import socket
from statistics import mode
import pickle
import configargparse
from simphile import jaccard_similarity
import helper

import requests
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL'
from socket import AF_INET, AF_INET6, SOCK_STREAM
import doh_query

def arg_parse():
    """ Argument parser. """

    parser = configargparse.ArgParser(description='Web Server fingerprinting tool.')
    parser.add('-t', dest="target", type=str,
               help="Please input the target address that you want to fingerprint.")
    parser.add('-p', dest="port", type=int,
               help="Please input the target port that you want to fingerprint.")
    args = parser.parse_args()

    return args

class Servers():
    """ holds the server_list also, it holds reactions of these servers """
    def __init__(self):
        self.server_list = ["cloudfront", "cloudflare", "fastly", "akamai", "nginx",
                            "varnish", "haproxy", "apache", "caddy", "envoy", "ats",
                            "squid", "tomcat", "lighttpd"]
        self.server_dict = {"cloudfront": 0, "cloudflare": 1, "fastly": 2, "akamai": 3,
                            "nginx": 4, "varnish": 5, "haproxy": 6, "apache": 7, "caddy": 8,
                            "envoy": 9, "ats": 10, "squid": 11, "tomcat": 12, "lighttpd":13}
        self.server_reaction_list = [0]*len(self.server_list)

class RedirectionDepthExceeded(Exception):
    "Raised when the redirections are higher than 15."

def redirect_check(response, server_n, path):
    """ checks redirects """

    try:
        lines = response.split(b'\r\n')
        status_line = lines[0]
        headers = lines[1:]
        status_code = int(status_line.split(b' ')[1])

        if status_code == 100:
            response = response.split(b"\r\n\r\n", 1)[1]
            lines = response.split(b'\r\n')
            status_line = lines[0]
            headers = lines[1:]
            status_code = int(status_line.split(b' ')[1])

        if status_code in (301, 302, 303, 307, 308):
            for header in headers:
                if header.lower().startswith(b'location:'):

                    url = header.split(b':', 1)[1].strip()
                    parse_results = urlparse(url)
                    server_n = parse_results.hostname
                    path = parse_results.path

                    return True, server_n, path
            return False, server_n, path
        return False, server_n, path

    except Exception as exception:
        print("here1 up", exception)
        return False, server_n, path

def send_request(target, port, path, request, from_redirection, depth=0):
    """ sends a request and return the response """

    try:
        if isinstance(path, str):
            path = path.encode()

        if depth > 15:
            raise RedirectionDepthExceeded
        
        address_family = AF_INET6 if ':' in target else AF_INET
        _socket = socket.socket(address_family, socket.SOCK_STREAM)

        original_request = request

        # If path == "/" no need to prepend something.
        if path in [b"/", b""]:
            pass
        else:
            request_line = request[:request.find(b"\r\n")]
            rest = request[request.find(b"\r\n"):]

            splitted_request_line = request_line.split(b" ")

            curr_path = splitted_request_line[1]

            if from_redirection is True:
                splitted_request_line[1] = path
            elif curr_path == b"/" and path[-1] == b"/":
                splitted_request_line[1] = path
            elif curr_path == b"/":
                splitted_request_line[1] = path
            else:
                new_path = path + curr_path
                splitted_request_line[1] = new_path

            new_request_line = b" ".join(splitted_request_line)
            request = new_request_line + rest

        if isinstance(target, str):
            pass
        else:
            target = target.decode()
        request = re.sub(b'hostname', bytes(target, 'utf-8'), request)

        # Adds User-Agent.
        user_agent_string = b'User-Agent: Wget/1.21.4'
        user_agent_request_line = request.split(b"\r\n")[:1]
        user_agent_rest = request.split(b"\r\n")[1:]
        user_agent_request_line.append(user_agent_string)
        user_agent_request_line.extend(user_agent_rest)
        new_req = b"\r\n".join(user_agent_request_line)
        request = new_req

        ssl._create_default_https_context = ssl._create_unverified_context
        ssl.match_hostname = lambda cert, hostname: True
        context = ssl.create_default_context()
        # context.options |= ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        context.set_ciphers('HIGH:!aNULL:!eNULL:!MD5')

        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with context.wrap_socket(_socket, server_hostname=target) as s:
            
            s.settimeout(10)
            s.connect((target, port))
            s.sendall(request)

            response = b''
            while True:
                data = s.recv(2048)
                if not data:
                    break
                response += data

            s.close()

            if len(response) == 0:
                return response

            redirect, server_n_r, path_r = redirect_check(response, target, path)

            if redirect is False:
                return response
            response = send_request(server_n_r, port, path_r, original_request,
                                        True, depth=depth+1)
            return response
    except RedirectionDepthExceeded:
        print("Redirection depth exceeded")
        return "exception"
    except socket.timeout:
        return "too_long"
    except Exception as exception:
        print(exception)
        return "exception"


def pick_request(server_reaction_list):
    """
        Find a request that matches with server_reaction
        list's requirements, if you cannot find return False
    """

    with open("behavior-add_lighttpd.json", "rb") as reader:
        hashmap  = json.load(reader)
        if str(server_reaction_list) in hashmap:
            return hashmap[str(server_reaction_list)]
        return False

def read_response(response, original_responses, server_n):
    # print(f'response: {response}')
    """ Reads the response and matches to a server with highest similarity score """

    max_sim_server = "unknown"
    max_sim_score = float("-inf")

    for server_name in original_responses:
        comp = original_responses[server_name].encode()

        comp_code = comp[comp.find(b'HTTP'):].split(b'\r\n')[0].split(b" ")[1].lower()
        response_code = response.split(b'\r\n')[0].split(b" ")[1].lower()
        response_code_sim = jaccard_similarity(comp_code, response_code)

        response = response.lower()
        comp = comp.lower()
        if server_name == 'caddy':
            pass
        jaccard_request_sim = jaccard_similarity(comp, response)

        response_body_sim = 0
        curr_body_text = comp.split(b'\r\n\r\n')[1].lower() if b'\r\n\r\n' in comp else ''
        response_body_text = response.split(b'\r\n\r\n')[1].lower()

        if len(response_body_text) <= 1 and len(curr_body_text) == 0:
            response_body_sim = 1
        elif len(response_body_text) != 0 and len(curr_body_text) != 0:
            response_body_sim = jaccard_similarity(curr_body_text, response_body_text)

        sim_score = response_code_sim + jaccard_request_sim + response_body_sim

        if server_name == "fastly":
            if b"x-served-by:".lower() in response:
                sim_score += 1
            else:
                sim_score -= 1
        if server_name == "cloudfront":
            if b"x-amz-cf-pop:".lower() in response or b"x-amz-cf-id".lower() in response:
                sim_score += 1
            else:
                sim_score -= 1
        if server_name == "cloudflare":
            if b"CF-Cache-Status:".lower() in response or b"CF-RAY".lower() in response:
                sim_score += 1
            else:
                sim_score -= 1
        if server_name == "caddy":
            if len(response) > 150:
                sim_score -= 1.5
            if b"Caddy" not in response:
                sim_score -= 0.45              
        if server_name == "envoy":
            if b"envoy".lower() not in response:
                sim_score -= 1

        if sim_score >= max_sim_score and sim_score >= 1.6222222222222224:
            max_sim_score = sim_score
            max_sim_server = server_name
    print(f'max-sim-server: {max_sim_server} max-sim-score: {max_sim_score}')
    return max_sim_server


def send_request_and_fingerprint(resp_tuple, server_n, server_p, path):
    """ send a request and fingerprint the response """

    _, resp = resp_tuple[0]
    picked_r = resp['after_mut'].encode()

    time.sleep(random.randint(0, 10)/10)

    response = send_request(server_n, server_p, path, picked_r, False)

    if response in ["too_long", "exception"]:
        return response

    # last layer fingerprinting is done
    if response in [b"HTTP/1.1 200", b"HTTP/1.0 200"]:
        return "200"

    if len(response) == 0:
        return "empty"

    try:
        predicted_server = read_response(response, resp['responses'], server_n)

        return predicted_server
    except Exception as exception:
        print(exception)
        return "exception"


def find_ordering_of_unordered_servers(server_n, server_p, path, unordered_list,
                                       found_server_list_indexed, ordered):
    """ finds the ordering for a given unordered list """

    ## Attention: Phase 3 is not complete. # TODO: complete the Phase 3.

    server_dict = {"cloudfront": 0, "cloudflare": 1, "fastly": 2, "akamai": 3,
                "nginx": 4, "varnish": 5, "haproxy": 6, "apache": 7, "caddy": 8,
                "envoy": 9, "ats": 10, "squid": 11, "tomcat": 12, "lighttpd":13}

    # Mark the ordered servers
    found_server_indexes = [idx for idx, value in
                              enumerate(found_server_list_indexed) if value == 1]
    all_predicts = []
    error_server_indexes = []

    # Mark the unordered servers
    for unordered_server in unordered_list:
        error_server_indexes.append(server_dict[unordered_server])

    # Iterate over the requests in behavior repository. 
    # with open("behavior_repository.out", "rb") as reader:
    #     hashmap  = pickle.load(reader)
    with open("behavior-add_lighttpd.json", "rb") as reader:
        hashmap  = json.load(reader)

        for i in hashmap:
            lst = json.loads(i)
            if 2 not in lst and 3 not in lst and 4 not in lst and 5 not in lst:
                # If all the servers that we found in order forwards the request.
                if all(lst[ind] == 1 for ind in found_server_indexes):
                    # If all the servers that are unordered return an error response.
                    if all(lst[error_ind] == 0 for error_ind in error_server_indexes):
                        # Get request.
                        picked_response = pick_request(lst)

                        if picked_response:
                            predicted_server = send_request_and_fingerprint(picked_response,
                                                                            server_n, server_p, path)

                            non_server_list = ["200", "too_long", "exception", "empty"]

                            if predicted_server not in non_server_list:
                                # qyy version: extend ——> append
                                all_predicts.append(predicted_server)

    try:
        # If it finds the server ordering.
        if len(all_predicts) > 0:
            ordered = True

            # Find the most common response.
            next_layer = mode(all_predicts)
            # Put the next layer server as a following server.
            layered_predicted_list = [next_layer]
            # Put the rest of the servers behind it.
            layered_predicted_list.extend([elem for elem in unordered_list if elem != next_layer])
            return ("predict", layered_predicted_list, ordered)

        # If it cannot find the server ordering.
        if len(unordered_list) > 0:
            return ("predict", unordered_list, ordered)
        return False

    except Exception:
        next_layer = predicted_server
        layered_predicted_list = [next_layer]
        layered_predicted_list.extend([elem for elem in unordered_list if elem != next_layer])
        return ("predict", layered_predicted_list, ordered)

def find_layer(target_reaction, server_n, server_p, path, found_server_list_indexed):
    """ for a given target reaction, picks a request and fingerprints the current layer """

    # Phase 1 starts
    # Searches for a request for a given target reaction in the behavior repository.
    picked_response = pick_request(target_reaction)

    # If the behavior repository has the request.
    if picked_response:

        # Fingerprint the server by sending this request.
        predicted_server = send_request_and_fingerprint(picked_response, server_n, server_p, path)
        if target_reaction == [0]*len(target_reaction) and predicted_server == 'caddy':
            picked_requset = '9GET /AAAAAAAAAA HTTP/1.1\r\nHost: targetIP\r\nContent-Length: 8\r\nConnection: close\r\n\r\ndata\r\n\r\n'.replace('targetIP', server_n)
            picked_requset = picked_requset.encode()
            picked_response = 'HTTP/1.1 502 Bad Gateway\r\nServer: Caddy\r\nDate: Tue, 20 Aug 2024 03:37:50 GMT\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
            response = send_request(server_n, server_p, path, picked_requset, False)
            if type(response) == 'bytes' and type(response.decode('utf-8')) == str and len(response.decode('utf-8')):
                resp_sim = jaccard_similarity(response.decode('utf-8'), picked_response)
            else:
                resp_sim = 0.5
            non_server_list = ["200", "too_long", "exception", "empty"]
            if response not in non_server_list and resp_sim < 0.7 and b'Caddy' not in response:
                predicted_server = 'unknown'
        # If it finds a server.
        if len(predicted_server) > 0:
            return predicted_server
        # If it cannot find a server.
        return False

    # If the behavior repository has not the request.
    # Phase 2 starts
    with open("behavior-add_lighttpd.json", "rb") as reader:
        hashmap  = json.load(reader)

        all_unordered_servers = []

        for i in hashmap:
            lst = json.loads(i)
            if 2 not in lst and 3 not in lst and 4 not in lst and 5 not in lst:
                # print('#'*40)
                founded_server_indexes = [idx for idx, value in enumerate(found_server_list_indexed)
                                          if value == 1]
                
                if all(lst[ind] == 1 for ind in founded_server_indexes):
                    picked_response = pick_request(lst)

                    if picked_response:
                        predicted_server = send_request_and_fingerprint(picked_response, server_n,
                                                                        server_p, path)
                        non_server_list = ["200", "too_long", "exception", "empty"]
                        if predicted_server not in non_server_list:
                            all_unordered_servers.append(predicted_server)

        # Put all unordered servers in a list.
        unordered_list = list(set(all_unordered_servers))

        # The servers are currently not ordered.
        ordered = False

        # qyy version: 对于存在unknown的多个预测结果的元素，删除unknown 进入原来的排序处理
        if "unknown" in unordered_list and len(unordered_list) > 1:
            unordered_list.remove('unknown')
        
        # Check if unknown servers are present in the list.
        # Check if there are more than one servers in the list.
        if "unknown" not in unordered_list and len(unordered_list) > 1:
            # Find the ordering of the unordered servers.
            # Phase 3
            return find_ordering_of_unordered_servers(server_n, server_p, path, unordered_list,
                                                      found_server_list_indexed, ordered)

        if len(unordered_list) == 1:
            # The only server is returned as ordered.
            return ("predict", unordered_list, True)

        if len(unordered_list) > 0:
            # Unknown is in the list, hence, it cannot find the ordering.
            return ("predict", unordered_list, ordered)

        return False

def initial_redirect_check(server_n, path):
    """ checking the initial redirects """

    redirect_count = 0

    try:
        while True:

            # if redirect count is larger or equal to 15, redirect count exceeded.
            if redirect_count >= 15:
                return None, "redirect count exceeded"

            # check if path is str, else decode it.
            if isinstance(path,str):
                pass
            else:
                path = path.decode()

            # request used in the initial redirection check.
            request = f"GET {path} HTTP/1.1\r\nHost: {server_n}\r\nUser-Agent: Wget/1.21.4\r\nConnection: close\r\n\r\n"

            # increase the redirect count.
            redirect_count += 1

            path = path.encode()

            # socket programming.
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # remove some checks.
            ssl.match_hostname = lambda cert, hostname: True
            ssl._create_default_https_context = ssl._create_unverified_context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            response = b''

            # send the request and receive a response.
            with context.wrap_socket(sock, server_hostname=server_n) as ssock:
                ssock.settimeout(10)
                ssock.connect((server_n, 443))
                ssock.sendall(request.encode())

                while True:
                    data = ssock.recv(2048)
                    if not data:
                        break
                    response += data

                ssock.close()

            if len(response) == 0:
                return server_n, path

            # parse the response.
            lines = response.split(b'\r\n')
            status_line = lines[0]
            headers = lines[1:]
            status_code = int(status_line.split(b' ')[1])

            # if status code is not redirect, return the hostname and path.
            if status_code not in (301, 302, 303, 307, 308):
                return server_n, path

            # search for the "Location" header.
            for header in headers:
                if header.lower().startswith(b'location:'):
                    # parse the url in the Location header.
                    url = header.split(b':', 1)[1].strip()
                    parse_results = urlparse(url)
                    if parse_results.hostname is not None:
                        server_n = parse_results.hostname
                    path = parse_results.path

    except Exception:
        return server_n, path

def compare_dict_similarity(dict1, dict2):
    # 计算key的重合度
    keys1 = set(dict1.keys())
    keys2 = set(dict2.keys())
    common_keys = keys1.intersection(keys2)
    sim1 = len(common_keys) / max(len(keys1), len(keys2)) if keys1 or keys2 else 1

    # 计算value的重合度
    sim2 = 0
    for key in common_keys:
        if dict1[key] == dict2[key]:
            sim2 += 1
    sim2 = sim2 / len(common_keys) if common_keys else 1

    # 计算最终的相似度得分
    similarity_score = sim1 * 0.6 + sim2 * 0.4

    return similarity_score

def send_https_request(picked_response, server_n, server_p, path):
    _, resp = picked_response[0]
    picked_r = resp['after_mut'].encode()
    time.sleep(random.randint(0, 10)/10)
    response = send_request(server_n, server_p, path, picked_r, False)
    if len(response) == 0:
        return ""
    return response

def pick_req_fordoh(found_server_list_indexed, server_n, server_p, path=''):
    """ for a given target reaction, picks a request and fingerprints the current layer """
    response_list = []
    
    with open("behavior-add_lighttpd.json", "rb") as reader:
        hashmap  = json.load(reader)
    
    # Phase 0 starts
    # if none of found server list ,then return all of response in behavior
    if found_server_list_indexed == [0] * len(found_server_list_indexed):
        for i in hashmap:
            picked_response = hashmap[i]
            response = send_https_request(picked_response, server_n, server_p, path)
            response_list.append(response)
        return response_list

    # Phase 1 starts
    # Searches for a request for a given target reaction in the behavior repository.
    picked_response = pick_request(found_server_list_indexed)

    # If the behavior repository has the request.
    if picked_response:
        # Fingerprint the server by sending this request.
        response = send_https_request(picked_response, server_n, server_p, path)
        response_list.append(response)

    all_unordered_servers = []
    for i in hashmap:
        lst = json.loads(i)
        if 2 not in lst and 3 not in lst and 4 not in lst and 5 not in lst:
            # print('#'*40)
            founded_server_indexes = [idx for idx, value in enumerate(found_server_list_indexed)
                                        if value == 1]

            if all(lst[ind] == 1 for ind in founded_server_indexes):

                picked_response = hashmap[i]
                response = send_https_request(picked_response, server_n, server_p, path)
                response_list.append(response)

    return response_list



def find_doh_server(found_server_list, target, port = 443):
    '''last layer in https'''
    
    with open("behavior_repository-doh.json", "rb") as reader:
        fp_doh_server = json.load(reader)
        if str(found_server_list) in fp_doh_server:
            server_dict = fp_doh_server[str(found_server_list)]
        else:
            server_dict = fp_doh_server["[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]"]
    # print(server_dict)
    fp_header,_ =  doh_query.send_doh_queries(
        hostname = target,
        port = port,
        query_name='google.com',
        query_type='A',
        query_class='IN',
        path='/dns-query',
        is_post=False,
        verify_mode=False
    )
    server = fp_header['server'] if 'server' in fp_header else ''
    
    max_sim = float("-inf")
    max_server = ''

    for server_key, success_query_header in server_dict[1]['doh-query-resp-header'].items():
        if 'date' in fp_header:
            success_query_header.replace("fill2date", fp_header['date'])

        server_sim = 0
        if server_key.lower() in server.lower():
            server_sim += 1
        
        success_query_header = success_query_header.replace("target", target)
        success_query_header = success_query_header.replace("\'", "\"")
        # fp_header_str = str().replace("\'", "\"")
        # dict_test = json.loads(fp_header_str)
        header_sim = compare_dict_similarity(fp_header, json.loads(success_query_header))
        # header_sim = jaccard_similarity(str(fp_header), success_query_header)
        
        total_sim = header_sim + server_sim
        if total_sim > max_sim:
            max_sim = total_sim
            max_server = server_key
    print(f'doh check: sim of header is {max_sim}')
    thresh = 0.8
    if max_sim > thresh:
        return 'doh_' + max_server
        pass
    
    # return 1
    
    max_sim = float("-inf")
    max_server = ''
    
    fp_http_list = pick_req_fordoh(found_server_list, target, port)
    for fp_http in fp_http_list:
        if type(fp_http) == str:
            continue
        fp_http_str = fp_http.decode('utf-8')
        for server_key, false_http_response in server_dict[1]['error-query-resp'].items():
            if 'Date: ' in fp_http_str and 'fill2date' in false_http_response:
                date_str = fp_http_str.split('Date: ')[1].split('\r\n')[0]
                false_http_response = false_http_response.replace('fill2date', date_str)
            response_sim = jaccard_similarity(fp_http_str, false_http_response)
            if response_sim > max_sim:
                max_sim = response_sim
                max_server = server_key
    print(f'doh check 2: sim of header is {max_sim}')
    thresh = 0.4
    if found_server_list[4] == 1: ## nginx
        thresh -= 0.1
    if found_server_list[8] == 1: ## caddy
        thresh -= 0.1
    if found_server_list[11] == 1: ## squid
        thresh -= 0.1
    if max_sim > thresh:
        return 'doh_' + max_server
        # pass
        
    return 'doh_unknown'

from dnslib import DNSRecord

def find_dns_server(found_server_list, target, port = 443):
    _, content =  doh_query.send_doh_queries(
        hostname = target,
        port = port,
        query_name='version.bind',
        query_type='TXT',
        query_class='chaos',
        path='/dns-query',
        is_post=False,
        verify_mode=False
    )
    if content == '':
        return 'dns_unknown'
    try:
        record = DNSRecord.parse(content).rr
        rdata_list = [rr.rdata for rr in record]
        print(rdata_list)
        if (len(rdata_list) == 0):
            return 'dns_unknown'
        else:
            return 'dns_' + str(rdata_list[0]).strip('\"')
    except:
        print('dns 解析失败')
        return 'dns_unknown'
    

def fingerprint(server_n, server_p):
    """ main fingerprinting function """

    # check initial redirects
    server_n, path = initial_redirect_check(server_n, "/")

    server = Servers()

    # found server list holds the servers that layyerx found.
    found_server_list = []
    found_server_list_indexed = [0]*len(server.server_list)

    # Initialize the target reaction = all servers return an error.
    target_reaction = [0]*len(server.server_list)

    # Current layer = 0
    layer = 0

    # Fingerprint up to 3 layers.
    while layer <= 2:
        # find the server
        predicted_server = find_layer(target_reaction, server_n, server_p,
                                      path, found_server_list_indexed)

        # if 
        if isinstance(predicted_server, tuple):
            if predicted_server[2] is True:
                # found_server_list.extend(predicted_server[1])
                for server_item in predicted_server[1]:
                    found_server_list.append(server_item)
                    if server_item not in ["200", "too_long", "unknown", "exception", "empty"]:
                        found_server_list_indexed[server.server_dict[server_item]] = 1
            else:
                found_server_list.append(predicted_server[1])
            break
        elif predicted_server in ["200", "too_long", "unknown", "exception", "empty"]:
            found_server_list.append(predicted_server)
            break
        elif predicted_server:
            target_reaction[server.server_dict[predicted_server]] = 1
            found_server_list_indexed[server.server_dict[predicted_server]] = 1
            found_server_list.append(predicted_server)
            layer += 1
        else:
            break
    
    # qyy version : add doh & dns result at the end
    doh_result = ''
    doh_result = find_doh_server(found_server_list_indexed, server_n, server_p)
    found_server_list.append(doh_result)

    dns_result = ''
    dns_result = find_dns_server(found_server_list_indexed, server_n, server_p)
    found_server_list.append(dns_result)

    # return fingerprinted servers
    return found_server_list

def layyerx(host, port):
    """ main function """

    # parsing arguments.
    arg = arg_parse()
    target_host = arg.target

    target_host = host
    target_port = port
    if target_host == None:
        print("Please use the -t flag and provide a hostname.")
        exit()

    # call fingerprint function.
    results = fingerprint(target_host, target_port)
    print(f'*****************{host}***************')
    # iterate over the results.
    for layer_num, server in enumerate(results):
        # if server is str, we know it is an ordered layer.
        if isinstance(server, str):
            if 'doh_' in server:
                print("Layer " + "doh" + ":", server.strip('doh_'))
            elif 'dns_' in server:
                print("Layer " + "dns" + ":", server.strip('dns_'))
            else:
                print("Layer " + str(layer_num+1) + ":", server)
        # if server is list, we know it is an unordered list of servers.
        elif isinstance(server, list):
            print("Unordered Layers:")
            for unordered_server in server:
                print(unordered_server)
        else:
            print("something wrong")

    
if __name__ == '__main__':

    arg = arg_parse()
    target_host = arg.target
    target_port = arg.port
    
    layyerx(target_host, target_port)

