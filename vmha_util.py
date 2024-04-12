import os
import traceback
from argparse import ArgumentParser
import base64
import json

def set_arg_parser():
        parser = ArgumentParser()
        parser.add_argument("-n", "--name", required=False)
        return parser

def string_to_base64(s):
        return base64.b64encode(s.encode()).decode()

def load_json_conf(file_name):
        print(f"file name: {file_name}")
        try:
            with open(file_name, "r") as jsonfile:
                data = json.load(jsonfile)       
            print(f'---Read successful--')
        except Exception as e:
            traceback.print_exc()
        return data

def load_multiple_json_conf(path_to_json, file_name):
    print(f'path_to_json: {path_to_json}; file_name: {file_name}')
    if(file_name == 'all_pairs'):
        json_files = [f'{path_to_json}/{json_file}' for json_file in os.listdir(path_to_json) if json_file.endswith('.json')]
    else:        
        json_files = [f'{path_to_json}/{json_file}' for json_file in os.listdir(path_to_json) if file_name in json_file]
    print(f'json_files: {json_files}')
    try:
        pairs_dict = {}
        print("Started Reading multiple JSON files")
        for file in json_files:
            pairs_dict[file] = load_json_conf(file)
        print(f'pairs_dict: {pairs_dict}')
    except Exception as e:
        traceback.print_exc()
    return pairs_dict

def get_from_src_by_key(pair, key):
    ret_val = None
    if pair is not None:
        try:
            ret_val = pair.get('src').get(key)
        except Exception as e:
            traceback.print_exc()
            
    print(f'{key}={ret_val}')
    return ret_val

def get_protocol_hostname_port(credential):
    if credential is not None:
        try:
            protocol = credential.get('protocol')
            hostname = credential.get('hostname')
            port = credential.get('port')
        except Exception as e:
            traceback.print_exc()
        
    print(f'protocol={protocol}; hostname={hostname}; port={port})')
    return protocol, hostname, port 

def get_vm_rsp_name(pair_rsp_name):
        return pair_rsp_name.replace("pair_rsp", "vm_rsp").replace('./', '')

def get_from_data_by_key(vm_rsp, key):
    ret_val = None
    if vm_rsp is not None:
        print(f'vm_rsp={vm_rsp}')
        try:
            ret_val = vm_rsp.get('data').get(key)
        except Exception as e:
            traceback.print_exc()
                
        print(f'{key}={ret_val}')
    return ret_val
    

def get_from_disk_by_key(disk, key):
    ret_val = None
    if disk is not None:
        try:
            ret_val = disk.get(key)
        except Exception as e:
            traceback.print_exc()
            
    print(f'{key}={ret_val}')
    return ret_val    

def update_global_URL(protocol, src_hostname, src_port):
    URL = f'{protocol}://{src_hostname}:{src_port}'
    print(f'URL updated = {URL}')
    return URL

def update_headers_Authorization_by_credential(headers, credential):
        if headers is not None:
            try:
                # update Authorization based on base64(user:)+password
                #'Authorization': 'Basic YWRtaW46cXExMjM0NTY='
                if credential is not None:
                    print(f'credential = {credential}')
                    username = credential.get('username')
                    password = credential.get('password')
                    print(f'username = {username}')
                    print(f'password = {password}')
                    new_Authorization = 'Basic '+ string_to_base64(username + ':' + password)
                    print(f'new_Authorization = {new_Authorization}')
                
                headers.update({'Authorization': new_Authorization})
                
            except Exception as e:
                traceback.print_exc()             
        print(f'updated headers={headers}')
        return 