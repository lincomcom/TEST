import socket
import os
from pathlib import Path
import sys
import traceback
import json
import re
from datetime import date
import base64
from argparse import ArgumentParser
import vmha_util




def checkIP(strIP):
    try:
        socket.inet_aton(strIP)
        return True
    except socket.error:
        return False

# 加上quorum_data['host'] = get_ip_addr(quorum_data['hostname'])
# get_ip_addr請實作判斷是否為ip格式 如果是否定要把hostname轉換為ip_addr
def get_ip_addr(hostname):
    
    if(checkIP(hostname)):
        return hostname
    else:
        #parse to ip_addr and return
        return
        
def test_get_ip_addr():
    quorum_data = {'hostname': '10.20.91.200', 'protocol': 'cifs', 'username': 'rtrd', 'password': 'UTF3MmUzcjQ='}
    print("quorum_data['hostname']: ", quorum_data['hostname'])
    
    ip_addr = get_ip_addr(quorum_data['hostname'])
    print("ip_addr: ", ip_addr)
    
def test_is_None():
    # { "host": "10.20.91.170", "protocol": "cifs", "username": "admin", "password": "cXExMjM0NTY="}
    quorum_data = {'host': '10.20.91.170', 'protocol': 'cifs', 'username': 'rtrd', 'password': 'UTF3MmUzcjQ='}
    
    # if(quorum_data.has_key('hostname')):
    if('hostname' in quorum_data):
        print("quorum_data['hostname']: ", quorum_data['hostname'])
    
    # if(not quorum_data.has_key('host')):
    if('host' not in quorum_data):
        ip_addr = get_ip_addr(quorum_data['hostname'])
        print("ip_addr: ", ip_addr)
    else:
        print("key \'host\' is in dict of quorum_data")
        print("quorum_data: ", quorum_data)
    
def test_try_except():
    try:
        print(f'login_qne: begin try oauth_v1')
        raise ValueError('oauth_v1 ERROR')
        
        print(f'login_qne: end try oauth_v1')
    except Exception as e:
        try:
            print(f'login_qne: begin try oauth_v2: str(e): { str(e)}')
            raise ValueError('oauth_v2 ERROR')
            print(f'login_qne: end try oauth_v2')
        except Exception as e:
            print(f'login_qne: exception after try oauth_v2: str(e): { str(e)}')
    print(f'login_qne: out of exception after try oauth_v2 and before if not token')

def test_os_path_split():
    remote_path = 'migrate_VM'
    parent_dir, target_dir = os.path.split(remote_path)
    if not parent_dir:
        print("parent_dir: ", parent_dir)
        parent_dir = target_dir
    
    print("parent_dir: ", parent_dir)
    
def test_printf(method, name):
    print(f'install method: {method}; name: {name}')
    
def test_python2_print(method, name):   
     print('install method: {}; name: {}'.format('method', 'name'))
     
def test_str_replace():
    filename = 'qvm_ui_1.4.5.q001_20230508_amd64.deb'
    print('filename: {}'.format(filename))
    pkg_name = filename.replace('_', '-', 1).split('_')[0]
    print('pkg_name: {}'.format(pkg_name))
    codesigning_file = '{}.codesigning'.format(pkg_name)
    print('codesigning_file: {}'.format(codesigning_file))
    
class MigrationOut:
        def __init__(self, vm):
            self.vm = vm
        
        def process_url(self, url: str) -> str:
            url += '_ret'
            return url

def test_instance_parameter():
    url="url_str"
    print('url: {}'.format(url)) 
    ret_url = MigrationOut.process_url(self=None, url=url)
    print('ret_url: {}'.format(ret_url))    

def test_is_secured_by_port():
    
    HTTPS_DEFAULT_PORT = 443
    
    def is_secured_by_port(port):
        print(f'port={port}')
        return int(port) == HTTPS_DEFAULT_PORT
    
    port = '443'
    print(f"type of port is {type(port)}")
    secured = is_secured_by_port(port)
    print(f"port={port}; secured={secured}")
    
def test_jason_loads_ascii_error():
    import json
    
    out = '["foo", {"bar":["baz", null, 1.0, 2]}]'
    try:
            rsp = json.loads(out)
            print(f'type of rsp={type(rsp)};rsp={rsp};')
    except Exception:
            rsp = {}
            
def test_execute():
    args = ['/usr/local/sbin/qsh', 'nc.get_policy', 'type=2', 'owner=A242']
    print(f'args: {args}; type od args is {type(args)}')
       
    return
    
def test_args_kwargs():
    URL_PREFIX = 'nc'
    SUCCESS = 200
    VS_APP_ID = 'A242'
    CMD_QSH = '/usr/local/sbin/qsh'
    # args: ['/usr/local/sbin/qsh', 'nc.get_policy', 'type=2', 'owner=A242']
    def execute(args, input=None, code_only=False, run_async=False,
            cwd=None, env=None, encoding=None, text=True):
        print(f'[execute] args: {args}; encoding: {encoding};')
        return
    
    def base_call( *args, **kwargs):
        args = list(args)
        print(f'[base_call] args: {args}')
        args.insert(0, CMD_QSH)
        print(f'[base_call][after assign command] args: {args}; kwargs: {kwargs};')
        return execute(args, **kwargs)
    
    def call( *args, **kwargs):
        print(f'[call][before list(args)] args: {args};  kwargs: {kwargs};')
        args = list(args)
        print(f'[call] args: {args}')
        command = '{}.{}'.format(URL_PREFIX, args[0])
        args[0] = command
        print(f'[call][after assign command] args: {args}')
        # kwargs = {'encoding': 'utf-8'}
        kwargs['encoding'] = 'utf-8'
        return base_call(*args, **kwargs)

    def list_policy(type=2):
        arg = 'type={}'.format(type)
        print(f'[list_policy] arg: {arg}')
        return call('get_policy', arg,
            'owner={}'.format(VS_APP_ID))
    
    list_policy()
    return

def test_is_abnormal_state_reaso_v1():
    import abc
    class PlanStateBase(abc.ABC):
    
        def is_abnormal_state_reason(self, virsh_domstate_reason_out):
            print(f'virsh_domstate_reason_out: {virsh_domstate_reason_out}')
            return virsh_domstate_reason_out ==  "shut off (crashed)" or virsh_domstate_reason_out ==  "shut off (daemon)"
    
    class Base(PlanStateBase):
        def steady_state(self):
            this_vm_domstate_reason = 'shut off (crashed)'
            is_abnormal_state_reason = self.is_abnormal_state_reason(this_vm_domstate_reason)
            print(f'is_abnormal_state_reason: {is_abnormal_state_reason}')
    
    Base().steady_state()
    return

def test_is_abnormal_state_reason_v2_strip():
    from enum import Enum, auto
    VIRSH_DOMSTATE_REASON_MAX =2
    
    class VirshDomstateReason(Enum):
        VIRSH_DOMSTATE_REASON_SHUTOFF_CRASHED = auto()
        VIRSH_DOMSTATE_REASON_SHUTOFF_DAEMON = auto()

    def is_abnormal_domstate_reason(virsh_domstate_reason_out):
        virsh_domstate_reason_out = virsh_domstate_reason_out.strip()
        print(f'[is_abnormal_domstate_reason] virsh_domstate_reason_out: \"{virsh_domstate_reason_out}\"') 
        return virsh_domstate_reason_out ==  "shut off (crashed)" or virsh_domstate_reason_out ==  "shut off (daemon)"
    
    virsh_domstate_reason_out = 'shut off (crashed)\n\n'
    ret_is_abnormal_domstate_reason = is_abnormal_domstate_reason(virsh_domstate_reason_out)
    
    print(f'[before if]virsh_domstate_reason_out: {virsh_domstate_reason_out}')
    
    if (ret_is_abnormal_domstate_reason):
        print(f'ret_is_abnormal_domstate_reason: {ret_is_abnormal_domstate_reason}')
    else:
        print(f'ret_is_abnormal_domstate_reason: {ret_is_abnormal_domstate_reason}')
    
    print(f'[after if]virsh_domstate_reason_out: {virsh_domstate_reason_out}')
    
def test_is_abnormal_state_reason_enum():
    from enum import Enum

    def is_abnormal_domstate_reason(virsh_domstate_reason_out):
        class VirshDomstateReason(Enum):
            VIRSH_DOMSTATE_REASON_SHUTOFF_CRASHED = "shut off (crashed)"
            VIRSH_DOMSTATE_REASON_SHUTOFF_DAEMON = "shut off (daemon)"
        
        virsh_domstate_reason_out = virsh_domstate_reason_out.strip()
        print(f'[is_abnormal_domstate_reason] virsh_domstate_reason_out: \"{virsh_domstate_reason_out}\"') 
        
        for reason in VirshDomstateReason:
            print(f'reason.name: {reason.name}; reason.value: {reason.value}')
            if virsh_domstate_reason_out == reason.value:
                return True
        
        return False
    
    virsh_domstate_reason_out = 'shut off (crashed)\n\n'
    ret_is_abnormal_domstate_reason = is_abnormal_domstate_reason(virsh_domstate_reason_out)
    
    if (ret_is_abnormal_domstate_reason):
        print(f'ret_is_abnormal_domstate_reason: {ret_is_abnormal_domstate_reason}')
    else:
        print(f'ret_is_abnormal_domstate_reason: {ret_is_abnormal_domstate_reason}')


def test_is_not_none():
    
    class Plan():
        CACHE_KEY_STOPPING = 'plans:{plan_uuid}:stopping'
        MAX_PLAN_NAME_LENGTH = 32
        MAX_PLAN_ROLE_LENGTH = 10
        MAX_PLAN_STRATEGY_LENGTH = 10
        RAMDISK_SIZE = 512 * 1024**2  # 512 MB
        REPLICATION_THRESHOLD = 256 * 1024**2  # 256 MB
        DEFAULT_SNAPSHOT_RETENTION_HA = 1
        # state = None
        state = 'running'
        
        @property
        def app_state(self):
            return self.state
        @property
        def is_none(self):
            print(f'self.app_state: {self.app_state}')
            ret = not self.app_state
            print(f'ret: {ret}')
            return ret
    
    
    if not Plan().is_none:
         print(f'call remote API')
    else:
        print(f'plan is None')
    
def test_get_pair_id():
    # response_text = {"status":0,"data":{"src":{"id":"6124a523-f190-4ce6-b578-6e00b777d6bb","credential":{"hostname":"10.20.91.163","protocol":"http","port":8080},"alink":"10.20.91.167","blinks":[{"id":"72532ede-f5ed-43a4-b934-11d0bb9588b5","vswitch":"qvs0"}],"storage":"shared://HA/VM_test","quorum":{"host":'null',"protocol":'null',"path":'null'},"failover_policies":{"failover_ups":'true',"failover_psu":'false',"failover_sys_fan":'false',"failover_avg_cpu_load":80,"failover_avg_mem_load":0,"failover_disk_health":'true',"failover_virtual_switch":'true',"failover_interval":15}},"dst":{"id":"b73d908d-c768-4642-b2b5-0deb77fd04b5","credential":{"hostname":"10.20.91.162","protocol":"http","port":8080},"alink":"10.20.91.166","blinks":[{"id":"4c307d00-21ce-4899-9323-f35e18db3559","vswitch":"qvs0"}],"storage":"shared://HA","quorum":{"host":'null',"protocol":'null',"path":'null'},"failover_policies":{"failover_ups":'true',"failover_psu":'false',"failover_sys_fan":'false',"failover_avg_cpu_load":80,"failover_avg_mem_load":0,"failover_disk_health":'true',"failover_virtual_switch":'true',"failover_interval":15}}}}
    response_text = {"status":0, "data":{}}
    
    def get_pair_id(response_text):
        local_pair_id = None
        if response_text is not None:
            try:
                local_pair_id = response_text.get('data').get('src').get('id')
            except Exception as e:
                traceback.print_exc()
                local_pair_id = None
                
            print(f'local_pair_id={local_pair_id}')
        return local_pair_id
    
    print(f'response_text={response_text}')
    print(f'get_pair_id={get_pair_id(response_text)}')
    
def test_get_vm_uuid():
    # response_text = {"status":0,"data":{"id":7,"uuid":"b8534d41-2943-40d2-a26d-d1bfa71c7cd3","name":"VM_test","cores":1,"memory":1073741824,"os_type":"generic","arch":"x86","description":"","boot_order":"hd","cpu_model":"Westmere","keymap":"en-us","bios":"seabios","video_type":"cirrus","auto_start":"off","auto_start_delay":60,"usb":"2","qvm":'false',"sound":'null',"disks":[{"id":7,"vm_id":7,"path":"shared://HA/VM_test/VM_test_00.img","root_path":"shared://HA/VM_test/VM_test_00.img","path_exist":'true',"size":268435456000,"actual_size":200608,"format":"qcow2","bus":"ide","cache":"writeback","dev":"hdb","boot_order":'null',"index":1,"is_dom":'false',"snapshots_size":0,"serial":"b8534d41294340d2a201","volume_name":"HA_Vol"}],"cdroms":[{"id":7,"vm_id":7,"path":'null',"image_id":'null',"path_exist":'false',"bus":"ide","dev":"hda","size":'null',"index":1,"boot_order":'null'}],"adapters":[{"id":7,"vm_id":7,"mac":"52:54:00:45:39:c7","bridge":"qvs0","port_id":"8b81b85d-b195-4ee6-9b6c-cb81ed773e6e","model":"e1000","index":1,"type":"bridge","multiqueue":'false',"queues":1}],"graphics":[{"id":7,"vm_id":7,"type":"vnc","auto_port":'true',"port":'null',"enable_password":'false',"localhost_only":'true'}],"usbs":[],"pcis":[],"gpus":[],"serialports":[],"app_states":[],"power_state":"stop","active_snapshot_id":'null',"default_folder":"shared://HA/VM_test","snapshot_type":"external","has_gpu_device":'false',"has_pci_pt_device":'false',"is_agent_enabled":'true',"is_qemu_agent_channel_connected":'false',"has_sata_controller":'false',"sata_controllers":[],"hide_kvm_sign":'false',"source":"generic","is_va":'false',"ballooning":0,"ballooning_rsvd":268435456,"hot_plug_cpu":'false',"memory_sharing":'true',"vfs":[],"create_time":"2023-06-06T11:16:07.871502","protected":'false',"tpm":'false',"processors":{"type":"shared","threads":[0]},"is_resumeable":0}}
    response_text = {"status":0,}
    # return pair_id if get or none
    def get_vm_uuid(response_text):
        if response_text is not None:
            try:
                vm_uuid = response_text.get('data').get('uuid')
            except Exception as e:
                traceback.print_exc()
                vm_uuid = None
                
            print(f'vm_uuid={vm_uuid}')
        return vm_uuid
    
    print(f'response_text={response_text}')
    print(f'get_vm_uuid={get_vm_uuid(response_text)}')
 

QVS = 'qvs'
PAIRS = 'pairs'
VMS = 'vms'
PLANS = 'plans'
protocol = 'http'
src_hostname = '10.20.91.182'
src_port = '8080'
URL = f'{protocol}://{src_hostname}:{src_port}'

vm_payload_dict = {
  "name": "VM_create_ha",
  "description": "",
  "os_type": "generic",
  "meta_path": "shared://Public/VM_create_ha",
  "cores": 1,
  "memory": 1073741824,
  "bios": "seabios",
  "disks": [
    {
      "index": 1,
      "creating_image": True,
      "size": 268435456000,
      "bus": "ide",
      "cache": "writeback",
      "path": "shared://Public"
    }
  ],
  "cdroms": [
    {
      "index": 1,
      "path": "",
      "bus": "ide"
    }
  ],
  "adapters": [
    {
      "index": 1,
      "mac": "52:54:00:45:39:c7",
      "model": "e1000",
      "type": "bridge",
      "bridge": "qvs0" # TODO:　might "qvs1"
    }
  ],
  "vfs": [],
  "graphics": [
    {
      "type": "vnc",
      "enable_password": False,
      "localhost_only": True
    }
  ],
  "qvm": False,
  "is_agent_enabled": True,
  "memory_sharing": True,
  "usb": "2",
  "video_type": "cirrus",
  "keymap": "en-us",
  "auto_start": "off",
  "auto_start_delay": 60,
  "cpu_model": "Westmere",
  "ballooning": 0,
  "hot_plug_cpu": False,
  "sound": None,
  "tpm": False,
  "ballooning_rsvd": 268435456,
  "boot": True
}     

def test_create_ha():   
    file = 'pair_conf.json'
    file_with_multiple_pairs = 'pairs_conf.txt'
    path_to_json = './pairs_conf'
    
    # 'Authorization': 'Basic YWRtaW46cXExMjM0NTY='
    headers = {
      'Content-Type': 'application/json',
      'Authorization': 'Basic adminqq123456'
    }
    
    
    
    def string_to_base64(s):
        return base64.b64encode(s.encode()).decode()

    def base64_to_string(b):
        return base64.b64decode(b.encode()).decode()
    
    def test_base64():
        password = "cXExMjM0NTY="
        str_password = "qq123456"
        print(f"base64_to_string: {base64_to_string(password)}")
        print(f"string_to_base64: {string_to_base64(str_password)}")
    
    #{'src': {'credential': {'protocol': 'http', 'hostname': '10.20.91.170', 'port': '8080', 'username': 'admin', 'password': 'cXExMjM0NTY='}
    def update_credential_password_base64(data):
        if data is not None:
            try:
                src_credential = data.get('src').get('credential')
                src_credential_password = data.get('src').get('credential').get('password')
                print(f'src_credential_password = {src_credential_password}')
                dst_credential = data.get('dst').get('credential')
                dst_credential_password = data.get('dst').get('credential').get('password')
                print(f'dst_credential_password = {dst_credential_password}')
                src_credential.update({'password': string_to_base64(src_credential_password)})
                dst_credential.update({'password': string_to_base64(dst_credential_password)})
            except Exception as e:
                traceback.print_exc()             
        print(f'updated data={data}')
        return 
    
    def load_json_conf(file):
        print(f"file name: {file}")
        try:
            with open(file, "r") as jsonfile:
                data = json.load(jsonfile)
                update_credential_password_base64(data)
                print("Read successful")
            print(f'data = {data}')
            print(f'-----')
        except Exception as e:
            traceback.print_exc()
        return data
    
    def load_multiple_json_conf(path_to_json):
        json_files = [f'{path_to_json}/{pos_json}' for pos_json in os.listdir(path_to_json) if pos_json.endswith('.json')]
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
    
    def get_credential(pair):
        if pair is not None:
            try:
                credential = pair.get('src').get('credential')
            except Exception as e:
                traceback.print_exc()
                credential = None
                
            print(f'credential={credential}')
        return credential
    
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

    def update_global_URL(protocol, src_hostname, src_port):
        global URL
        print(f'global URL = {URL}')
        URL = f'{protocol}://{src_hostname}:{src_port}'
        print(f'URL updated = {URL}')
        return URL

    def get_conf_name(pair_key):
        # ./pairs_conf/pair_181_182.json
        print(f'pair_key: {pair_key}')
        match_obj = re.search("pair_\d+_\d+", pair_key)
        if(match_obj):
            return match_obj.group()
        else:
            return None
    
    def update_headers_Authorization(headers, credential):
        if headers is not None:
            try:
                # TODO: update Authorization based on base64(user:)+password
                #'Authorization': 'Basic YWRtaW46cXExMjM0NTY='
                #'credential': {'protocol': 'http', 'hostname': '10.20.91.170', 'port': '8080', 'username': 'admin', 'password': 'cXExMjM0NTY='},
                if credential is not None:
                    print(f'credential = {credential}')
                    username = credential.get('username')
                    password = credential.get('password')
                    print(f'username = {username}')
                    print(f'password = {password}')
                    new_Authorization = 'Basic '+ string_to_base64(username + ':') + password
                    print(f'new_Authorization = {new_Authorization}')
                
                headers.update({'Authorization': new_Authorization})
                
            except Exception as e:
                traceback.print_exc()             
        print(f'updated headers={headers}')
        return 
    
    def process_multiple_pairs():
        
        pairs_dict = load_multiple_json_conf(path_to_json)
        for pair_key in pairs_dict:
            print(f'pair_key = {pair_key}; pairs_dict[pair_key]: {pairs_dict[pair_key]}')
            pair = pairs_dict[pair_key]
            credential = get_credential(pair)
            protocol, src_hostname, src_port = get_protocol_hostname_port(credential)
            print(f'[before update_headers_Authorization] headers = {headers}')
            update_headers_Authorization(headers, credential)
            URL = update_global_URL(protocol, src_hostname, src_port)
            pair_url = f'{URL}/{QVS}/{PAIRS}'
            print(f'pair_url = {pair_url}')
            print(f'get_conf_name: {get_conf_name(pair_key)}')
        return
    
    # "mac": "52:54:00:45:39:c7"
    def mac_generator():
        import random
        return f"{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}"
    
    
    def update_mac_addr(vm_payload_dict):
        if vm_payload_dict is not None:
            try:
                adapters = vm_payload_dict.get('adapters')
                for adapter in adapters:
                    adapter.update({"mac": mac_generator()})
            except Exception as e:
                traceback.print_exc()
                       
        print(f'vm_payload_dict={vm_payload_dict}')
        return 
        
    
    # data = load_json_conf(file)
    # pairs_list = load_multiple_json_conf(path_to_json)
    # for pair in pairs_list:
    #     get_protocol_hostname_port(get_credential(pair))
    # process_multiple_pairs()
    # mac_addr = mac_generator()
    # print(f'mac_addr = {mac_addr}')
    # print(f'[before] vm_payload_dict={vm_payload_dict}')
    # update_mac_addr(vm_payload_dict)
    # test_base64()
    
delete_vm_payload_dict = {
  "deleted_images": [
    
  ],
  "deleted_folder": True
}
headers = {
  'Content-Type': 'application/json',
  'Authorization': 'Basic WRtaW46cXExMjM0NTY='
}
def test_destroy_ha():
    
    pair_key = './pair_170_171_pair_rsp.json'
    # pair_rsp_name = 'pair_170_171_pair_rsp.json'
    path_to_rsp_json = '.'
    def get_config_name_from_pair_key(pair_key): 
        print(f'pair_key={pair_key}')
        return pair_key.replace('_pair_rsp', '').replace('./', '')
    
    
    # print(f'pair_key={pair_key}') 
    # print(f'vm_rsp_name={vmha_util.get_vm_rsp_name(pair_key)}') 
    # print(f'pair_key={get_config_name_from_pair_key(pair_key)}')   
    # print(f'pair_rsp_name={pair_rsp_name}') 
    # print(f'vm_rsp_name={vmha_util.get_vm_rsp_name(pair_rsp_name)}') 
    
    #POST http://10.20.91.182:8080/qvs/vms/{vm_id}/forceshutdown
    def force_shutdown_vm(url, headers, payload=None):
        url += '/forceshutdown'
        print(f'[{sys._getframe().f_code.co_name}] url: {url}')
        print(f'[{sys._getframe().f_code.co_name}] headers: {headers}')
        # response = requests.request("POST", url, headers=headers, data=payload)
        # print(f'[{sys._getframe().f_code.co_name}] response.text: {response.text}')
        # return response
    #DELETE http://10.20.91.182:8080/qvs/vms/{vm_id}
    def delete_vm(url, payload, headers):
        print(f'[{sys._getframe().f_code.co_name}] url: {url}')
        print(f'[{sys._getframe().f_code.co_name}] headers: {headers}')
        print(f'[{sys._getframe().f_code.co_name}] payload: {payload}')
        # response = requests.request("DELETE", url, headers=headers, data=payload)
        # print(f'[{sys._getframe().f_code.co_name}] response.text: {response.text}')
        # return response
    
    def process_delete_vm(pair_key):
        vm_rsp_name = vmha_util.get_vm_rsp_name(pair_key)
        print(f'vm_rsp_name={vm_rsp_name}') 
        vm_rsp_dict = vmha_util.load_multiple_json_conf(path_to_rsp_json, vm_rsp_name)
        key = f'{path_to_rsp_json}/{vm_rsp_name}'
        print(f'key: {key}') 
        vm_rsp = vm_rsp_dict.get(key)
        print(f'vm_rsp={vm_rsp}') 
        vm_id = vmha_util.get_from_data_by_key(vm_rsp, 'id')
        print(f'vm_id={vm_id}')
        vm_url = f'{URL}/{QVS}/{VMS}/{vm_id}'
        print(f'[{sys._getframe().f_code.co_name}] vm_url: {vm_url}')
        disks_list = vmha_util.get_from_data_by_key(vm_rsp, 'disks')
        for disk in disks_list:      
            delete_vm_payload_dict.get('deleted_images').append({f'path':vmha_util.get_from_disk_by_key(disk, 'path')})
        
        force_shutdown_vm(vm_url, headers)
        print(f'delete_vm_payload_dict={delete_vm_payload_dict}') 
        print(f'type of delete_vm_payload_dict={type(delete_vm_payload_dict)}') 
        delete_vm_payload = json.dumps(delete_vm_payload_dict)
        delete_vm(vm_url, delete_vm_payload, headers)
        print(f'delete_vm_payload_dict={delete_vm_payload_dict}') 
    
    process_delete_vm(pair_key)
    return

def test_parse_resp_str():
    rsp_detail ='[max_2G/ubuntu-2004-kube-v1.22.9], msg:Remote_path:max_2G/ubuntu-2004-kube-v1.22.9, volume:[DataVol2],4.54GB/20.87GB(needed/available)'
    
    def parse_res_data_detail(input_str, contain_key):
        ret = input_str
        split_list = input_str.split(",")
        for element in split_list:
            if contain_key in element:
                ret = element.replace(contain_key, '').strip()
        return ret
    
    ret = parse_res_data_detail(rsp_detail, 'msg:Remote_path:')
    print(f'parse_res_data_detail: {ret}')
    return

def test_parse_config():
    xml =  '<?xml version="1.0" encoding="UTF-8"?>\n<Envelope'
   
    
    def is_bytes(input):
        print(f'type  of input: {type(input)}')
        return 'bytes' in str(type(input))
    
    
    def parse_config(input):
        try:
           
            parsed = input    
        except Exception as e:
            traceback.print_exc()
            print(f"error: {str(e)}")
        return parsed     
    
    # if(is_bytes(xml)): 
    #     print(f'xml is bytes')
    # else:
    #     print(f'xml is not bytes')
    
    print(f'parse_config: {parse_config(xml)}')
    return 

def test_call_migrate_in_log_by_status(status_code):
        data = dict(vm='self.vm', credential='self.credential', status_code=status_code)
        # url = MIGRATION_IN_LOG_BY_STATUS_URL.format(domain=self.remote_device.connection_url)
        # print(f'data: {json.dumps(data, indent=4)}')
        print(f'{data=}')
        # self.remote_post_api(url, data)

def test_os_path_join():
    Path1 = 'home'
    Path2 = '/develop'
    Path3 = 'code'

    # Path10 = Path1 + Path2 + Path3
    Path20 = os.path.join('/share',Path2,Path3)
    # print ('Path10 = ',Path10)
    print (f'{Path20=}')
    
def test_real_path():
    ROOT_APP_VOL = 'app_volume'
    ROOT_SHARED = 'shared'
    ROOT_APP_VOL_PREFIX = '/mnt/app_volume'
    ROOT_SHARED_PREFIX = '/share'
    

    def real_path(protocol_path: str) -> str:
        # process auto_install usb path
        if not protocol_path:
            return ''
        
        protocol_parts = Path(protocol_path).parts  # '/', 'mnt', 'app_volume'
        print(f'type of parts is {type(protocol_parts)}; {protocol_parts=}')
        print(f'the last one of parts is {protocol_parts[-1]}')
        file_name = protocol_parts[-1]
        if file_name == "QuWAN.img":
            print(f'{protocol_path=}')
            quwan_path = os.path.join(ROOT_SHARED_PREFIX, protocol_path.lstrip('/'))
            print(f'{quwan_path=}')
            return quwan_path 
        
        print(f'[after quwan]{protocol_path=}')
        protocol, path = protocol_path.split('://')
        print(f'{protocol=}; {path=}')
        parts = Path(path).parts
        if protocol == ROOT_APP_VOL:
            # app_volume://Application Volume/qvm-agent/VMs/VM/vm.img
            return str(Path(ROOT_APP_VOL_PREFIX, *parts[1:]))
    
    path = "/Public/QuWAN/QuWAN.img"
    # path = "https://Public/QuWAN/QuWAN.txt"
    # path = "app_volume://Application Volume/qvm-agent/VMs/VM/vm.img"
    ret = real_path(path)
    print(f'{ret=}')
    
def test_remove_vm_dir():
    def is_empty_upload_cache_dir(path):
        files_list = os.listdir(path)
        UPLOAD_CACHE = '.@upload_cache'
        is_empty = False
        print(f'{files_list=}')
        if len(files_list) == 1 and files_list[0] == UPLOAD_CACHE:
            upload_cache_path = os.path.join(path, UPLOAD_CACHE)
            print(f'{upload_cache_path=}')
            files_in_upload_cache = os.listdir(upload_cache_path)
            print(f'{files_in_upload_cache=}')
            is_empty =  not files_in_upload_cache
        
        return is_empty
        
    def remove_vm_dir(path):
            files = os.listdir(path)
            print(f'[before]{files} in {path}')
            if files and not is_empty_upload_cache_dir(path):
                print(f'{files} in {path}')
                return
            
            print(f'after files check')

    path = 'C:\\Users\\xunlin\\python_workspace\\test\\VM_remove'
    remove_vm_dir(path)
    
def test_handle_logs_log():
    
    def handle_logs_log(fk_value, parent_datas):
        if fk_value is not None and fk_value not in parent_datas or len(parent_datas) == 0 :
            print(f'[in if] {fk_value=}; {parent_datas=}')
        else:
            print(f'[out if] {fk_value=}; {parent_datas=}')
            
            
    handle_logs_log('FK', [])
    
def test_multiple_try_exceptions():
    
    def input_int():
        try:
            numbers = input('輸入數字（空白區隔）：').split(' ')
            print('平均', sum(int(number) for number in numbers) / len(numbers))
        except ValueError as err:
            print(err)
            raise err
    
    def task_pre_check():
        try:
            input_int()
        except Exception as e:
            print(f'[task_pre_check]{str(e)=}')
            raise e
            
        
    def migration():
        try:
            task_pre_check()
        except Exception as e:
            print(f'[migration]{str(e)=}')
            #call remote lo
            # raise e
        else:
            print(f'[migration] task.enqueue()')
    
    migration()
        
def test_parse_data_from_detail():
    e_detail='[max_2G/VM_ubuntu_18.04_testMax2G], msg:Remote_path:max_2G/VM_ubuntu_18.04_testMax2G, volume:[DataVol2],16.87GB/6.64GB(needed/available)'
     
    def parse_data_from_detail(exce_detail):
        try:
            return exce_detail.split('[')[1].split(']')[0]
        except Exception as e:
            print(str(e))
            return '' 
        
    print(f'{e_detail=};\n{parse_data_from_detail(e_detail)=}')
     

def test_QuorumWriter():
    import time
    class QuorumWriter:
        def __init__(self):
            pwd_path = '/c/Users/xunlin/python_workspace/test/'
            sufix = 'timestamp'
            self.timestamp_path = pwd_path + sufix
        
        def mkdir(self, path):
            dirname = os.path.dirname(path)
            if not os.path.exists(dirname):
                self.mkdir(dirname)
            if not os.path.exists(path):
                os.mkdir(path)

        def write_file(self, timestamp_path, quorum_info):
            self.mkdir(os.path.dirname(timestamp_path))
            fp = open(timestamp_path, 'w')
            json.dump(quorum_info, fp, sort_keys=True,
                        indent=4, separators=(',', ': '))
            fp.close()
            
        def write_quorum(self):
            
            try:              
                quorum_info = {
                        "time":	int(time.time()),
                        "pvm_state_code": 777
                }
                print(f'{self.timestamp_path= }; {quorum_info=}')
                self.write_file(self.timestamp_path, quorum_info)
                fp = open(self.timestamp_path, 'w')
                json.dump(quorum_info, fp, sort_keys=True,
                        indent=4, separators=(',', ': '))
                fp.close()
            except Exception as e:
                print(f'{str(e)}')
                traceback.print_exc()  
        
    # pwd_path = '/c/Users/xunlin/python_workspace/test'
    # sufix = '/0/timestamp'
    quo = QuorumWriter()
    quo.write_quorum()
   
import subprocess

def test_ping(ip_address):
    """
    Test if the given IP address is connected by ping.
    
    Args:
    - ip_address: A string representing the IP address to test.
    
    Returns:
    - True if the IP address is reachable, False otherwise.
    """
    # Use subprocess to run the ping command
    result = subprocess.run(['ping', '-c', '1', ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(f"{result=}")
    # Check the return code to determine if the ping was successful
    if result.returncode == 0:
        return True
    else:
        return False

TASK_MIGRATE_CHECK_SPACE_FAILED = 3808
def main():
    
    
    # print(f'{type(TASK_MIGRATE_CHECK_SPACE_FAILED)=}')
    
    # test_get_ip_addr()
    #test_is_None()
    # test_try_except()  
    # date_path = date.today().strftime("%Y/%b/%d")
    # print(f'date_path = {date_path}')
    # test_os_path_split()
    # test_printf("apt", "python")
    # test_python2_print("apt", "python")
    # test_str_replace()
    # test_instance_parameter()
    # test_is_secured_by_port()
    
    # test_jason_loads_ascii_error()
    # test_execute()
    # test_args_kwargs()
    # test_is_abnormal_state_reason()
    # test_is_abnormal_state_reason_v2_strip()
    # test_is_abnormal_state_reason_enum()
    # test_is_not_none()
    # test_get_pair_id()
    # test_get_vm_uuid()
    # test_create_ha()
    # test_destroy_ha()
    # test_parse_resp_str()
    # test_parse_config()
    # test_call_migrate_in_log_by_status(status_code=12345)
    # path = "/Public/QuWAN/QuWAN.img"
    # test_real_path()
    # test_remove_vm_dir()
    # test_handle_logs_log()
    
    # test_multiple_try_exceptions()
    # test_parse_data_from_detail()
    
    # test_QuorumWriter()
    
    # Example usage:
    ip_to_test = '8.8.8.8'  # IP address to test
    is_connected = test_ping(ip_to_test)
    print(f"Is {ip_to_test} connected? {is_connected}")
  
    
    # test_os_path_join()
    return

if __name__ == '__main__':
    
    
    # parser = set_arg_parser()
    # args = parser.parse_args()
    # print(f'args.name={args.name}')
    main()