
import json
import pandas as pd
import ipaddress as ip
import re

with open("../FW-UV_policy.json") as f:
    uv_policy_raw = json.load(f)
with open("../FW-SV_policy.json") as f:
    sv_policy_raw = json.load(f)
with open("../Firewall_Object-Address.json") as f:
    fw_address_raw = json.load(f)
with open("../Firewall_Object-Service.json") as f:
    fw_service_raw = json.load(f)

fw_address = pd.DataFrame(fw_address_raw['records'])
del fw_address_raw
fw_service = pd.DataFrame(fw_service_raw['records'])
del fw_service_raw
sv_policy = pd.DataFrame(sv_policy_raw['records'])
del sv_policy_raw
uv_policy = pd.DataFrame(uv_policy_raw['records'])
del uv_policy_raw


def split_policy(policy):
    '''Split into header and rules'''
    headers = policy[policy.sect.isna() == False]
    header_names = [d['txt'] for d in headers.sect]
    policy_splits = []
    policy_splits_active = []
    for i in range(len(headers)-1):
        rs = policy[headers.index.values[i] + 1: headers.index.values[i + 1]]
        policy_splits.append(rs)
        policy_splits_active.append(rs[rs.status == 1])
    rs = policy[headers.index.values[-1] + 1:]
    policy_splits.append(rs)
    policy_splits_active.append(rs[rs.status == 1])
    return header_names, policy_splits


def extract_usefull_information_from_policy_split(rs, fw_address):
    # treat rs.srcintf
    source_interface_name = [[d['name'] for d in l] for l in rs.srcintf]
    # treat rs.dstintf
    destination_interface_name = [[d['name'] for d in l] for l in rs.dstintf]
    # treat rs.src
    source_name = [[d['name'] for d in l] for l in rs.src]
    source_details = []
    ip_mask_re = re.compile('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    for l in rs.src:
        src_adresses = []
        for d in l:
            if ip_mask_re.match(d) is not None:
                src_adresses.append(d)
            else:
                refs = d.split(',')

    source_details = [[d['details'] for d in l] for l in rs.src]



def resolve_address(name, fw_address):
    ip_mask_re = re.compile('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    entry = fw_address[fw_address.name == name]
    if len(entry) != 1:
        raise RuntimeError('keyerror')
    if entry.values[0,4] == 'Address':
        if entry.values[0,5][:8] == 'IP/Mask:':
            return [ip.ip_network(entry.values[0,5][8:])]
        else:
            # got FQDM
            pass
    elif entry.values[0,4] == 'IPv6 Address':
        return [ip.ip_network(entry.values[0, 5])]


sv_headers, sv_policy_splits = split_policy(sv_policy)

