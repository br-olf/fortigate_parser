from lark import Lark
import logging
from typing import NamedTuple, Any, List, Dict, Union
from ipaddress import IPv4Network, IPv4Address, summarize_address_range

logging.basicConfig(level=logging.DEBUG)

with open("fortigate.lark", "r") as f:
    grammar = f.read()

with open("../FW-UV_db.conf", "r") as f:
    conf = f.read()

parser = Lark(grammar,
              parser="lalr",
              propagate_positions=True,
              start="root",
              debug=True)

parsed_conf = parser.parse(conf)
del conf
# print(parsed_conf.pretty())

"""Extract firewall config sections"""
firewall = {}
for config in parsed_conf.children:
    if config.data == 'config':
        config_branch = config.children[0].children
    elif config.data == 'config_branch':
        config_branch = config.children
    else:
        raise RuntimeError('invalid parse tree')

    if config_branch[0] == 'firewall':
        if config_branch[1] == 'address':
            if 'address' not in firewall.keys():
                firewall['address'] = config.children
            else:
                print('ERROR: config "firewall address" should only be present once')
        elif config_branch[1] == 'policy':
            if 'policy' not in firewall.keys():
                firewall['policy'] = config.children
            else:
                print('ERROR: config "firewall policy" should only be present once')
        elif config_branch[1] == 'acl':
            if 'acl' not in firewall.keys():
                firewall['acl'] = config.children
            else:
                print('ERROR: config "firewall acl" should only be present once')
        elif config_branch[1] == 'addrgrp':
            if 'addrgrp' not in firewall.keys():
                firewall['addrgrp'] = config.children
            else:
                print('ERROR: config "firewall addrgrp" should only be present once')

FwAddress = NamedTuple("FwAddress", [("key", str), ("comment", str), ("addresses", List[IPv4Network])])

fw_address_list = []

for entry in firewall['address'][1:]:
    key = entry.children[0]
    ip = []
    ip_s = None
    for cmd in entry.children[1:]:
        if cmd.data == 'subcommand_field_set':
            if cmd.children[0] == 'subnet':
                if len(cmd.children[1].children) == 2:
                    # case ip + netmask
                    ip.append(IPv4Network('/'.join(cmd.children[1].children)))
                else:
                    # case subnet
                    ip.append(IPv4Network(cmd.children[1].children[0]))
            elif cmd.children[0] == 'comment':
                comment = cmd.children[1].children[0]
            elif cmd.children[0] == 'start-ip':
                if ip_s is None:
                    ip_s = IPv4Address(cmd.children[1].children[0])
                else:
                    raise RuntimeError("Double \"start-ip\"")
            elif cmd.children[0] == 'end-ip':
                if ip_s is not None:
                    for i in summarize_address_range(ip_s, IPv4Address(cmd.children[1].children[0])):
                        ip.append(i)
                else:
                    raise RuntimeError("\"end-ip\" without \"start-ip\"")
    fw_address_list.append(FwAddress(key, comment, ip))

# TODO!
# nice Idea but better use aliases in OPNsense
# remove below code....

def resolve_addr(key:str, fw_address_list:List[FwAddress]) -> List[IPv4Network]:
    for addr in fw_address_list:
        if str(key) == str(addr.key):
            return addr.addresses

for entry in firewall['addrgrp'][1:]:
    key = entry.children[0]
    ip = []
    for cmd in entry.children[1:]:
        if cmd.data == 'subcommand_field_set':
            if cmd.children[0] == 'comment':
                comment = cmd.children[1].children[0]
            elif cmd.children[0] == 'member':
                for addr in cmd.children[1].children:
                    ip += resolve_addr(addr, fw_address_list)
    fw_address_list.append(FwAddress(key, comment, ip))
