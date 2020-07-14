import logging
from ipaddress import IPv4Network, IPv4Address, summarize_address_range
from typing import NamedTuple, List

from lark import Lark

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
        elif config_branch[1] == 'ippool':
            if 'ippool' not in firewall.keys():
                firewall['ippool'] = config.children
            else:
                print('ERROR: config "firewall ippool" should only be present once')

#######################################################################################
"""Convert useful information to NamedTuples"""
#######################################################################################
FwNetAlias = NamedTuple("FwNetAlias", [("key", str), ("comment", str), ("net_list", List[IPv4Network])])
fw_address = []

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
        else:
            raise RuntimeError("Expected 'set' command!")
    if not ip:
        print("WARNING: Skipped incomplete/unparseable 'config firewall address':", entry)
        continue
    fw_address.append(FwNetAlias(str(key), str(comment), ip))


# not used function
def resolve_addr(key: str, fw_address_list: List[FwNetAlias]) -> List[IPv4Network]:
    for addr in fw_address_list:
        if str(key) == str(addr.key):
            return addr.addresses


FwNetAliasGroup = NamedTuple("FwNetAliasGroup", [("key", str), ("comment", str), ("net_alias_list", List[str])])
fw_address_grop = []

for entry in firewall['addrgrp'][1:]:
    key = entry.children[0]
    address_keys = []
    for cmd in entry.children[1:]:
        if cmd.data == 'subcommand_field_set':
            if cmd.children[0] == 'comment':
                comment = cmd.children[1].children[0]
            elif cmd.children[0] == 'member':
                for addr_key in cmd.children[1].children:
                    address_keys.append(str(addr_key))
        else:
            raise RuntimeError("Expected 'set' command!")
    if not address_keys:
        raise RuntimeError("Incompletely parsed record")
    fw_address_grop.append(FwNetAlias(str(key), str(comment), address_keys))

FwIPAlias = NamedTuple("FwIPAlias", [("key", str), ("comment", str), ("ip", IPv4Address)])
fw_ippool = []  # used for NAT/PAT

for entry in firewall['ippool'][1:]:
    key = entry.children[0]
    ip = None
    ip_s = None
    for cmd in entry.children[1:]:
        if cmd.data == 'subcommand_field_set':
            if cmd.children[0] == 'comment':
                comment = cmd.children[1].children[0]
            elif cmd.children[0] == 'startip':
                if ip_s is None:
                    ip_s = IPv4Address(cmd.children[1].children[0])
                else:
                    raise RuntimeError("Double \"startip\"")
            elif cmd.children[0] == 'endip':
                if ip_s is not None:
                    if ip_s == IPv4Address(cmd.children[1].children[0]):
                        ip = ip_s
                    else:
                        raise RuntimeError("Encountered net slide and expected single IP")
                else:
                    raise RuntimeError("\"endip\" without \"startip\"")
        else:
            raise RuntimeError("Expected 'set' command!")
    if ip is None:
        raise RuntimeError("Incompletely parsed record")
    fw_ippool.append(FwIPAlias(str(key), str(comment), ip))

FwPolicy = NamedTuple("FwPolicy", [("src_interface", str), ("dst_interface", str),
                                   ("src_alias_list", List[str]), ("dst_alias_list", List[str]),
                                   ("action", str), ("service", List[str]), ("log_traffic", str),
                                   ("comment", str), ("label", str), ('nat', bool)])
fw_policy = []

for entry in firewall['policy'][1:]:
    src_interface = None
    dst_interface = None
    src_alias_list = []
    dst_alias_list = []
    action = None
    service = []
    label = None
    log_traffic = 'disable'
    nat = False
    for cmd in entry.children[1:]:
        if cmd.data == 'subcommand_field_set':
            if cmd.children[0] == 'comment':
                comment = cmd.children[1].children[0]
            elif cmd.children[0] == 'srcintf':
                if src_interface is None:
                    src_interface = str(cmd.children[1].children[0])
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'dstintf':
                if dst_interface is None:
                    dst_interface = str(cmd.children[1].children[0])
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'srcaddr':
                if not src_alias_list:
                    for alias in cmd.children[1].children:
                        src_alias_list.append(str(alias))
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'dstaddr':
                if not dst_alias_list:
                    for alias in cmd.children[1].children:
                        dst_alias_list.append(str(alias))
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'action':
                if action is None:
                    action = str(cmd.children[1].children[0])
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'send-deny-packet':
                if action is None:
                    if str(cmd.children[1].children[0]) == 'enable':
                        action = 'deny'
                    else:
                        raise RuntimeError('Encountered unexpected value')
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'service':
                if not service:
                    for s in cmd.children[1].children:
                        service.append(str(s))
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'global-label':
                if label is None:
                    label = str(cmd.children[1].children[0])
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'global-label':
                if label is None:
                    label = str(cmd.children[1].children[0])
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'nat':
                if nat is False:
                    if not str(cmd.children[1].children[0]) == 'enable':
                        raise RuntimeError('Expected "set nat enable" got "set nat'+str(cmd.children[1].children[0])+'"')
                    else:
                        nat = True
                else:
                    raise RuntimeError("Encountered conflicting set command")
        else:
            raise RuntimeError("Expected 'set' command!")
    if src_interface is None:
        print("WARNING: Skipped incomplete/unparseable 'config firewall policy':", entry)
        continue
    elif dst_interface is None:
        print("WARNING: Skipped incomplete/unparseable 'config firewall policy':", entry)
        continue
    elif action is None:
        print("WARNING: Skipped incomplete/unparseable 'config firewall policy':", entry)
        continue
    elif not src_alias_list:
        print("WARNING: Skipped incomplete/unparseable 'config firewall policy':", entry)
        continue
    elif not dst_alias_list:
        print("WARNING: Skipped incomplete/unparseable 'config firewall policy':", entry)
        continue
    elif not service:
        print("WARNING: Skipped incomplete/unparseable 'config firewall policy':", entry)
        continue
    elif label is None:
        print("WARNING: Skipped incomplete/unparseable 'config firewall policy':", entry)
        continue
    fw_policy.append(FwPolicy(src_interface, dst_interface, src_alias_list, dst_alias_list,
                              action, service, log_traffic, comment, label, nat))

# TODO:
#  'config firewall service custom'
#  'config firewall service group'
#  'config firewall service category'
