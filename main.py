import logging
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv4Address, summarize_address_range
from typing import List, Optional

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
        elif config_branch[1] == 'service' and config_branch[2] == 'category':
            if 'service_category' not in firewall.keys():
                firewall['service_category'] = config.children
            else:
                print('ERROR: config "firewall service category" should only be present once')
        elif config_branch[1] == 'service' and config_branch[2] == 'group':
            if 'service_group' not in firewall.keys():
                firewall['service_group'] = config.children
            else:
                print('ERROR: config "firewall service category" should only be present once')
        elif config_branch[1] == 'service' and config_branch[2] == 'custom':
            if 'service_custom' not in firewall.keys():
                firewall['service_custom'] = config.children
            else:
                print('ERROR: config "firewall service custom" should only be present once')


#######################################################################################
# Convert useful information to dataclasses
#######################################################################################
@dataclass
class FwNetAlias:
    name: str
    comment: str
    net_list: List[IPv4Network]


fw_address = []

for entry in firewall['address'][1:]:
    name = entry.children[0]
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
                if cmd.children[0] != 'color' and cmd.children[0] != 'uuid':
                    print('WARNING: NOT EVALUATED: config firewall address:', cmd.children[0], cmd.children[1:],
                          '\n  CONTEXT:', entry)
        else:
            raise RuntimeError("Expected 'set' command!")
    if not ip:
        print("WARNING: Skipped incomplete/unparseable 'config firewall address': missing 'subnet' or 'start-ip'/'end-ip'", entry)
        continue
    fw_address.append(FwNetAlias(str(name), str(comment), ip))


# not used function
def resolve_addr(key: str, fw_address_list: List[FwNetAlias]) -> List[IPv4Network]:
    for addr in fw_address_list:
        if str(key) == str(addr.key):
            return addr.addresses


@dataclass
class FwNetAliasGroup:
    name: str
    comment: str
    net_alias_list: List[str]

fw_address_grop = []

for entry in firewall['addrgrp'][1:]:
    name = entry.children[0]
    address_keys = []
    for cmd in entry.children[1:]:
        if cmd.data == 'subcommand_field_set':
            if cmd.children[0] == 'comment':
                comment = cmd.children[1].children[0]
            elif cmd.children[0] == 'member':
                for addr_key in cmd.children[1].children:
                    address_keys.append(str(addr_key))
            else:
                if cmd.children[0] != 'color' and cmd.children[0] != 'uuid':
                    print('WARNING: NOT EVALUATED: config firewall addrgrp:', cmd.children[0], cmd.children[1:],
                          '\n  CONTEXT:', entry)
        else:
            raise RuntimeError("Expected 'set' command!")
    if not address_keys:
        raise RuntimeError("Incompletely parsed record")
    fw_address_grop.append(FwNetAlias(str(name), str(comment), address_keys))


@dataclass
class FwIPAlias:
    name: str
    comment: str
    ip: List[IPv4Address]

fw_ippool = []  # used for NAT/PAT

for entry in firewall['ippool'][1:]:
    name = entry.children[0]
    ip = None
    ip_s = None
    for cmd in entry.children[1:]:
        if cmd.data == 'subcommand_field_set':
            if cmd.children[0] == 'comments':
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
                if cmd.children[0] != 'TODO':
                    print('WARNING: NOT EVALUATED: config firewall ippool:', cmd.children[0], cmd.children[1:],
                          '\n  CONTEXT:',entry)
        else:
            raise RuntimeError("Expected 'set' command!")
    if ip is None:
        raise RuntimeError("Incompletely parsed record")
    fw_ippool.append(FwIPAlias(str(name), str(comment), ip))


@dataclass
class FwPolicy:
    src_interface: str
    dst_interface: str
    src_alias_list: List[str]
    dst_alias_list: List[str]
    action: str
    service: List[str]
    log_traffic: str
    comment: str
    label: str
    nat: bool
    session_ttl: Optional[int]
    ippool: bool
    poolname: Optional[str]
    voip_profile: Optional[str]
    utm_status:bool
    nat_ip:Optional[IPv4Network]

fw_policy = []

for entry in firewall['policy'][1:]:
    skip = False
    src_interface = None
    dst_interface = None
    src_alias_list = []
    dst_alias_list = []
    action = None
    service = []
    comment = None
    label = None
    log_traffic = 'disable'
    nat = False
    session_ttl = None
    ippool = False
    poolname = None
    voip_profile=None
    utm_status=False
    nat_ip=None

    for cmd in entry.children[1:]:
        if cmd.data == 'subcommand_field_set':
            if cmd.children[0] == 'status':
                if str(cmd.children[1].children[0]) == 'disable':
                    skip = True
                    break
            elif cmd.children[0] == 'comments':
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
            elif cmd.children[0] == 'natip':
                if nat_ip is None:
                    if len(cmd.children[1].children) == 2:
                        # case ip + netmask
                        nat_ip = IPv4Network('/'.join(cmd.children[1].children))
                    else:
                        # case subnet
                        nat_ip = IPv4Network(cmd.children[1].children[0])
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
            elif cmd.children[0] == 'logtraffic':
                log_traffic = str(cmd.children[1].children[0])
            elif cmd.children[0] == 'nat':
                if nat is False:
                    if not str(cmd.children[1].children[0]) == 'enable':
                        raise RuntimeError('Expected "set nat enable" got "set nat '+str(cmd.children[1].children[0])+'"')
                    else:
                        nat = True
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'ippool':
                if ippool is False:
                    if not str(cmd.children[1].children[0]) == 'enable':
                        raise RuntimeError('Expected "set ippool enable" got "set ippool '+str(cmd.children[1].children[0])+'"')
                    else:
                        ippool = True
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'utm-status':
                if utm_status is False:
                    if not str(cmd.children[1].children[0]) == 'enable':
                        raise RuntimeError('Expected "set utm-status enable" got "set utm-status '+str(cmd.children[1].children[0])+'"')
                    else:
                        utm_status = True
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'poolname':
                if poolname is None:
                    poolname = str(cmd.children[1].children[0])
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'voip-profile':
                if voip_profile is None:
                    voip_profile = str(cmd.children[1].children[0])
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'session-ttl':
                if session_ttl is None:
                    session_ttl = int(cmd.children[1].children[0])
                else:
                    raise RuntimeError("Encountered conflicting set command")
            else:
                if cmd.children[0] != 'uuid' and cmd.children[0] != 'schedule' \
                        and cmd.children[0] != 'logtraffic-start':
                    print('WARNING: NOT EVALUATED: config firewall policy:', cmd.children[0], cmd.children[1:],
                          '\n  CONTEXT:',entry)
        else:
            raise RuntimeError("Expected 'set' command!")
    if skip:
        continue
    if src_interface is None:
        print("WARNING: Skipped incomplete/unparseable 'config firewall policy': missing 'srcintf':", entry)
        continue
    elif dst_interface is None:
        print("WARNING: Skipped incomplete/unparseable 'config firewall policy': missing 'dstintf':", entry)
        continue
    elif action is None:
        print("WARNING: Skipped incomplete/unparseable 'config firewall policy': missing 'action':", entry)
        continue
    elif not src_alias_list:
        print("WARNING: Skipped incomplete/unparseable 'config firewall policy': missing 'srcaddr'", entry)
        continue
    elif not dst_alias_list:
        print("WARNING: Skipped incomplete/unparseable 'config firewall policy': missing 'dstaddr':", entry)
        continue
    elif not service:
        print("WARNING: Skipped incomplete/unparseable 'config firewall policy': missing 'service':", entry)
        continue
    elif label is None:
        print("WARNING: Skipped incomplete/unparseable 'config firewall policy': missing 'global-label':", entry)
        continue
    fw_policy.append(FwPolicy(src_interface, dst_interface, src_alias_list, dst_alias_list,
                              action, service, log_traffic, comment, label, nat, session_ttl,
                              ippool,poolname,voip_profile,utm_status,nat_ip))


@dataclass
class FwServiceCategroy:
    name: str
    comment: str
    members: List[str]


fw_service_category = []

for entry in firewall['service_category'][1:]:
    name = entry.children[0]
    if len(entry.children[1:]) != 1:
        raise RuntimeError('Unexpected number of commands')
    if entry.children[1].data != 'subcommand_field_set':
        raise RuntimeError('Unexpected type of command')
    if entry.children[1].children[0] != 'comment':
        raise RuntimeError('Unexpected set target')
    comment = entry.children[1].children[1].children[0]
    fw_service_category.append(FwServiceCategroy(str(name), str(comment), []))

@dataclass
class PortRange:
    start: int
    end: int

@dataclass
class FwService:
    name: str
    comment: Optional[str]
    category: Optional[str]
    protocol: Optional[str]
    icmp_type: Optional[int]
    tcp_range: Optional[PortRange]  # Maybe List needed
    udp_range: Optional[PortRange]  # Maybe List needed
    session_ttl: Optional[str]


fw_service = []

for entry in firewall['service_custom'][1:]:
    skip = False
    name = entry.children[0]
    comment = None
    category = None
    protocol = None
    icmp_type = None
    tcp_range = None
    udp_range = None
    session_ttl = None
    for cmd in entry.children[1:]:
        if cmd.data == 'subcommand_field_set':
            if cmd.children[0] == 'category':
                if category is None:
                    category = str(cmd.children[1].children[0])
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'comment':
                if comment is None:
                    comment = str(cmd.children[1].children[0])
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'protocol':
                if protocol is None:
                    protocol = str(cmd.children[1].children[0])
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'icmptype':
                if icmp_type is None:
                    icmp_type = int(cmd.children[1].children[0])
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'session-ttl':
                if session_ttl is None:
                    session_ttl = int(cmd.children[1].children[0])
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'tcp-portrange':
                if tcp_range is None:
                    tmp = str(cmd.children[1].children[0]).split(':')
                    assert 0 < len(tmp) <= 2
                    if len(tmp) == 2 and tmp[1] != '0' and tmp[1] !='0-65535':
                        print("WARNING: Unexpected port-range; skipped 'config firewall service custom':", entry)
                        skip=True
                        break
                    else:
                        tmp = tmp[0].split('-')
                        assert 0 < len(tmp) <= 2
                        if len(tmp) == 2:
                            tcp_range=PortRange(int(tmp[0]),int(tmp[1]))
                        else:
                            tcp_range=PortRange(int(tmp[0]),int(tmp[0]))
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'udp-portrange':
                if udp_range is None:
                    tmp = str(cmd.children[1].children[0]).split(':')
                    assert 0 < len(tmp) <= 2
                    if len(tmp) == 2 and (tmp[1] != '0' or tmp[1] != '0-65535'):
                        print("WARNING: Skipped unexpected 'config firewall service custom':", entry)
                        skip = True
                        break
                    else:
                        tmp = tmp[0].split('-')
                        assert 0 < len(tmp) <= 2
                        if len(tmp) == 2:
                            udp_range = PortRange(int(tmp[0]), int(tmp[1]))
                        else:
                            udp_range = PortRange(int(tmp[0]), int(tmp[0]))
                else:
                    raise RuntimeError("Encountered conflicting set command")
            else:
                if cmd.children[0] != 'color' and cmd.children[0] != 'visibility':
                    print('NOT EVALUATED:', cmd.children[0], cmd.children[1:])
    if skip:
        continue
    fw_service.append(FwService(name,comment,category,protocol,icmp_type,tcp_range,udp_range,session_ttl))

# TODO:
#  'config firewall service group'

