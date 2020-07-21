import logging
import re
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv4Address, summarize_address_range
from typing import List, Optional

from lark import Lark

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")

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

#######################################################################################
# Extract relevant configuration pieces
#######################################################################################
firewall_raw = {}
system_raw = {}
for config in parsed_conf.children:
    if config.data == 'config':
        config_branch = config.children[0].children
    elif config.data == 'config_branch':
        config_branch = config.children
    else:
        raise RuntimeError('invalid parse tree')

    if config_branch[0] == 'system':
        if config_branch[1] == 'dhcp' and config_branch[2] == 'server':
            if 'dhcp_server' not in firewall_raw.keys():
                system_raw['dhcp_server'] = config.children
            else:
                logging.error('config "system dhcp server" should only be present once')

    if config_branch[0] == 'firewall':
        if config_branch[1] == 'address':
            if 'address' not in firewall_raw.keys():
                firewall_raw['address'] = config.children
            else:
                logging.error('config "firewall address" should only be present once')
        elif config_branch[1] == 'policy':
            if 'policy' not in firewall_raw.keys():
                firewall_raw['policy'] = config.children
            else:
                logging.error('config "firewall policy" should only be present once')
        elif config_branch[1] == 'acl':
            if 'acl' not in firewall_raw.keys():
                firewall_raw['acl'] = config.children
            else:
                logging.error('config "firewall acl" should only be present once')
        elif config_branch[1] == 'addrgrp':
            if 'addrgrp' not in firewall_raw.keys():
                firewall_raw['addrgrp'] = config.children
            else:
                logging.error('config "firewall addrgrp" should only be present once')
        elif config_branch[1] == 'ippool':
            if 'ippool' not in firewall_raw.keys():
                firewall_raw['ippool'] = config.children
            else:
                logging.error('config "firewall ippool" should only be present once')
        elif config_branch[1] == 'service' and config_branch[2] == 'category':
            if 'service_category' not in firewall_raw.keys():
                firewall_raw['service_category'] = config.children
            else:
                logging.error('config "firewall service category" should only be present once')
        elif config_branch[1] == 'service' and config_branch[2] == 'group':
            if 'service_group' not in firewall_raw.keys():
                firewall_raw['service_group'] = config.children
            else:
                logging.error('config "firewall service category" should only be present once')
        elif config_branch[1] == 'service' and config_branch[2] == 'custom':
            if 'service_custom' not in firewall_raw.keys():
                firewall_raw['service_custom'] = config.children
            else:
                logging.error('config "firewall service custom" should only be present once')


#######################################################################################
# Convert useful information to dataclasses
#######################################################################################
@dataclass
class FwNetAlias:
    name: str
    comment: str
    net_list: List[IPv4Network]


fw_address = []
if 'address' in firewall_raw.keys():
    for entry in firewall_raw['address'][1:]:
        name = str(entry.children[0])
        ip = []
        ip_s = None
        comment = ''
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
                        logging.warning(' '.join(
                            ['NOT EVALUATED: config firewall address:\n  option:', str(cmd.children[0]), '\n  value:',
                             str(cmd.children[1:]), '\n  CONTEXT:', str(entry)]))
            else:
                raise RuntimeError("Expected 'set' command!")
        if not ip:
            logging.error(' '.join([
                "Skipped incomplete/unparseable 'config firewall address': missing 'subnet' or 'start-ip'/'end-ip':\n  CONTEXT:",
                str(entry)]))
            continue
        fw_address.append(FwNetAlias(str(name), str(comment), ip))
else:
    logging.critical('Could not find critical important section \'config firewall address\'')


@dataclass
class FwNetAliasGroup:
    name: str
    comment: str
    net_alias_list: List[str]


fw_address_group = []
if 'addrgrp' in firewall_raw.keys():
    for entry in firewall_raw['addrgrp'][1:]:
        name = str(entry.children[0])
        address_keys = []
        comment = ''
        for cmd in entry.children[1:]:
            if cmd.data == 'subcommand_field_set':
                if cmd.children[0] == 'comment':
                    comment = cmd.children[1].children[0]
                elif cmd.children[0] == 'member':
                    for addr_key in cmd.children[1].children:
                        address_keys.append(str(addr_key))
                else:
                    if cmd.children[0] != 'color' and cmd.children[0] != 'uuid':
                        logging.warning(' '.join(
                            ['NOT EVALUATED: config firewall addrgrp:\n  option:', str(cmd.children[0]), '\n  value:',
                             str(cmd.children[1:]), '\n  CONTEXT:', str(entry)]))
            else:
                raise RuntimeError("Expected 'set' command!")
        if not address_keys:
            raise RuntimeError("Incompletely parsed record")
        fw_address_group.append(FwNetAliasGroup(str(name), str(comment), address_keys))
else:
    logging.critical('Could not find critical important section \'config firewall addrgrp\'')


@dataclass
class FwIPAlias:
    name: str
    comment: str
    ip: IPv4Address


fw_ippool = []  # used for NAT/PAT
if 'ippool' in firewall_raw.keys():
    for entry in firewall_raw['ippool'][1:]:
        name = str(entry.children[0])
        ip = None
        ip_s = None
        comment = ''
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
                        logging.warning(' '.join(
                            ['NOT EVALUATED: config firewall ippool:\n  option:', str(cmd.children[0]), '\n  value:',
                             str(cmd.children[1:]), '\n  CONTEXT:', str(entry)]))
            else:
                raise RuntimeError("Expected 'set' command!")
        if ip is None:
            raise RuntimeError("Incompletely parsed record")
        fw_ippool.append(FwIPAlias(str(name), str(comment), ip))
else:
    logging.warning('Could not find section \'config firewall ippool\'')


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
    utm_status: bool
    nat_ip: Optional[IPv4Network]


fw_policy = []
if 'policy' in firewall_raw.keys():
    for entry in firewall_raw['policy'][1:]:
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
        voip_profile = None
        utm_status = False
        nat_ip = None

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
                            raise RuntimeError(
                                'Expected "set nat enable" got "set nat ' + str(cmd.children[1].children[0]) + '"')
                        else:
                            nat = True
                    else:
                        raise RuntimeError("Encountered conflicting set command")
                elif cmd.children[0] == 'ippool':
                    if ippool is False:
                        if not str(cmd.children[1].children[0]) == 'enable':
                            raise RuntimeError(
                                'Expected "set ippool enable" got "set ippool ' + str(
                                    cmd.children[1].children[0]) + '"')
                        else:
                            ippool = True
                    else:
                        raise RuntimeError("Encountered conflicting set command")
                elif cmd.children[0] == 'utm-status':
                    if utm_status is False:
                        if not str(cmd.children[1].children[0]) == 'enable':
                            raise RuntimeError('Expected "set utm-status enable" got "set utm-status ' + str(
                                cmd.children[1].children[0]) + '"')
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
                        logging.warning(' '.join(
                            ['NOT EVALUATED: config firewall policy:\n  option:', str(cmd.children[0]), '\n  value:',
                             str(cmd.children[1:]), '\n  CONTEXT:', str(entry)]))
            else:
                raise RuntimeError("Expected 'set' command!")
        if skip:
            continue
        if src_interface is None:
            logging.error(' '.join(
                ["Skipped incomplete/unparseable 'config firewall policy': missing 'srcintf':\n  CONTEXT:",
                 str(entry)]))
            continue
        elif dst_interface is None:
            logging.error(' '.join(
                ["Skipped incomplete/unparseable 'config firewall policy': missing 'dstintf':\n  CONTEXT:",
                 str(entry)]))
            continue
        elif action is None:
            logging.error(' '.join(
                ["Skipped incomplete/unparseable 'config firewall policy': missing 'action':\n  CONTEXT:", str(entry)]))
            continue
        elif not src_alias_list:
            logging.error(' '.join(
                ["Skipped incomplete/unparseable 'config firewall policy': missing 'srcaddr':\n  CONTEXT:",
                 str(entry)]))
            continue
        elif not dst_alias_list:
            logging.error(' '.join(
                ["Skipped incomplete/unparseable 'config firewall policy': missing 'dstaddr':\n  CONTEXT:",
                 str(entry)]))
            continue
        elif not service:
            logging.error(' '.join(
                ["Skipped incomplete/unparseable 'config firewall policy': missing 'service':\n  CONTEXT:",
                 str(entry)]))
            continue
        elif label is None:
            logging.error(' '.join(
                ["Skipped incomplete/unparseable 'config firewall policy': missing 'global-label':\n  CONTEXT:",
                 str(entry)]))
            continue
        fw_policy.append(FwPolicy(src_interface, dst_interface, src_alias_list, dst_alias_list,
                                  action, service, log_traffic, comment, label, nat, session_ttl,
                                  ippool, poolname, voip_profile, utm_status, nat_ip))
else:
    logging.critical('Could not find critical important section \'config firewall policy\'')


@dataclass
class FwServiceCategroy:
    name: str
    comment: str
    members: List[str]


fw_service_category = []
if 'service_category' in firewall_raw.keys():
    for entry in firewall_raw['service_category'][1:]:
        name = str(entry.children[0])
        if len(entry.children[1:]) != 1:
            raise RuntimeError('Unexpected number of commands')
        if entry.children[1].data != 'subcommand_field_set':
            raise RuntimeError('Unexpected type of command')
        if entry.children[1].children[0] != 'comment':
            raise RuntimeError('Unexpected set target')
        comment = entry.children[1].children[1].children[0]
        fw_service_category.append(FwServiceCategroy(str(name), str(comment), []))
else:
    logging.critical('Could not find critical important section \'config firewall service group\'')


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
if 'service_custom' in firewall_raw.keys():
    for entry in firewall_raw['service_custom'][1:]:
        skip = False
        name = str(entry.children[0])
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
                        found = False
                        for cat in fw_service_category:
                            if cat.name == category:
                                cat.members.append(name)
                                found = True
                                break
                        if not found:
                            logging.warning('category ' + category + ' could not be found in fw_service_category')
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
                        if len(tmp) == 2 and tmp[1] != '0' and tmp[1] != '0-65535':
                            logging.error(' '.join(
                                ["Unexpected port-range; skipped 'config firewall service custom':\n  CONTEXT:",
                                 str(entry)]))
                            skip = True
                            break
                        else:
                            tmp = tmp[0].split('-')
                            assert 0 < len(tmp) <= 2
                            if len(tmp) == 2:
                                tcp_range = PortRange(int(tmp[0]), int(tmp[1]))
                            else:
                                tcp_range = PortRange(int(tmp[0]), int(tmp[0]))
                    else:
                        raise RuntimeError("Encountered conflicting set command")
                elif cmd.children[0] == 'udp-portrange':
                    if udp_range is None:
                        tmp = str(cmd.children[1].children[0]).split(':')
                        assert 0 < len(tmp) <= 2
                        if len(tmp) == 2 and (tmp[1] != '0' or tmp[1] != '0-65535'):
                            logging.error(' '.join(
                                ["Skipped unexpected 'config firewall service custom':\n  CONTEXT:", str(entry)]))
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
                        logging.warning('NOT EVALUATED: config firewall service custom:', cmd.children[0],
                                        cmd.children[1:])
        if skip:
            continue
        fw_service.append(FwService(name, comment, category, protocol, icmp_type, tcp_range, udp_range, session_ttl))
else:
    logging.critical('Could not find critical important section \'config firewall service custom\'')


@dataclass
class FwServiceGroup:
    name: str
    comment: Optional[str]
    members: List[str]


fw_service_group = []
if 'service_group' in firewall_raw.keys():
    for entry in firewall_raw['service_group'][1:]:
        name = str(entry.children[0])
        comment = None
        members = []
        for cmd in entry.children[1:]:
            if cmd.children[0] == 'comment':
                if comment is None:
                    comment = str(cmd.children[1].children[0])
                else:
                    raise RuntimeError("Encountered conflicting set command")
            elif cmd.children[0] == 'member':
                if not members:
                    for val in cmd.children[1].children:
                        members.append(str(val))
                else:
                    raise RuntimeError("Encountered conflicting set command")
            else:
                if cmd.children[0] != 'color':
                    logging.warning(' '.join(
                        ['NOT EVALUATED: config firewall service group:', str(cmd.children[0]), str(cmd.children[1:])]))
        fw_service_group.append(FwServiceGroup(name, comment, members))
else:
    logging.critical('Could not find critical important section \'config firewall service group\'')


@dataclass
class DhcpServer:
    lease_time: int
    dns_server: List[IPv4Address]
    domain: Optional[str]
    netmask: Optional[IPv4Address]
    gateway: Optional[IPv4Address]
    ip_range_start: IPv4Address
    ip_range_end: IPv4Address


fw_dhcp_server = []
re_dns_server = re.compile('dns-server\d+')
if 'dhcp_server' in system_raw.keys():
    for entry in system_raw['dhcp_server'][1:]:
        lease_time = None
        dns_server = []
        domain = None
        netmask = None
        gateway = None
        ip_range_start = None
        ip_range_end = None
        for cmd in entry.children[1:]:
            if cmd.data == 'subcommand_field_set':
                if cmd.children[0] == 'lease-time':
                    lease_time = int(cmd.children[1].children[0])
                elif cmd.children[0] == 'default-gateway':
                    if gateway is None:
                        gateway = IPv4Address(cmd.children[1].children[0])
                    else:
                        raise RuntimeError("Encountered conflicting set command")
                elif cmd.children[0] == 'netmask':
                    if netmask is None:
                        netmask = IPv4Address(cmd.children[1].children[0])
                    else:
                        raise RuntimeError("Encountered conflicting set command")
                elif cmd.children[0] == 'domain':
                    if domain is None:
                        domain = str(cmd.children[1].children[0])
                    else:
                        raise RuntimeError("Encountered conflicting set command")
                elif re_dns_server.match(cmd.children[0]):
                    dns_server.append(IPv4Address(cmd.children[1].children[0]))
                else:
                    if cmd.children[0] != 'TODO':
                        logging.warning(' '.join(
                            ['NOT EVALUATED: config system dhcp server:\n  option:', str(cmd.children[0]), '\n  value:',
                             str(cmd.children[1:]), '\n  CONTEXT:', str(entry)]))
            elif cmd.data == 'subcommand_config':

                if cmd.children[0].children[0].children[0] == 'ip-range':
                    # Unnecessary because only one subentry expected
                    # for sentry in cmd.children[0].children[1:]:
                    #     for scmd in sentry.children[1:]:
                    #         print(scmd.pretty())

                    for scmd in cmd.children[0].children[1].children[1:]:
                        if scmd.children[0] == 'start-ip':
                            if ip_range_start is None:
                                ip_range_start = IPv4Address(scmd.children[1].children[0])
                            else:
                                logging.error('Parsing conflict in nested "config" statement\n  CONTEXT: ' + str(entry))
                        elif scmd.children[0] == 'end-ip':
                            if ip_range_end is None:
                                ip_range_end = IPv4Address(scmd.children[1].children[0])
                            else:
                                logging.error('Parsing conflict in nested "config" statement\n  CONTEXT: ' + str(entry))
                else:
                    logging.error('Unexpected entry in nested "config" statement\n  CONTEXT: ' + str(entry))
            else:
                raise RuntimeError("Expected 'set' command!")
        fw_dhcp_server.append(
            DhcpServer(lease_time, dns_server, domain, netmask, gateway, ip_range_start, ip_range_end))
else:
    logging.warning('Could not find section \'config system dhcp server\'')

#######################################################################################
# experimental generation of OPNsense config entries
#######################################################################################


import xml.etree.ElementTree as ET
import time


def pretty_xml(element: ET.Element, indent='  ') -> str:
    import xml.dom.minidom
    xml_str = ET.tostring(element, 'utf-8')
    dom = xml.dom.minidom.parseString(xml_str)
    return '\n'.join([line for line in dom.toprettyxml(indent=indent).split('\n') if line.strip()])


def add_xml_created_signature_to_fw_rule(element: ET.Element) -> None:
    created = ET.SubElement(element, 'created')
    ET.SubElement(created, 'username').text = 'root@fortigate-migration-tool'
    t = str(time.time()).split('.')
    ET.SubElement(created, 'time').text = '.'.join([t[0], t[1][:4]])
    ET.SubElement(created, 'description').text = 'created by the automatic fortigate-migration-tool'


doc = ET.parse("config-site-2-opnsense-1.localdomain.xml")
root = doc.getroot()

# root.find('rrddata').clear()
for x in root.findall('cert'):
    x.clear()

new_rule = ET.SubElement(root.find('filter'), 'rule')
ET.SubElement(new_rule, 'type').text = 'pass'  # 'block' 'reject'
ET.SubElement(new_rule, 'interface').text = 'wan'
ET.SubElement(new_rule, 'ipprotocol').text = 'inet'  # 'inet6'  # IPv4 or IPv6
ET.SubElement(new_rule, 'gateway').text = 'Null4'  # optional  # only if direction == in

# Keep state is used for stateful connection tracking.
# Sloppy state works like keep state, but it does not check sequence numbers. Use it when the firewall does not see all packets.
# Synproxy state proxies incoming TCP connections to help protect servers from spoofed TCP SYN floods. This option includes the functionality of keep state and modulate state combined.
# None: Do not use state mechanisms to keep track. This is only useful if you're doing advanced queueing in certain situations. Please check the documentation.
ET.SubElement(new_rule,
              'statetype').text = 'keep state'  # 'sloppy state' 'modulate state' 'synproxy state' 'none'  # optional

ET.SubElement(new_rule, 'descr').text = 'Some description'
ET.SubElement(new_rule, 'direction').text = 'in'  # 'out'
ET.SubElement(new_rule, 'disabled').text = '1'  # optional
ET.SubElement(new_rule, 'quick').text = '1'  # '0'  # Apply the action immediately on match.
ET.SubElement(new_rule, 'protocol').text = 'icmp'  # 'tcp/udp' 'udp' 'tcp' ...  # optional
ET.SubElement(new_rule, 'icmptype').text = 'echoreq'  # ...  # optional  # only if protocol == icmp

src = ET.SubElement(new_rule, 'source')
if False:
    ET.SubElement(src, 'any').text = '1'
elif True:
    ET.SubElement(src, 'address').text = '10.1.1.0/24'  # 'addr_alias' 'alias_group' ' 127.0.0.1'
else:
    ET.SubElement(src, 'network').text = 'lan'  # '(self)'
ET.SubElement(src, 'not').text = '1'  # optional  # invert match
ET.SubElement(src, 'port').text = '1234-4321'  # '22'  # optional

dst = ET.SubElement(new_rule, 'destination')  # same options as in 'source'
ET.SubElement(dst, 'any').text = '1'

add_xml_created_signature_to_fw_rule(new_rule)

with open('config_test.xml', 'w') as f:
    f.write(pretty_xml(root))
