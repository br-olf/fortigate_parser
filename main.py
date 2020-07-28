import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional, Union, Tuple


#######################################################################################
# experimental generation of OPNsense config entries
#######################################################################################


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

if False:
    # root.find('rrddata').clear()
    for x in root.findall('cert'):
        x.clear()

from enum import Enum


class NoValue(Enum):
    def __repr__(self):
        return '<%s.%s>' % (self.__class__.__name__, self.name)


class FwRuleType(NoValue):
    PASS = 'pass'
    REJECT = 'reject'
    BLOCK = 'block'


class FwIpProtocol(NoValue):
    IPv4 = 'inet'
    IPv6 = 'inet6'
    IPv46 = 'inet46'


class FwDirection(NoValue):
    IN = 'in'
    OUT = 'out'


@dataclass(init=False)
class FwTarget:
    _any: Optional[bool] = None
    _invert: Optional[bool] = None
    _address: Optional[str] = None
    _network: Optional[str] = None
    _port: Optional[int] = None
    _portrange: Optional[Tuple[int, int]] = None

    @classmethod
    def _set_port(cls, port: Optional[Union[tuple, int]]):
        if port is None:
            cls._port = None
            return cls
        elif isinstance(port, int):
            cls._port = port
            return cls
        elif isinstance(port, tuple) and len(port) == 2 and type(port[0]) == int and type(port[1]) == int and 0 <= port[
            0] < port[1]:
            cls._portrange = port
            return cls
        else:
            raise ValueError('Invalid port argument!')

    @classmethod
    def any(cls, invert: Optional[bool] = None, port: Optional[Union[tuple, int]] = None):
        cls._any = True
        cls._invert = invert
        return cls._set_port(port)()

    @classmethod
    def network(cls, network: str, invert: Optional[bool] = None, port: Optional[Union[tuple, int]] = None):
        cls._network = network
        cls._invert = invert
        return cls._set_port(port)()

    @classmethod
    def address(cls, address: str, invert: Optional[bool] = None, port: Optional[Union[tuple, int]] = None):
        cls._address = address
        cls._invert = invert
        return cls._set_port(port)()


def create_opnsense_firewall_rule(xml_root_element: ET.Element, type: FwRuleType, interface: str,
                                  ip_protocol: FwIpProtocol, description: str, direction: FwDirection,
                                  source: FwTarget, destination: FwTarget, TODO):
    # TODO
    pass


if True:
    #########################################
    # New Firewall rule
    new_rule = ET.SubElement(root.find('filter'), 'rule')
    ET.SubElement(new_rule, 'type').text = 'pass'  # 'block' 'reject'
    ET.SubElement(new_rule, 'interface').text = 'wan'
    ET.SubElement(new_rule, 'ipprotocol').text = 'inet'  # 'inet6'  # IPv4 or IPv6
    ET.SubElement(new_rule, 'gateway').text = '1.2.3.4'  # optional  # only if direction == in

    # Keep state is used for stateful connection tracking.
    # Sloppy state works like keep state, but it does not check sequence numbers. Use it when the firewall does not see all packets.
    # Synproxy state proxies incoming TCP connections to help protect servers from spoofed TCP SYN floods. This option includes the functionality of keep state and modulate state combined.
    # None: Do not use state mechanisms to keep track. This is only useful if you're doing advanced queueing in certain situations. Please check the documentation.
    ET.SubElement(new_rule,
                  'statetype').text = 'keep state'  # 'sloppy state' 'modulate state' 'synproxy state' 'none'  # optional

    ET.SubElement(new_rule, 'descr').text = 'generated rule'
    ET.SubElement(new_rule, 'direction').text = 'in'  # 'out'
    ET.SubElement(new_rule, 'category').text = 'a_category'  # optional
    ET.SubElement(new_rule, 'floating').text = 'yes'  # optional
    ET.SubElement(new_rule, 'disabled').text = '1'  # optional
    ET.SubElement(new_rule, 'quick').text = '1'  # '0'  # Apply the action immediately on match.
    if False:
        ET.SubElement(new_rule, 'protocol').text = 'icmp'  # 'tcp/udp' 'udp' 'tcp' ...  # optional
        ET.SubElement(new_rule, 'icmptype').text = 'echoreq'  # ...  # optional  # only if protocol == icmp

    src = ET.SubElement(new_rule, 'source')
    if True:
        ET.SubElement(src, 'any').text = '1'
    elif False:
        ET.SubElement(src, 'address').text = '10.1.1.0/24'  # 'addr_alias' 'alias_group' ' 127.0.0.1'
    else:
        ET.SubElement(src, 'network').text = 'lan'  # '(self)'
    ET.SubElement(src, 'not').text = '1'  # optional  # invert match
    if False:
        ET.SubElement(src, 'port').text = '1234-4321'  # '22'  # optional

    dst = ET.SubElement(new_rule, 'destination')  # same options as in 'source'
    ET.SubElement(dst, 'network').text = '(self)'

    add_xml_created_signature_to_fw_rule(new_rule)

if True:
    ##################################################
    # New Alias
    import uuid

    new_alias = ET.SubElement(root.find('OPNsense').find('Firewall').find('Alias').find('aliases'), 'alias')
    new_alias.set('uuid', str(uuid.uuid4()))
    ET.SubElement(new_alias, 'enabled').text = '1'
    ET.SubElement(new_alias, 'name').text = 'another_alias'
    ET.SubElement(new_alias, 'type').text = 'host'  # 'network' 'networkgroup' 'urltable' 'port' 'url'
    ET.SubElement(new_alias, 'proto')
    ET.SubElement(new_alias, 'counters').text = '0'
    ET.SubElement(new_alias, 'updatefreq')  # or .text = refresh interval in days
    ET.SubElement(new_alias, 'content').text = '127.0.0.0/24\ntest'
    ET.SubElement(new_alias, 'description').text = 'can also be a group'

    ### json:
    # "04090139-d735-43c3-810c-0834e558986c": {
    #     "enabled": "1",
    #     "name": "external",
    #     "type": "external",
    #     "proto": "",
    #     "counters": "0",
    #     "updatefreq": "",
    #     "content": "",
    #     "description": "a test "
    # }

    new_alias_json = {str(uuid.uuid4()): {"enabled:": "1",
                                          "name": "another_alias",
                                          "type": "host",
                                          "proto": "",
                                          "counters": "0",
                                          "updatefreq": "",
                                          "content": "www.youtube.com",
                                          "description": "a test "}}
    import json

    with open('aliases.json', 'r') as f:
        old = json.loads(f.read())
    old["aliases"]["alias"].update(new_alias_json)
    with open('aliases2.json', 'w') as f:
        f.write(json.dumps(old, indent=2))

with open('config_test.xml', 'w') as f:
    f.write(pretty_xml(root))
