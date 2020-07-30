import time
import xml.etree.ElementTree as ET

from utility_dataclasses import *


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


if False:
    doc = ET.parse("config-site-2-opnsense-1.localdomain.xml")
    root = doc.getroot()

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
    with open("FwData.json", 'r') as f:
        s = FgDataSchema()
        fw_data = s.loads(f.read())

    if False:
        from fortigate_extractor import to_cname


        def lookup_alias(name) -> bool:
            for x in fw_data.net_alias_group:
                if x.name == name:
                    return True
            for x in fw_data.net_alias:
                if x.name == name:
                    return True
            for x in fw_data.ip_alias:
                if x.name == name:
                    return True
            return False


        count = 0
        for policy in fw_data.policy:
            src = to_cname(policy.src_interface)
            if not lookup_alias(src):
                print('src:', src, '- not found')
                count += 1
            dst = to_cname(policy.dst_interface)
            if not lookup_alias(dst):
                print('dst:', dst, '- not found')
                count += 1
        print('\ndid not found', count, 'out of', len(fw_data.policy) * 2, 'interfaces')

    if True:
        dst_set = set()
        src_set = set()
        for policy in fw_data.policy:
            dst_set.add(str(policy.dst_interface))
            src_set.add(str(policy.src_interface))

        print('Used source interfaces:\n', src_set)
        print('Used destination interfaces:\n', dst_set)
