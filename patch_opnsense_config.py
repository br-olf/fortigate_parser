import logging
import time
import uuid
import xml.etree.ElementTree as ET
from typing import List

from utility_dataclasses import FgData, FgDataSchema, FgNetAlias, FgNetAliasGroup, FgIPAlias, \
    FgVpnIpsecPhase1, FgVpnIpsecPhase2


def patch_config(config_xml_file: str, fw_data_json_file: str, output_xml_file: str) -> None:
    pass


def pretty_xml(element: ET.Element, indent='  ') -> str:
    import xml.dom.minidom
    xml_str = ET.tostring(element, 'utf-8')
    dom = xml.dom.minidom.parseString(xml_str)
    return '\n'.join([line for line in dom.toprettyxml(indent=indent).split('\n') if line.strip()])


def _add_created_signature_to_fw_rule(element: ET.Element) -> None:
    created = ET.SubElement(element, 'created')
    ET.SubElement(created, 'username').text = 'root@fortigate-migration-tool'
    t = str(time.time()).split('.')
    ET.SubElement(created, 'time').text = '.'.join([t[0], t[1][:4]])
    ET.SubElement(created, 'description').text = 'created by automated fortigate-migration-tool'


def _read_json_file(fw_data_json_file: str) -> FgData:
    with open(fw_data_json_file, 'r') as f:
        s = FgDataSchema()
        return s.loads(f.read())


def _add_net_aliases(config_root: ET.Element, net_alias: List[FgNetAlias]) -> None:
    for fw_alias in net_alias:
        new_alias = ET.SubElement(config_root.find('OPNsense').find('Firewall').find('Alias').find('aliases'), 'alias')
        new_alias.set('uuid', str(uuid.uuid4()))
        ET.SubElement(new_alias, 'enabled').text = '1'
        ET.SubElement(new_alias, 'name').text = fw_alias.name
        ET.SubElement(new_alias, 'proto')
        ET.SubElement(new_alias, 'description').text = fw_alias.comment
        ET.SubElement(new_alias, 'counters').text = '0'
        ET.SubElement(new_alias, 'updatefreq')
        if fw_alias.fqdn is not None:
            ET.SubElement(new_alias, 'type').text = 'host'
            ET.SubElement(new_alias, 'content').text = fw_alias.fqdn
        elif fw_alias.net_list is not None and len(fw_alias.net_list) > 0:
            ET.SubElement(new_alias, 'type').text = 'network'
            ET.SubElement(new_alias, 'content').text = '\n'.join([x.exploded for x in fw_alias.net_list])


def _add_group_aliases(config_root: ET.Element, net_alias_group: List[FgNetAliasGroup]) -> None:
    for fw_alias_group in net_alias_group:
        new_alias = ET.SubElement(config_root.find('OPNsense').find('Firewall').find('Alias').find('aliases'), 'alias')
        new_alias.set('uuid', str(uuid.uuid4()))
        ET.SubElement(new_alias, 'enabled').text = '1'
        ET.SubElement(new_alias, 'name').text = fw_alias_group.name
        ET.SubElement(new_alias, 'proto')
        ET.SubElement(new_alias, 'description').text = fw_alias_group.comment
        ET.SubElement(new_alias, 'counters').text = '0'
        ET.SubElement(new_alias, 'updatefreq')
        ET.SubElement(new_alias, 'type').text = 'networkgroup'
        ET.SubElement(new_alias, 'content').text = '\n'.join(fw_alias_group.net_alias_list)


def _add_ip_aliases(config_root: ET.Element, ip_alias: List[FgIPAlias]) -> None:
    for fw_ip_alias in ip_alias:
        new_alias = ET.SubElement(config_root.find('OPNsense').find('Firewall').find('Alias').find('aliases'), 'alias')
        new_alias.set('uuid', str(uuid.uuid4()))
        ET.SubElement(new_alias, 'enabled').text = '1'
        ET.SubElement(new_alias, 'name').text = fw_ip_alias.name
        ET.SubElement(new_alias, 'proto')
        ET.SubElement(new_alias, 'description').text = fw_ip_alias.comment
        ET.SubElement(new_alias, 'counters').text = '0'
        ET.SubElement(new_alias, 'updatefreq')
        ET.SubElement(new_alias, 'type').text = 'host'
        ET.SubElement(new_alias, 'content').text = fw_ip_alias.ip.exploded


def _add_ipsec_phase2(config_root: ET.Element, ipsec_phase_2: List[FgVpnIpsecPhase2]) -> None:
    for phase2 in ipsec_phase_2:
        new_phase2 = ET.SubElement(config_root.find('OPNsense').find('ipsec'), 'phase2')
        ET.SubElement(new_phase2, 'ikeid').text = _find_ikeid(phase2.phase1name)
        ET.SubElement(new_phase2, 'uniqid').text = uuid.uuid4().hex[:13]
        ET.SubElement(new_phase2, 'mode').text = 'tunnel'
        ET.SubElement(new_phase2, 'lifetime').text = str(phase2.keylife)
        ET.SubElement(new_phase2, 'descr').text = phase2.name
        ET.SubElement(new_phase2, 'protocol').text = 'esp'
        # TODO: localid remoteid encryption-algorithm-option hash-algorithm-option


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")

    config_xml_file = 'config-site-2-opnsense-1.localdomain.xml'
    fw_data_json_file = "FwData.json"
    output_xml_file = 'config_test.xml'

    # patch_config(config_xml_file,fw_data_json_file,output_xml_file)

    config_root = ET.parse(config_xml_file).getroot()
    fw_data = _read_json_file(fw_data_json_file)

    _add_net_aliases(config_root, fw_data.net_alias)
    _add_group_aliases(config_root, fw_data.net_alias_group)
    _add_ip_aliases(config_root, fw_data.ip_alias)

    # for policy in
    # new_rule = ET.SubElement(config_root.find('filter'), 'rule')
    # ET.SubElement(new_rule, 'type').text =

    with open('config_test.xml', 'w') as f:
        f.write(pretty_xml(config_root))
