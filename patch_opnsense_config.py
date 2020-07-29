import logging
import time
import uuid
import xml.etree.ElementTree as ET
from typing import List

from utility_dataclasses import FwData, FwDataSchema, FwNetAlias, FwNetAliasGroup, FwIPAlias


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


def _read_json_file(fw_data_json_file: str) -> FwData:
    with open(fw_data_json_file, 'r') as f:
        s = FwDataSchema()
        return s.loads(f.read())


def _add_net_aliases(config_root: ET.Element, net_alias: List[FwNetAlias]) -> None:
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


def _add_group_aliases(config_root: ET.Element, net_alias_group: List[FwNetAliasGroup]) -> None:
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


def _add_ip_aliases(config_root: ET.Element, ip_alias: List[FwIPAlias]) -> None:
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

    with open('config_test.xml', 'w') as f:
        f.write(pretty_xml(config_root))
