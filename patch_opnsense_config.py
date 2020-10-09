import logging
import time
import uuid
import base64
import xml.etree.ElementTree as ET
from typing import List

from utility_dataclasses import FgData, FgDataSchema, FgNetAlias, FgNetAliasGroup, FgIPAlias, \
    FgVpnIpsecPhase1, FgVpnIpsecPhase2, FgVpnCertCa


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
        else:
            error_str = 'Nighter FgNetAlias.fqdn nor FgNetAlias.net_list are set in alias "{}".'.format(fw_alias.name)
            logging.fatal(error_str)
            raise ValueError(error_str)


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


def _find_ipsec_phase1_ikeid(config_root: ET.Element, phase1name: str) -> str:
    try:
        for phase1 in config_root.find('ipsec').findall('phase1'):
            try:
                if phase1.find('descr').text.startswith(phase1name):
                    return phase1.find('ikeid').text
            except AttributeError as err:
                error_str = 'Encountered invalid <phase1> entry in <"config_root" -> ipsec>: {}'.format(err)
                logging.fatal(error_str)
                raise RuntimeError(error_str)
    except AttributeError as err:
        error_str = 'Could not find <ipsec -> phase1> in "config_root": {}'.format(err)
        logging.fatal(error_str)
        raise RuntimeError(error_str)

    error_str = 'Could not find phase1name "{}" in <"config_root" -> ipsec -> phase1>!'.format(phase1name)
    logging.error(error_str)
    raise ValueError(error_str)

def _get_next_ipsec_phase1_ikeid(config_root: ET.Element) -> int:
    max_ikeid = 0
    try:
        for phase1 in config_root.find('ipsec').findall('phase1'):
            ikeid = int(phase1.find('ikeid').text)
            if ikeid > max_ikeid:
                max_ikeid = ikeid
    except AttributeError as err:
        logging.info('Could not find <ipsec -> phase1> in "config_root": {}'.format(err))
    return max_ikeid + 1

def _add_ipsec_phase1(config_root: ET.Element, ipsec_phase_1: List[FgVpnIpsecPhase1]) -> None:
    if config_root.find('ipsec') is None:
        ET.SubElement(config_root, 'ipsec')

    for phase1 in ipsec_phase_1:
        if phase1.xauthtype is not None or phase1.authusrgrp is not None or phase1.remote_gw is None:
            logging.error(
                'Could not migrate ipsec phase1 configuration "{}"! Automatic XAuth migration is not possible!'.format(phase1.name))
            continue

        ikeid = str(_get_next_ipsec_phase1_ikeid(config_root))  # Do this before creating new node to suppress errors
        new_phase1 = ET.SubElement(config_root.find('ipsec'), 'phase1')
        ET.SubElement(new_phase1, 'descr').text = '{} -> {}'.format(phase1.name, phase1.comment)
        ET.SubElement(new_phase1, 'ikeid').text = ikeid
        ET.SubElement(new_phase1, 'iketype').text = 'ike'
        ET.SubElement(new_phase1, 'interface').text = phase1.interface
        ET.SubElement(new_phase1, 'protocol').text = 'inet'
        ET.SubElement(new_phase1, 'lifetime').text = str(phase1.keylife)
        ET.SubElement(new_phase1, 'pre-shared-key').text = phase1.psksecret
        ET.SubElement(new_phase1, 'private-key')
        ET.SubElement(new_phase1, 'authentication_method').text = 'pre_shared_key'
        ET.SubElement(new_phase1, 'dhgroup').text = ','.join([str(x) for x in phase1.dhgrp])
        ET.SubElement(new_phase1, 'remote-gateway').text = phase1.remote_gw.exploded
        ET.SubElement(new_phase1, 'nat_traversal').text = 'on' if phase1.nattraversal else 'off'

        if phase1.connect_type == 'static':
            pass  # this is the default
        elif phase1.connect_type == 'dynamic':  # allow gateway to be on a dynamic IP
            ET.SubElement(new_phase1, 'rightallowany').text = 1
        else:
            error_str = 'Encountered an unexpected FgVpnIpsecPhase1.connect_type: {}'.format(phase1.connect_type)
            logging.error(error_str)
            raise NotImplementedError(error_str)

        if phase1.dpd:
            ET.SubElement(new_phase1, 'dpd_maxfail').text = '3'
            ET.SubElement(new_phase1, 'dpd_delay').text = '5'
            ET.SubElement(new_phase1, 'dpd_action').text = 'restart'

        enc_str = None
        for c_prop in phase1.c_proposal:
            se_enc_alg = ET.SubElement(new_phase1, 'encryption-algorithm')
            skip_enc_alg = False

            if enc_str is None:
                enc_str = c_prop.encrypt
            elif enc_str != c_prop.encrypt:
                error_str = 'OPNsense ipsec phase1 configuration only allows one encryption algorithm specification! '
                error_str += 'Already configured "{}" conflicts "{}".\n   SKIPPED: '.format(enc_str, c_prop.encrypt)
                error_str += '"{}" remains the only possible encryption algorithm for FgVpnIpsecPhase1 "{}"'.format(enc_str, phase1.name)
                logging.error(error_str)
                skip_enc_alg = True

            if not skip_enc_alg:
                if enc_str.startswith('aes'):
                    ET.SubElement(se_enc_alg, 'name').text = 'aes'
                    keybits = int(enc_str[3:])
                    ET.SubElement(se_enc_alg, 'keylen').text = str(keybits)
                elif enc_str == '3des':
                    logging.warning('Insecure encryption algorithm "{}" in FgVpnIpsecPhase1 "{}" encountered.'.format(enc_str, phase1.name))
                    ET.SubElement(se_enc_alg, 'name').text = '3des'
                else:
                    error_str = 'Unsupported or insecure encryption algorithm "{}" in FgVpnIpsecPhase1 "{}" encountered.'.format(enc_str, phase1.name)
                    logging.fatal(error_str)
                    raise NotImplementedError(error_str)

            if new_phase1.find('hash-algorithm') is None:
                hash_alg_str = ''
            else:
                hash_alg_str = new_phase1.find('hash-algorithm').text + ','

            if c_prop.digest.startswith('sha'):
                ET.SubElement(new_phase1, 'hash-algorithm').text = hash_alg_str + c_prop.digest
            elif c_prop.digest == 'md5':
                logging.warning('Insecure digest algorithm "{}" in FgVpnIpsecPhase1 "{}" encountered.'.format(c_prop.digest, phase1.name))
                ET.SubElement(new_phase1, 'hash-algorithm').text = hash_alg_str + c_prop.digest
            else:
                error_str = 'Unsupported or insecure digest algorithm "{}" in FgVpnIpsecPhase1 "{}" encountered.'.format(c_prop.digest, phase1.name)
                logging.fatal(error_str)
                raise NotImplementedError(error_str)


def _add_ipsec_phase2(config_root: ET.Element, ipsec_phase_2: List[FgVpnIpsecPhase2]) -> None:
    for phase2 in ipsec_phase_2:
        try:
            ikeid = _find_ipsec_phase1_ikeid(config_root, phase2.phase1name)
        except ValueError:
            logging.error('Could not create configuration for ipsec phase2 "{}"! Matching phase1 entry is missing.'.format(phase2.name))
            continue
        new_phase2 = ET.SubElement(config_root.find('ipsec'), 'phase2')
        ET.SubElement(new_phase2, 'ikeid').text = ikeid
        ET.SubElement(new_phase2, 'uniqid').text = uuid.uuid4().hex[:13]
        ET.SubElement(new_phase2, 'mode').text = 'tunnel'
        ET.SubElement(new_phase2, 'lifetime').text = str(phase2.keylife)
        ET.SubElement(new_phase2, 'descr').text = phase2.name
        ET.SubElement(new_phase2, 'protocol').text = 'esp'

        se_localid = ET.SubElement(new_phase2, 'localid')
        if phase2.src_addr_type == 'ip':
            ET.SubElement(se_localid, 'type').text = 'address'
            ET.SubElement(se_localid, 'address').text = phase2.src_ip.exploded
        elif phase2.src_addr_type == 'net':
            ET.SubElement(se_localid, 'type').text = 'network'
            ip = phase2.src_net.with_prefixlen.split('/')
            assert len(ip) == 2
            ET.SubElement(se_localid, 'address').text = ip[0]
            ET.SubElement(se_localid, 'netbits').text = ip[1]
        else:
            error_str = 'Encountered unexpected FgVpnIpsecPhase2.src_addr_type value: {}'.format(phase2.dst_addr_type)
            logging.fatal(error_str)
            raise NotImplementedError(error_str)

        se_remoteid = ET.SubElement(new_phase2, 'remoteid')
        if phase2.dst_addr_type == 'ip':
            ET.SubElement(se_remoteid, 'type').text = 'address'
            ET.SubElement(se_remoteid, 'address').text = phase2.dst_ip.exploded
        elif phase2.dst_addr_type == 'net':
            ET.SubElement(se_remoteid, 'type').text = 'network'
            ip = phase2.dst_net.with_prefixlen.split('/')
            assert len(ip) == 2
            ET.SubElement(se_remoteid, 'address').text = ip[0]
            ET.SubElement(se_remoteid, 'netbits').text = ip[1]
        else:
            error_str = 'Encountered unexpected FgVpnIpsecPhase2.dst_addr_type value: {}'.format(phase2.dst_addr_type)
            logging.fatal(error_str)
            raise NotImplementedError(error_str)

        for c_prop in phase2.c_proposal:

            skip_enc_alg = False
            for c in new_phase2.findall('encryption-algorithm-option'):
                if (c.find('name').text == '3des' and c_prop.encrypt == '3des') or \
                   (c.find('name').text == 'aes' and c_prop.encrypt.startswith('aes') and c.find('keylen').text == c_prop.encrypt[3:]):
                    skip_enc_alg = True
                    break
            if not skip_enc_alg:
                se_enc_alg = ET.SubElement(new_phase2, 'encryption-algorithm-option')
                enc_str = c_prop.encrypt
                if enc_str.startswith('aes'):
                    ET.SubElement(se_enc_alg, 'name').text = 'aes'
                    keybits = int(enc_str[3:])
                    ET.SubElement(se_enc_alg, 'keylen').text = str(keybits)
                elif enc_str == '3des':
                    logging.warning('Insecure encryption algorithm "{}" in FgVpnIpsecPhase2 "{}" encountered.'.format(enc_str, phase2.name))
                    ET.SubElement(se_enc_alg, 'name').text = '3des'
                else:
                    error_str = 'Unsupported or insecure encryption algorithm "{}" in FgVpnIpsecPhase2 "{}" encountered.'.format(enc_str, phase2.name)
                    logging.fatal(error_str)
                    raise NotImplementedError(error_str)

            skip_digest = False
            for h in new_phase2.findall('hash-algorithm-option'):
                if h.text == 'hmac_{}'.format(c_prop.digest):  # Skipps duplicates
                    skip_digest = True
                    break
            if not skip_digest:
                if c_prop.digest.startswith('sha'):
                    ET.SubElement(new_phase2, 'hash-algorithm-option').text = 'hmac_{}'.format(c_prop.digest)
                elif c_prop.digest == 'md5':
                    logging.warning('Insecure digest algorithm "{}" in FgVpnIpsecPhase2 "{}" encountered.'.format(c_prop.digest, phase2.name))
                    ET.SubElement(new_phase2, 'hash-algorithm-option').text = 'hmac_{}'.format(c_prop.digest)
                else:
                    error_str = 'Unsupported or insecure digest algorithm "{}" in FgVpnIpsecPhase2 "{}" encountered.'.format(c_prop.digest, phase2.name)
                    logging.fatal(error_str)
                    raise NotImplementedError(error_str)


def _add_ca_certs(config_root: ET.Element, vpn_cert_ca: List[FgVpnCertCa]) -> None:
    for ca in vpn_cert_ca:
        skip_cert = False
        for c in config_root.findall('ca'):
            if c.find('descr').text == ca.name:
                skip_cert = True
                break
        if not skip_cert:
            new_ca = ET.SubElement(config_root, 'ca')
            ET.SubElement(new_ca, 'refid').text = uuid.uuid4().hex[:13]
            ET.SubElement(new_ca, 'descr').text = ca.name
            ET.SubElement(new_ca, 'serial').text = '0'
            ET.SubElement(new_ca, 'crt').text = base64.b64encode(ca.cert.encode('utf-8')).decode('utf-8')
            # ET.SubElement(new_ca, 'crt').text


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")

    config_xml_file = 'config-site-1-opnsense-1.localdomain.xml'
    fw_data_json_file = "FwData.json"
    output_xml_file = 'config_test.xml'

    # patch_config(config_xml_file,fw_data_json_file,output_xml_file)

    config_root = ET.parse(config_xml_file).getroot()
    fw_data = _read_json_file(fw_data_json_file)

    _add_net_aliases(config_root, fw_data.net_alias)
    _add_group_aliases(config_root, fw_data.net_alias_group)
    _add_ip_aliases(config_root, fw_data.ip_alias)
    _add_ipsec_phase1(config_root, fw_data.vpn_ipsec_phase_1)
    _add_ipsec_phase2(config_root, fw_data.vpn_ipsec_phase_2)
    _add_ca_certs(config_root, fw_data.vpn_cert_ca)

    # for policy in
    # new_rule = ET.SubElement(config_root.find('filter'), 'rule')
    # ET.SubElement(new_rule, 'type').text =

    with open('config_test.xml', 'w') as f:
        f.write(pretty_xml(config_root))
