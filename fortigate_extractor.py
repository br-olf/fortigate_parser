import logging
import re
from ipaddress import IPv4Network, IPv4Address, IPv4Interface, summarize_address_range

from lark import Lark, Tree

from utility_dataclasses import FgData, FgPolicy, FgService, FgServiceCategory, FgServiceGroup, FgDhcpServer, \
    FgNetAlias, FgNetAliasGroup, FgIPAlias, FgDataSchema, PortRange, FgInterface, FgVpnCertCa, FgVpnCertLocal, \
    FgVpnIpsecPhase1, FgIpsecCryptoParams

_regex_cname = re.compile('^[a-zA-Z0-9_]+$')


def to_cname(name) -> str:
    """Ensures output is a string containing only characters from [a-zA-Z0-9_]"""
    n = str(name).strip('\'" \t')
    if _regex_cname.match(n):
        return n
    else:
        c1 = n.replace(',', '_').replace('.', '_').replace('-', '_')
        c1 = c1.replace('ü', 'ue').replace('ö', 'oe').replace('ä', 'ae').replace('ß', 'ss')
        c1 = c1.replace('Ü', 'Ue').replace('Ö', 'Oe').replace('Ä', 'Ae')
        if _regex_cname.match(c1):
            return c1
        else:
            c2 = ''
            for char in c1:
                if _regex_cname.match(char):
                    c2 += char
                else:
                    c2 += '_'
            return c2


def _extraction_stage_1(parsed_conf: Tree):
    """Extract relevant configuration pieces"""

    logging.info('Extraction of relevant fortigate configurations started')
    firewall_raw = {}
    system_raw = {}
    vpn_raw = {}
    for config in parsed_conf.children:
        if config.data == 'config':
            config_branch = config.children[0].children
        elif config.data == 'config_branch':
            config_branch = config.children
        else:
            raise RuntimeError('invalid parse tree')

        if config_branch[0] == 'system':
            if config_branch[1] == 'dhcp' and config_branch[2] == 'server':
                if 'dhcp_server' not in system_raw.keys():
                    system_raw['dhcp_server'] = config.children
                else:
                    logging.error('config "system dhcp server" should only be present once')
            if config_branch[1] == 'interface':
                if 'interface' not in system_raw.keys():
                    system_raw['interface'] = config.children
                else:
                    logging.error('config "system interface" should only be present once')

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

        if config_branch[0] == 'vpn':
            if config_branch[1] == 'certificate' and config_branch[2] == 'ca':
                if 'certificate_ca' not in vpn_raw.keys():
                    vpn_raw['certificate_ca'] = config.children
                else:
                    logging.error('config "vpn certificate ca" should only be present once')
            elif config_branch[1] == 'certificate' and config_branch[2] == 'local':
                if 'certificate_local' not in vpn_raw.keys():
                    vpn_raw['certificate_local'] = config.children
                else:
                    logging.error('config "vpn certificate local" should only be present once')
            elif config_branch[1] == 'ipsec' and config_branch[2] == 'phase1-interface':
                if 'ipsec_phase1' not in vpn_raw.keys():
                    vpn_raw['ipsec_phase1'] = config.children
                else:
                    logging.error('config "vpn ipsec phase1-interface" should only be present once')
            elif config_branch[1] == 'ipsec' and config_branch[2] == 'phase2-interface':
                if 'ipsec_phase2' not in vpn_raw.keys():
                    vpn_raw['ipsec_phase2'] = config.children
                else:
                    logging.error('config "vpn ipsec phase2-interface" should only be present once')
            elif config_branch[1] == 'ipsec' and config_branch[2] == 'forticlient':
                if 'ipsec_forticlient' not in vpn_raw.keys():
                    vpn_raw['ipsec_forticlient'] = config.children
                else:
                    logging.error('config "vpn ipsec forticlient" should only be present once')
            elif config_branch[1] == 'ssl' and config_branch[2] == 'settings':
                if 'ssl_settings' not in vpn_raw.keys():
                    vpn_raw['ssl_settings'] = config.children
                else:
                    logging.error('config "vpn ssl settings" should only be present once')

    logging.info('Extraction of relevant fortigate configurations finished')
    return firewall_raw, system_raw, vpn_raw


# noinspection PyUnresolvedReferences,DuplicatedCode
def _extraction_stage_2(firewall_raw: dict, system_raw: dict, vpn_raw: dict) -> FgData:
    """Converts useful information to dataclasses"""

    fw_data = FgData()

    logging.info('Extraction of "config vpn ipsec phase1-interface" started')

    if 'ipsec_phase1' in vpn_raw.keys():
        for entry in vpn_raw['ipsec_phase1'][1:]:
            name = to_cname(entry.children[0])
            comment = ''
            interface = None
            dpd = True
            nattraversal = True
            dhgrp = []
            c_proposal = []
            remote_gw = None
            psksecret = None
            keylife = 86400
            connect_type = 'static'
            xauthtype = None
            authusrgrp = None

            for cmd in entry.children[1:]:
                if cmd.data == 'subcommand_field_set':
                    if cmd.children[0] == 'comments':
                        comment = str(cmd.children[1].children[0]).strip('"')
                    elif cmd.children[0] == 'interface':
                        if interface is None:
                            interface = str(cmd.children[1].children[0]).strip('"')
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'psksecret':
                        if psksecret is None:
                            psksecret = str(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'keylife':
                        keylife = int(cmd.children[1].children[0])
                    elif cmd.children[0] == 'type':
                        connect_type = str(cmd.children[1].children[0])
                    elif cmd.children[0] == 'xauthtype':
                        if xauthtype is None:
                            xauthtype = str(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'authusrgrp':
                        if authusrgrp is None:
                            authusrgrp = str(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'remote-gw':
                        if remote_gw is None:
                            remote_gw = IPv4Address(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'proposal':
                        if len(c_proposal) == 0:
                            for n in cmd.children[1].children:
                                e, d = str(n).split('-')
                                c_proposal.append(FgIpsecCryptoParams(e, d))
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'dhgrp':
                        if len(dhgrp) == 0:
                            for n in cmd.children[1].children:
                                n_int = int(n)
                                assert n_int > 0
                                dhgrp.append(n_int)
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'dpd':
                        dpd_str = str(cmd.children[1].children[0])
                        if dpd_str == 'disable':
                            dpd = False
                        elif dpd_str == 'enable':
                            dpd = True
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ': Encountered unexpected value in "set dpd" "{}"'.format(dpd_str))
                    elif cmd.children[0] == 'nattraversal':
                        nattraversal_str = str(cmd.children[1].children[0])
                        if nattraversal_str == 'disable':
                            nattraversal = False
                        elif nattraversal_str == 'enable':
                            nattraversal = True
                        else:
                            raise RuntimeError('line ' + str(
                                cmd.line) + ': Encountered unexpected value in "set dpd" "{}"'.format(nattraversal_str))
                    else:
                        if cmd.children[0] != 'keepalive':
                            logging.warning(' '.join(
                                ['line', str(cmd.line) + ': NOT EVALUATED: config vpn ipsec phase1-interface:\n  option:',
                                 str(cmd.children[0]), '\n  value:',
                                 str(cmd.children[1:]), '\n  CONTEXT:', str(entry)]))
                else:
                    raise RuntimeError("Expected 'set' or 'config' command!")
            assert 172800 > keylife > 120
            # remote_gw is optional
            if interface is None or dpd is None or nattraversal is None or psksecret is None \
                    or len(dhgrp) == 0 or len(c_proposal) == 0:
                raise RuntimeError('line ' + str(entry.line) + ":Incompletely parsed record")
            fw_data.vpn_ipsec_phase_1.append(FgVpnIpsecPhase1(name, comment, interface, dpd, nattraversal, dhgrp,
                                                              c_proposal, remote_gw, psksecret, keylife,
                                                              connect_type, xauthtype, authusrgrp))
    else:
        logging.warning('Could not find section \'config vpn ipsec phase1-interface\'')

    logging.info('Extraction of "config vpn ipsec phase1-interface" finished')

    #######################################################################################
    logging.info('Extraction of "config vpn certificate local" started')

    if 'certificate_local' in vpn_raw.keys():
        for entry in vpn_raw['certificate_local'][1:]:
            name = to_cname(entry.children[0])
            comment = ''
            cert = None
            private_key = None
            password = None

            for cmd in entry.children[1:]:
                if cmd.data == 'subcommand_field_set':
                    if cmd.children[0] == 'comments':
                        comment = str(cmd.children[1].children[0]).strip('"')
                    elif cmd.children[0] == 'certificate':
                        if cert is None:
                            cert = str(cmd.children[1].children[0]).strip('"')
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'private-key':
                        if private_key is None:
                            private_key = str(cmd.children[1].children[0]).strip('"')
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'password':
                        if password is None:
                            password = str(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    else:
                        if cmd.children[0] != 'TODO':
                            logging.warning(' '.join(
                                ['line', str(cmd.line) + ': NOT EVALUATED: config vpn certificate local:\n  option:',
                                 str(cmd.children[0]), '\n  value:',
                                 str(cmd.children[1:]), '\n  CONTEXT:', str(entry)]))
                else:
                    raise RuntimeError("Expected 'set' or 'config' command!")

            if cert is None or private_key is None or password is None:
                raise RuntimeError('line ' + str(entry.line) + ":Incompletely parsed record")
            fw_data.vpn_cert_local.append(FgVpnCertLocal(name, comment, cert, private_key, password))
    else:
        logging.warning('Could not find section \'config vpn certificate local\'')

    logging.info('Extraction of "config vpn certificate local" finished')

    #######################################################################################
    if 'certificate_ca' in vpn_raw.keys():
        for entry in vpn_raw['certificate_ca'][1:]:
            name = to_cname(entry.children[0])
            cert = None

            for cmd in entry.children[1:]:
                if cmd.data == 'subcommand_field_set':
                    if cmd.children[0] == 'ca':
                        if cert is None:
                            cert = str(cmd.children[1].children[0]).strip('"')
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    else:
                        if cmd.children[0] != 'TODO':
                            logging.warning(' '.join(
                                ['line', str(cmd.line) + ': NOT EVALUATED: config vpn certificate ca:\n  option:',
                                 str(cmd.children[0]), '\n  value:',
                                 str(cmd.children[1:]), '\n  CONTEXT:', str(entry)]))
                else:
                    raise RuntimeError("Expected 'set' or 'config' command!")

            if cert is None:
                raise RuntimeError('line ' + str(entry.line) + ":Incompletely parsed record")
            fw_data.vpn_cert_ca.append(FgVpnCertCa(name, cert))
    else:
        logging.warning('Could not find section \'config vpn certificate ca\'')

    logging.info('Extraction of "config vpn certificate ca" finished')

    #######################################################################################
    logging.info('Extraction of "config firewall address" started')
    if 'address' in firewall_raw.keys():
        for entry in firewall_raw['address'][1:]:
            name = to_cname(entry.children[0])
            ip = []
            ip_s = None
            fqdn = None
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
                        comment = str(cmd.children[1].children[0]).strip('"')
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
                    elif cmd.children[0] == 'fqdn':
                        if fqdn is None:
                            fqdn = cmd.children[1].children[0].strip('"')
                        else:
                            raise RuntimeError("Double \"fqdn\"")
                    else:
                        if cmd.children[0] != 'color' and cmd.children[0] != 'uuid' and cmd.children[0] != 'type':
                            logging.warning(' '.join(
                                ['line', str(cmd.line) + ': NOT EVALUATED: config firewall address:\n  option:',
                                 str(cmd.children[0]), '\n  value:',
                                 str(cmd.children[1:]), '\n  CONTEXT:', str(entry)]))
                else:
                    raise RuntimeError('line ' + str(cmd.line) + ": Expected 'set' command!")
            if not ip:
                ip = None
            if ip is None and fqdn is None:
                logging.error(' '.join(
                    ["line", str(entry.line) + ": Skipped incomplete/unparseable 'config firewall address':",
                     "missing 'subnet' or 'fqdn' or 'start-ip'/'end-ip':\n  CONTEXT:", str(entry)]))
                continue

            fw_data.net_alias.append(FgNetAlias(str(name), str(comment), ip, fqdn))
    else:
        logging.critical('Could not find critical important section \'config firewall address\'')

    logging.info('Extraction of "config firewall address" finished')

    #######################################################################################
    logging.info('Extraction of "config firewall addrgrp" started')
    if 'addrgrp' in firewall_raw.keys():
        for entry in firewall_raw['addrgrp'][1:]:
            name = to_cname(entry.children[0])
            address_keys = []
            comment = ''
            for cmd in entry.children[1:]:
                if cmd.data == 'subcommand_field_set':
                    if cmd.children[0] == 'comment':
                        comment = str(cmd.children[1].children[0]).strip('"')
                    elif cmd.children[0] == 'member':
                        for addr_key in cmd.children[1].children:
                            address_keys.append(to_cname(addr_key))
                    else:
                        if cmd.children[0] != 'color' and cmd.children[0] != 'uuid':
                            logging.warning(' '.join(
                                ['line', str(cmd.line) + ': NOT EVALUATED: config firewall addrgrp:\n  option:',
                                 str(cmd.children[0]), '\n  value:',
                                 str(cmd.children[1:]), '\n  CONTEXT:', str(entry)]))
                else:
                    raise RuntimeError('line ' + str(cmd.line) + ": Expected 'set' command!")
            if not address_keys:
                raise RuntimeError('line ' + str(entry.line) + ": Incompletely parsed record")
            fw_data.net_alias_group.append(FgNetAliasGroup(str(name), str(comment), address_keys))
    else:
        logging.critical('Could not find critical important section \'config firewall addrgrp\'')

    logging.info('Extraction of "config firewall addrgrp" finished')

    #######################################################################################
    logging.info('Extraction of "config firewall ippool" started')
    if 'ippool' in firewall_raw.keys():
        for entry in firewall_raw['ippool'][1:]:
            name = to_cname(entry.children[0])
            ip = None
            ip_s = None
            comment = ''
            for cmd in entry.children[1:]:
                if cmd.data == 'subcommand_field_set':
                    if cmd.children[0] == 'comments':
                        comment = str(cmd.children[1].children[0]).strip('"')
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
                                ['line', str(cmd.line) + ': NOT EVALUATED: config firewall ippool:\n  option:',
                                 str(cmd.children[0]), '\n  value:',
                                 str(cmd.children[1:]), '\n  CONTEXT:', str(entry)]))
                else:
                    raise RuntimeError('line ' + str(cmd.line) + ": Expected 'set' command!")
            if ip is None:
                raise RuntimeError('line ' + str(entry.line) + ":Incompletely parsed record")
            fw_data.ip_alias.append(FgIPAlias(str(name), str(comment), ip))
    else:
        logging.warning('Could not find section \'config firewall ippool\'')

    logging.info('Extraction of "config firewall ippool" finished')

    #######################################################################################
    logging.info('Extraction of "config firewall policy" started')
    if 'policy' in firewall_raw.keys():
        for entry in firewall_raw['policy'][1:]:
            skip = False
            src_interface = None
            dst_interface = None
            src_alias_list = []
            dst_alias_list = []
            action = None
            service = []
            comment = ''
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
                        comment = str(cmd.children[1].children[0]).strip('"')
                    elif cmd.children[0] == 'srcintf':
                        if src_interface is None:
                            src_interface = to_cname(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'dstintf':
                        if dst_interface is None:
                            dst_interface = to_cname(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'srcaddr':
                        if not src_alias_list:
                            for alias in cmd.children[1].children:
                                src_alias_list.append(to_cname(alias))
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'dstaddr':
                        if not dst_alias_list:
                            for alias in cmd.children[1].children:
                                dst_alias_list.append(to_cname(alias))
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'natip':
                        if nat_ip is None:
                            if len(cmd.children[1].children) == 2:
                                # case ip + netmask
                                nat_ip = IPv4Network('/'.join(cmd.children[1].children))
                            else:
                                # case subnet
                                nat_ip = IPv4Network(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'action':
                        if action is None:
                            action = str(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'send-deny-packet':
                        if action is None:
                            if str(cmd.children[1].children[0]) == 'enable':
                                action = 'deny'
                            else:
                                raise RuntimeError('Encountered unexpected value')
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'service':
                        if not service:
                            for s in cmd.children[1].children:
                                service.append(str(s))
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'global-label':
                        if label is None:
                            label = str(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
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
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'ippool':
                        if ippool is False:
                            if not str(cmd.children[1].children[0]) == 'enable':
                                raise RuntimeError(
                                    'Expected "set ippool enable" got "set ippool ' + str(
                                        cmd.children[1].children[0]) + '"')
                            else:
                                ippool = True
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'utm-status':
                        if utm_status is False:
                            if not str(cmd.children[1].children[0]) == 'enable':
                                raise RuntimeError('Expected "set utm-status enable" got "set utm-status ' + str(
                                    cmd.children[1].children[0]) + '"')
                            else:
                                utm_status = True
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'poolname':
                        if poolname is None:
                            poolname = to_cname(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'voip-profile':
                        if voip_profile is None:
                            voip_profile = str(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'session-ttl':
                        if session_ttl is None:
                            session_ttl = int(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    else:
                        if cmd.children[0] != 'uuid' and cmd.children[0] != 'schedule' \
                                and cmd.children[0] != 'logtraffic-start':
                            logging.warning(' '.join(
                                ['line', str(cmd.line) + ': NOT EVALUATED: config firewall policy:\n  option:',
                                 str(cmd.children[0]), '\n  value:',
                                 str(cmd.children[1:]), '\n  CONTEXT:', str(entry)]))
                else:
                    raise RuntimeError('line ' + str(cmd.line) + ": Expected 'set' command!")
            if skip:
                continue
            if src_interface is None:
                logging.error(' '.join(
                    ["line", str(entry.line) + ": Skipped incomplete/unparseable 'config firewall policy':",
                     "missing 'srcintf':\n  CONTEXT:", str(entry)]))
                continue
            elif dst_interface is None:
                logging.error(' '.join(
                    ["line", str(entry.line) + ": Skipped incomplete/unparseable 'config firewall policy':",
                     "missing 'dstintf':\n  CONTEXT:", str(entry)]))
                continue
            elif action is None:
                logging.error(' '.join(
                    ["line", str(entry.line) + ": Skipped incomplete/unparseable 'config firewall policy':",
                     "missing 'action':\n  CONTEXT:", str(entry)]))
                continue
            elif not src_alias_list:
                logging.error(' '.join(
                    ["line", str(entry.line) + ": Skipped incomplete/unparseable 'config firewall policy':",
                     "missing 'srcaddr':\n  CONTEXT:", str(entry)]))
                continue
            elif not dst_alias_list:
                logging.error(' '.join(
                    ["line", str(entry.line) + ": Skipped incomplete/unparseable 'config firewall policy':",
                     "missing 'dstaddr':\n  CONTEXT:", str(entry)]))
                continue
            elif not service:
                logging.error(' '.join(
                    ["line", str(entry.line) + ": Skipped incomplete/unparseable 'config firewall policy':",
                     "missing 'service':\n  CONTEXT:", str(entry)]))
                continue
            elif label is None:
                logging.error(' '.join(
                    ["line", str(entry.line) + ": Skipped incomplete/unparseable 'config firewall policy':",
                     "missing 'global-label':\n  CONTEXT:", str(entry)]))
                continue
            fw_data.policy.append(FgPolicy(src_interface, dst_interface, src_alias_list, dst_alias_list,
                                           action, service, log_traffic, comment, label, nat, session_ttl,
                                           ippool, poolname, voip_profile, utm_status, nat_ip))
    else:
        logging.critical('Could not find critical important section \'config firewall policy\'')

    logging.info('Extraction of "config firewall policy" finished')

    #######################################################################################
    logging.info('Extraction of "config firewall service category" started')
    if 'service_category' in firewall_raw.keys():
        for entry in firewall_raw['service_category'][1:]:
            name = to_cname(entry.children[0])
            if len(entry.children[1:]) != 1:
                raise RuntimeError("line" + str(entry.line) + ': Unexpected number of commands')
            if entry.children[1].data != 'subcommand_field_set':
                raise RuntimeError("line" + str(entry.line) + ': Unexpected type of command')
            if entry.children[1].children[0] != 'comment':
                raise RuntimeError("line" + str(entry.line) + ': Unexpected set target')
            comment = str(entry.children[1].children[1].children[0]).strip('"')
            fw_data.service_category.append(FgServiceCategory(str(name), str(comment), []))
    else:
        logging.critical('Could not find critical important section \'config firewall service group\'')

    logging.info('Extraction of "config firewall service category" finished')

    #######################################################################################
    logging.info('Extraction of "config firewall service custom" started')
    if 'service_custom' in firewall_raw.keys():
        for entry in firewall_raw['service_custom'][1:]:
            skip = False
            name = to_cname(entry.children[0])
            comment = ''
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
                            category = to_cname(cmd.children[1].children[0])
                            found = False
                            for cat in fw_data.service_category:
                                if cat.name == category:
                                    cat.members.append(name)
                                    found = True
                                    break
                            if not found:
                                logging.warning('category ' + category + ' could not be found in fw_service_category')
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'comment':
                        comment = str(cmd.children[1].children[0]).strip('"')
                    elif cmd.children[0] == 'protocol':
                        if protocol is None:
                            protocol = str(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'icmptype':
                        if icmp_type is None:
                            icmp_type = int(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'session-ttl':
                        if session_ttl is None:
                            session_ttl = int(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
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
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
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
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    else:
                        if cmd.children[0] != 'color' and cmd.children[0] != 'visibility':
                            logging.warning('line', str(cmd.line) + ': NOT EVALUATED: config firewall service custom:',
                                            cmd.children[0],
                                            cmd.children[1:])
            if skip:
                continue
            fw_data.service.append(
                FgService(name, comment, category, protocol, icmp_type, tcp_range, udp_range, session_ttl))
    else:
        logging.critical('Could not find critical important section \'config firewall service custom\'')

    logging.info('Extraction of "config firewall service custom" finished')

    #######################################################################################
    logging.info('Extraction of "config firewall service group" started')
    if 'service_group' in firewall_raw.keys():
        for entry in firewall_raw['service_group'][1:]:
            name = to_cname(entry.children[0])
            comment = ''
            members = []
            for cmd in entry.children[1:]:
                if cmd.children[0] == 'comment':
                    comment = str(cmd.children[1].children[0]).strip('"')
                elif cmd.children[0] == 'member':
                    if not members:
                        for val in cmd.children[1].children:
                            members.append(str(val))
                    else:
                        raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                else:
                    if cmd.children[0] != 'color':
                        logging.warning(' '.join(
                            ['line', str(cmd.line) + ': NOT EVALUATED: config firewall service group:',
                             str(cmd.children[0]), str(cmd.children[1:])]))
            fw_data.service_group.append(FgServiceGroup(name, comment, members))
    else:
        logging.critical('Could not find critical important section \'config firewall service group\'')

    logging.info('Extraction of "config firewall service group" finished')

    #######################################################################################
    logging.info('Extraction of "config system dhcp server" started')
    re_dns_server = re.compile('dns-server[0-9]+')
    if 'dhcp_server' in system_raw.keys():
        for entry in system_raw['dhcp_server'][1:]:
            lease_time = None
            dns_server = []
            domain = None
            netmask = None
            gateway = None
            ip_range_start = None
            ip_range_end = None
            interface = None
            for cmd in entry.children[1:]:
                if cmd.data == 'subcommand_field_set':
                    if cmd.children[0] == 'lease-time':
                        lease_time = int(cmd.children[1].children[0])
                    elif cmd.children[0] == 'default-gateway':
                        if gateway is None:
                            gateway = IPv4Address(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'netmask':
                        if netmask is None:
                            netmask = IPv4Address(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'domain':
                        if domain is None:
                            domain = str(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'interface':
                        if interface is None:
                            interface = str(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif re_dns_server.match(cmd.children[0]):
                        dns_server.append(IPv4Address(cmd.children[1].children[0]))
                    else:
                        if cmd.children[0] != 'TODO':
                            logging.warning(' '.join(
                                ['line', str(cmd.line) + ': NOT EVALUATED: config system dhcp server:\n  option:',
                                 str(cmd.children[0]), '\n  value:',
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
                                    logging.error('line ' + str(scmd.line) +
                                                  ': Parsing conflict in nested "config" statement\n  CONTEXT: ' + str(
                                        entry))
                            elif scmd.children[0] == 'end-ip':
                                if ip_range_end is None:
                                    ip_range_end = IPv4Address(scmd.children[1].children[0])
                                else:
                                    logging.error('line ' + str(scmd.line) +
                                                  ': Parsing conflict in nested "config" statement\n  CONTEXT: ' + str(
                                        entry))
                    else:
                        logging.error('Unexpected entry in nested "config" statement\n  CONTEXT: ' + str(entry))
                else:
                    raise RuntimeError("Expected 'set' or 'config' command!")
            fw_data.dhcp_server.append(
                FgDhcpServer(lease_time, dns_server, domain, netmask, gateway, ip_range_start, ip_range_end, interface))
    else:
        logging.warning('Could not find section \'config system dhcp server\'')

    logging.info('Extraction of "config system dhcp server" finished')

    #######################################################################################
    logging.info('Extraction of "config system interface" started')

    if 'interface' in system_raw.keys():
        for entry in system_raw['interface'][1:]:
            name = to_cname(entry.children[0])
            interface_type = None
            comment = ''
            interface_ip = None
            allowaccess = []
            vlanid = None
            parent_interface = None
            secondary_interface_ip = None
            secondary_allowaccess = []
            dhcp_relay = None
            dhcp_enabled = False
            snmp_index = None
            secondary_enabled = False
            up = True
            member_interfaces = []
            vlanforward = False

            for cmd in entry.children[1:]:
                if cmd.data == 'subcommand_field_set':
                    if cmd.children[0] == 'description':
                        if comment != '':
                            comment += '\n'
                        comment += 'description: ' + str(cmd.children[1].children[0]).strip('"')
                    elif cmd.children[0] == 'alias':
                        if comment != '':
                            comment += '\n'
                        comment += 'alias: ' + str(cmd.children[1].children[0]).strip('"')
                    elif cmd.children[0] == 'ip':
                        if interface_ip is None:
                            interface_ip = IPv4Interface('/'.join(cmd.children[1].children))
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'type':
                        if interface_type is None:
                            interface_type = str(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'secondary-IP':
                        if not secondary_enabled:
                            if str(cmd.children[1].children[0]) == 'enable':
                                secondary_enabled = True
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'vlanforward':
                        if not vlanforward:
                            if str(cmd.children[1].children[0]) == 'enable':
                                vlanforward = True
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'dhcp-relay-service':
                        if not dhcp_enabled:
                            if str(cmd.children[1].children[0]) == 'enable':
                                dhcp_enabled = True
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'dhcp-relay-ip':
                        if dhcp_relay is None:
                            dhcp_relay = IPv4Address(str(cmd.children[1].children[0]).strip('\'"'))
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'status':
                        if str(cmd.children[1].children[0]) == 'down':
                            up = False
                        elif str(cmd.children[1].children[0]) == 'up':
                            up = True
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered invalid set command")
                    elif cmd.children[0] == 'vlanid':
                        if vlanid is None:
                            vlanid = int(cmd.children[1].children[0])
                            interface_type = 'vlan'
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'snmp-index':
                        if snmp_index is None:
                            snmp_index = int(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'member':
                        if not member_interfaces:
                            for member in cmd.children[1].children:
                                member_interfaces.append(to_cname(member))
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'allowaccess':
                        if not allowaccess:
                            allowaccess = [str(x) for x in cmd.children[1].children]
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    elif cmd.children[0] == 'interface':
                        if parent_interface is None:
                            parent_interface = to_cname(cmd.children[1].children[0])
                        else:
                            raise RuntimeError('line ' + str(cmd.line) + ": Encountered conflicting set command")
                    else:
                        if cmd.children[0] != 'vdom' and cmd.children[0] != 'speed':
                            logging.warning(' '.join(
                                ['line', str(cmd.line) + ': NOT EVALUATED: config system interface:\n  option:',
                                 str(cmd.children[0]), '\n  value:',
                                 str(cmd.children[1:]), '\n  CONTEXT:', str(entry)]))
                elif cmd.data == 'subcommand_config':

                    if cmd.children[0].children[0].children[0] == 'secondaryip':
                        # Unnecessary because only one subentry expected
                        # for sentry in cmd.children[0].children[1:]:
                        #     for scmd in sentry.children[1:]:
                        #         print(scmd.pretty())

                        for scmd in cmd.children[0].children[1].children[1:]:
                            if scmd.children[0] == 'ip':
                                if secondary_interface_ip is None:
                                    secondary_interface_ip = IPv4Interface('/'.join(scmd.children[1].children))
                                else:
                                    logging.error('line ' + str(scmd.line) +
                                                  ': Parsing conflict in nested "config" statement\n  CONTEXT: ' + str(
                                        entry))
                            elif scmd.children[0] == 'allowaccess':
                                if not secondary_allowaccess:
                                    secondary_allowaccess = [str(x) for x in scmd.children[1].children]
                                else:
                                    logging.error('line ' + str(scmd.line) +
                                                  ': Parsing conflict in nested "config" statement\n  CONTEXT: ' + str(
                                        entry))
                    else:
                        logging.error('Unexpected entry in nested "config" statement\n  CONTEXT: ' + str(entry))
                else:
                    raise RuntimeError("Expected 'set' or 'config' command!")
            if not secondary_enabled:
                secondary_allowaccess = []
                secondary_interface_ip = None
            if not dhcp_enabled:
                dhcp_relay = None
            fw_data.interface.append(
                FgInterface(name, interface_type, comment, interface_ip, allowaccess, vlanid,
                            parent_interface, secondary_interface_ip, secondary_allowaccess, dhcp_relay, snmp_index,
                            up, member_interfaces, vlanforward))
    else:
        logging.warning('Could not find section \'config system interface\'')

    logging.info('Extraction of "config system interface" finished')

    return fw_data


def _validity_check(fg_data: FgData):
    logging.info('Consistency check of policy data started')

    def find_alias(alias, data):
        for i in data.net_alias_group:
            if i.name == alias:
                return True
        for i in data.net_alias:
            if i.name == alias:
                return True
        for i in data.ip_alias:
            if i.name == alias:
                return True
        return False

    def find_interface(intf, data):
        for i in data.interface:
            if i.name == intf:
                return True
        return False

    for p in fg_data.policy:
        if not find_interface(p.src_interface, fg_data):
            logging.error('src interface', p.src_interface, 'not found in fg_data.interface')
        if not find_interface(p.dst_interface, fg_data):
            logging.error('dst interface', p.dst_interface, 'not found in fg_data.interface')
        for a in p.src_alias_list:
            if not find_alias(a, fg_data):
                logging.error('src address alias (srcaddr) ' + a +
                              ' not found in fg_data.net_alias or fg_data.net_alias_group')
        for a in p.dst_alias_list:
            if not find_alias(a, fg_data):
                logging.error('dst address alias (dstaddr) ' + a +
                              ' not found in fg_data.net_alias or fg_data.net_alias_group')

    logging.info('Consistency check of policy data finished')


def parse_config(fortigate_config: str, fortigate_lark_grammar: str) -> str:
    """Parses a fortigate configuration using LARK and extracts firewall specific date as well as DHCP configurations

    :param fortigate_config The raw configuraiton file contents to parse
    :param fortigate_lark_grammar LARK grammar to parse fortigate configurations
    :returns extracted data as JSON serialized FwData class
    """

    parser = Lark(fortigate_lark_grammar,
                  parser="lalr",
                  propagate_positions=True,
                  start="root",
                  debug=True)

    parsed_conf = parser.parse(fortigate_config)
    logging.info('Fortigate configuration parsed')

    firewall_raw, system_raw, vpn_raw = _extraction_stage_1(parsed_conf)

    fg_data = _extraction_stage_2(firewall_raw, system_raw, vpn_raw)

    _validity_check(fg_data)  # TODO: config firewall vip

    logging.info('Serializing extracted data')
    s = FgDataSchema()
    serialized_data = s.dumps(fg_data)

    logging.info('Testing data deserialization')
    deserialized_data = s.loads(serialized_data)

    if deserialized_data != fg_data:
        logging.critical('Could not verify serialized data')
        assert deserialized_data == fg_data
    return serialized_data


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")

    fortigate_config_file = "../FW-UV_db.conf"
    grammar_file = "fortigate.lark"
    output_json_file = "FwData.json"

    with open(grammar_file, "r") as f:
        fortigate_lark_grammar = f.read()

    with open(fortigate_config_file, "r") as f:
        fortigate_config = f.read()

    json_data = parse_config(fortigate_config, fortigate_lark_grammar)

    with open(output_json_file, 'w') as f:
        f.write(json_data)
