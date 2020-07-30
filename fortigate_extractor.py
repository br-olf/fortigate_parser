import logging
import re
from ipaddress import IPv4Network, IPv4Address, summarize_address_range

from lark import Lark

from utility_dataclasses import FwData, FwPolicy, FwService, FwServiceCategory, FwServiceGroup, FwDhcpServer, \
    FwNetAlias, FwNetAliasGroup, FwIPAlias, FwDataSchema, PortRange

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


# noinspection PyUnresolvedReferences
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

    #######################################################################################
    # Extract relevant configuration pieces
    #######################################################################################
    logging.info('Extraction of relevant fortigate configurations started')
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
    fw_data = FwData()

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
                    raise RuntimeError("Expected 'set' command!")
            if not ip:
                ip = None
            if ip is None and fqdn is None:
                logging.error(' '.join(
                    ["line", str(entry.line) + ": Skipped incomplete/unparseable 'config firewall address':",
                     "missing 'subnet' or 'fqdn' or 'start-ip'/'end-ip':\n  CONTEXT:", str(entry)]))
                continue

            fw_data.net_alias.append(FwNetAlias(str(name), str(comment), ip, fqdn))
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
                    raise RuntimeError("Expected 'set' command!")
            if not address_keys:
                raise RuntimeError("Incompletely parsed record")
            fw_data.net_alias_group.append(FwNetAliasGroup(str(name), str(comment), address_keys))
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
                    raise RuntimeError("Expected 'set' command!")
            if ip is None:
                raise RuntimeError("Incompletely parsed record")
            fw_data.ip_alias.append(FwIPAlias(str(name), str(comment), ip))
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
                            poolname = to_cname(cmd.children[1].children[0])
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
                            # noinspection PyUnresolvedReferences
                            logging.warning(' '.join(
                                ['line', str(cmd.line) + ': NOT EVALUATED: config firewall policy:\n  option:',
                                 str(cmd.children[0]), '\n  value:',
                                 str(cmd.children[1:]), '\n  CONTEXT:', str(entry)]))
                else:
                    raise RuntimeError("Expected 'set' command!")
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
            fw_data.policy.append(FwPolicy(src_interface, dst_interface, src_alias_list, dst_alias_list,
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
                raise RuntimeError('Unexpected number of commands')
            if entry.children[1].data != 'subcommand_field_set':
                raise RuntimeError('Unexpected type of command')
            if entry.children[1].children[0] != 'comment':
                raise RuntimeError('Unexpected set target')
            comment = str(entry.children[1].children[1].children[0]).strip('"')
            fw_data.service_category.append(FwServiceCategory(str(name), str(comment), []))
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
                            category = str(cmd.children[1].children[0])
                            found = False
                            for cat in fw_data.service_category:
                                if cat.name == category:
                                    cat.members.append(name)
                                    found = True
                                    break
                            if not found:
                                logging.warning('category ' + category + ' could not be found in fw_service_category')
                        else:
                            raise RuntimeError("Encountered conflicting set command")
                    elif cmd.children[0] == 'comment':
                        comment = str(cmd.children[1].children[0]).strip('"')
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
                            logging.warning('line', str(cmd.line) + ': NOT EVALUATED: config firewall service custom:',
                                            cmd.children[0],
                                            cmd.children[1:])
            if skip:
                continue
            fw_data.service.append(
                FwService(name, comment, category, protocol, icmp_type, tcp_range, udp_range, session_ttl))
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
                        raise RuntimeError("Encountered conflicting set command")
                else:
                    if cmd.children[0] != 'color':
                        logging.warning(' '.join(
                            ['line', str(cmd.line) + ': NOT EVALUATED: config firewall service group:',
                             str(cmd.children[0]), str(cmd.children[1:])]))
            fw_data.service_group.append(FwServiceGroup(name, comment, members))
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
                    elif cmd.children[0] == 'interface':
                        if interface is None:
                            interface = str(cmd.children[1].children[0])
                        else:
                            raise RuntimeError("Encountered conflicting set command")
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
                                    logging.error(
                                        'Parsing conflict in nested "config" statement\n  CONTEXT: ' + str(entry))
                            elif scmd.children[0] == 'end-ip':
                                if ip_range_end is None:
                                    ip_range_end = IPv4Address(scmd.children[1].children[0])
                                else:
                                    logging.error(
                                        'Parsing conflict in nested "config" statement\n  CONTEXT: ' + str(entry))
                    else:
                        logging.error('Unexpected entry in nested "config" statement\n  CONTEXT: ' + str(entry))
                else:
                    raise RuntimeError("Expected 'set' command!")
            fw_data.dhcp_server.append(
                FwDhcpServer(lease_time, dns_server, domain, netmask, gateway, ip_range_start, ip_range_end, interface))
    else:
        logging.warning('Could not find section \'config system dhcp server\'')

    logging.info('Extraction of "config system dhcp server" finished')

    #######################################################################################
    logging.info('Serializing extracted data')
    s = FwDataSchema()
    serialized_data = s.dumps(fw_data)

    logging.info('Testing data deserialization')
    deserialized_data = s.loads(serialized_data)

    if deserialized_data != fw_data:
        logging.critical('Could not verify serialized data')
        assert deserialized_data == fw_data
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
