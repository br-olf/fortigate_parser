from dataclasses import dataclass, field as dc_field
from ipaddress import IPv4Network, IPv4Address, IPv4Interface
from typing import Optional, List

from marshmallow import Schema, fields as mm_fields, post_load, ValidationError


class IPv4InterfaceSchema(mm_fields.Field):
    def _deserialize(self, value, *args, **kwargs):
        try:
            return IPv4Interface(value)
        except Exception as e:
            raise ValidationError("Not a valid IPv4Interface.") from e

    def _serialize(self, value, *args, **kwargs):
        if isinstance(value, IPv4Interface):
            return value.exploded
        else:
            return value


class IPv4NetworkSchema(mm_fields.Field):
    def _deserialize(self, value, *args, **kwargs):
        try:
            return IPv4Network(value)
        except Exception as e:
            raise ValidationError("Not a valid IPv4Network.") from e

    def _serialize(self, value, *args, **kwargs):
        if isinstance(value, IPv4Network):
            return value.exploded
        else:
            return value


class IPv4AddressSchema(mm_fields.Field):
    def _deserialize(self, value, *args, **kwargs):
        try:
            return IPv4Address(value)
        except Exception as e:
            raise ValidationError("Not a valid IPv4Address.") from e

    def _serialize(self, value, *args, **kwargs):
        if isinstance(value, IPv4Address):
            return value.exploded
        else:
            return value


@dataclass
class FgInterface:
    name: str
    interface_type: str
    comment: str
    interface_ip: Optional[IPv4Interface]
    allowaccess: List[str]
    vlanid: Optional[int]
    parent_interface: Optional[str]
    secondary_interface_ip: Optional[IPv4Interface]
    secondary_allowaccess: List[str]
    dhcp_relay: Optional[IPv4Address]
    snmp_index: Optional[int]
    up: bool
    member_interfaces: List[str]
    vlanforward: bool


class FgInterfaceSchema(Schema):
    name = mm_fields.String(required=True)
    interface_type = mm_fields.String(required=True)
    comment = mm_fields.String(required=True)
    interface_ip = IPv4InterfaceSchema(allow_none=True)
    allowaccess = mm_fields.List(mm_fields.String, required=True)
    vlanid = mm_fields.Integer(allow_none=True)
    parent_interface = mm_fields.String(allow_none=True)
    secondary_interface_ip = IPv4InterfaceSchema(allow_none=True)
    secondary_allowaccess = mm_fields.List(mm_fields.String, required=True)
    dhcp_relay = IPv4AddressSchema(allow_none=True)
    snmp_index = mm_fields.Integer(allow_none=True)
    up = mm_fields.Boolean(required=True)
    member_interfaces = mm_fields.List(mm_fields.String, required=True)
    vlanforward = mm_fields.Boolean(required=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FgInterface(data['name'], data['interface_type'], data['comment'],
                           data['interface_ip'], data['allowaccess'], data['vlanid'], data['parent_interface'],
                           data['secondary_interface_ip'], data['secondary_allowaccess'], data['dhcp_relay'],
                           data['snmp_index'], data['up'], data['member_interfaces'], data['vlanforward'])


@dataclass
class FgNetAliasGroup:
    name: str
    comment: str
    net_alias_list: List[str]


class FgNetAliasGroupSchema(Schema):
    name = mm_fields.String(required=True)
    comment = mm_fields.String(required=True)
    net_alias_list = mm_fields.List(mm_fields.String, required=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FgNetAliasGroup(data['name'], data['comment'], data['net_alias_list'])


@dataclass
class FgNetAlias:
    name: str
    comment: str
    net_list: Optional[List[IPv4Network]]
    fqdn: Optional[str]


class FgNetAliasSchema(Schema):
    name = mm_fields.String(required=True)
    comment = mm_fields.String(required=True)
    net_list = mm_fields.List(IPv4NetworkSchema, allow_none=True)
    fqdn = mm_fields.String(allow_none=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FgNetAlias(data['name'], data['comment'], data['net_list'], data['fqdn'])


@dataclass
class FgIPAlias:
    name: str
    comment: str
    ip: IPv4Address


class FgIPAliasSchema(Schema):
    name = mm_fields.String(required=True)
    comment = mm_fields.String(required=True)
    ip = IPv4AddressSchema(required=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FgIPAlias(data['name'], data['comment'], data['ip'])


@dataclass
class FgServiceCategory:
    name: str
    comment: str
    members: List[str]


class FgServiceCategorySchema(Schema):
    name = mm_fields.String(required=True)
    comment = mm_fields.String(required=True)
    members = mm_fields.List(mm_fields.String, required=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FgServiceCategory(data['name'], data['comment'], data['members'])


@dataclass
class FgPolicy:
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


class FgPolicySchema(Schema):
    src_interface = mm_fields.String(required=True)
    dst_interface = mm_fields.String(required=True)
    src_alias_list = mm_fields.List(mm_fields.String, required=True)
    dst_alias_list = mm_fields.List(mm_fields.String, required=True)
    action = mm_fields.String(required=True)
    service = mm_fields.List(mm_fields.String, required=True)
    log_traffic = mm_fields.String(required=True)
    comment = mm_fields.String(required=True)
    label = mm_fields.String(required=True)
    nat = mm_fields.Boolean(required=True)
    session_ttl = mm_fields.Integer(allow_none=True)
    ippool = mm_fields.Boolean(required=True)
    poolname = mm_fields.String(allow_none=True)
    voip_profile = mm_fields.String(allow_none=True)
    utm_status = mm_fields.Boolean(required=True)
    nat_ip = IPv4NetworkSchema(allow_none=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FgPolicy(data['src_interface'], data['dst_interface'], data['src_alias_list'], data['dst_alias_list'],
                        data['action'], data['service'], data['log_traffic'], data['comment'], data['label'],
                        data['nat'], data['session_ttl'], data['ippool'], data['poolname'], data['voip_profile'],
                        data['utm_status'], data['nat_ip'])


@dataclass
class PortRange:
    start: int
    end: int


class PortRangeSchema(Schema):
    start = mm_fields.Integer(required=True)
    end = mm_fields.Integer(required=True)

    @post_load
    def make_object(self, data, **kwargs):
        return PortRange(data['start'], data['end'])


@dataclass
class FgService:
    name: str
    comment: str
    category: Optional[str]
    protocol: Optional[str]
    icmp_type: Optional[int]
    tcp_range: Optional[PortRange]  # Maybe List needed
    udp_range: Optional[PortRange]  # Maybe List needed
    session_ttl: Optional[int]


class FgServiceSchema(Schema):
    name = mm_fields.String(required=True)
    comment = mm_fields.String(required=True)
    category = mm_fields.String(allow_none=True)
    protocol = mm_fields.String(allow_none=True)
    icmp_type = mm_fields.Integer(allow_none=True)
    tcp_range = mm_fields.Nested(PortRangeSchema, allow_none=True)
    udp_range = mm_fields.Nested(PortRangeSchema, allow_none=True)
    session_ttl = mm_fields.Integer(allow_none=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FgService(data['name'], data['comment'], data['category'], data['protocol'],
                         data['icmp_type'], data['tcp_range'], data['udp_range'], data['session_ttl'])


@dataclass
class FgServiceGroup:
    name: str
    comment: str
    members: List[str]


class FgServiceGroupSchema(Schema):
    name = mm_fields.String(required=True)
    comment = mm_fields.String(required=True)
    members = mm_fields.List(mm_fields.String, required=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FgServiceGroup(data['name'], data['comment'], data['members'])


@dataclass
class FgDhcpServer:
    lease_time: int
    dns_server: List[IPv4Address]
    domain: Optional[str]
    netmask: Optional[IPv4Address]
    gateway: Optional[IPv4Address]
    ip_range_start: IPv4Address
    ip_range_end: IPv4Address
    interface: str


class FgDhcpServerSchema(Schema):
    lease_time = mm_fields.Integer(required=True)
    dns_server = mm_fields.List(IPv4AddressSchema, required=True)
    domain = mm_fields.String(allow_none=True)
    netmask = IPv4AddressSchema(allow_none=True)
    gateway = IPv4AddressSchema(allow_none=True)
    ip_range_start = IPv4AddressSchema(required=True)
    ip_range_end = IPv4AddressSchema(required=True)
    interface = mm_fields.String(required=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FgDhcpServer(data['lease_time'], data['dns_server'], data['domain'], data['netmask'],
                            data['gateway'], data['ip_range_start'], data['ip_range_end'], data['interface'])


@dataclass
class FgVpnCertCa:
    name: str
    cert: str


class FgVpnCertCaSchema(Schema):
    name = mm_fields.String(required=True)
    cert = mm_fields.String(required=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FgVpnCertCa(data['name'], data['cert'])


@dataclass
class FgVpnCertLocal:
    name: str
    comment: str
    cert: str
    private_key: str
    password: str


class FgVpnCertLocalSchema(Schema):
    name = mm_fields.String(required=True)
    comment = mm_fields.String(required=True)
    cert = mm_fields.String(required=True)
    private_key = mm_fields.String(required=True)
    password = mm_fields.String(required=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FgVpnCertLocal(data['name'], data['comment'], data['cert'], data['private_key'], data['password'])


@dataclass
class FgIpsecCryptoParams:
    encrypt: str
    digest: str


class FgIpsecCryptoParamsSchema(Schema):
    encrypt = mm_fields.String(required=True)
    digest = mm_fields.String(required=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FgIpsecCryptoParams(data['encrypt'], data['digest'])


@dataclass
class FgVpnIpsecPhase1:
    name: str
    comment: str
    interface: str
    dpd: bool  # Dead Peer Detection
    nattraversal: bool
    dhgrp: List[int]
    c_proposal: List[FgIpsecCryptoParams]
    remote_gw: Optional[IPv4Address]  # authmethod == psk
    psksecret: str
    keylife: int
    connect_type: str
    xauthtype: Optional[str]
    authusrgrp: Optional[str]


class FgVpnIpsecPhase1Schema(Schema):
    name = mm_fields.String(required=True)
    comment = mm_fields.String(required=True)
    interface = mm_fields.String(required=True)
    dpd = mm_fields.Boolean(required=True)
    nattraversal = mm_fields.Boolean(required=True)
    dhgrp = mm_fields.List(mm_fields.Integer, required=True)
    c_proposal = mm_fields.List(mm_fields.Nested(FgIpsecCryptoParamsSchema), required=True)
    remote_gw = IPv4AddressSchema(allow_none=True)
    psksecret = mm_fields.String(required=True)
    keylife = mm_fields.Integer(required=True)
    connect_type = mm_fields.String(required=True)
    xauthtype = mm_fields.String(allow_none=True)
    authusrgrp = mm_fields.String(allow_none=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FgVpnIpsecPhase1(data['name'], data['comment'], data['interface'], data['dpd'], data['nattraversal'],
                                data['dhgrp'], data['c_proposal'], data['remote_gw'], data['psksecret'],
                                data['keylife'], data['connect_type'], data['xauthtype'], data['authusrgrp'])


@dataclass
class FgVpnIpsecPhase2:
    name: str
    phase1name: str
    c_proposal: List[FgIpsecCryptoParams]
    dhgrp: List[int]
    keylife: int
    src_addr_type: str
    dst_addr_type: str
    src_net: IPv4Network
    dst_net: IPv4Network
    src_ip: IPv4Address
    dst_ip: IPv4Address


class FgVpnIpsecPhase2Schema(Schema):
    name = mm_fields.String(required=True)
    phase1name = mm_fields.String(required=True)
    c_proposal = mm_fields.List(mm_fields.Nested(FgIpsecCryptoParamsSchema), required=True)
    dhgrp = mm_fields.List(mm_fields.Integer, required=True)
    keylife = mm_fields.Integer(required=True)
    src_addr_type = mm_fields.String(required=True)
    dst_addr_type = mm_fields.String(required=True)
    src_net = IPv4NetworkSchema(allow_none=True)
    dst_net = IPv4NetworkSchema(allow_none=True)
    src_ip = IPv4AddressSchema(allow_none=True)
    dst_ip = IPv4AddressSchema(allow_none=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FgVpnIpsecPhase2(data['name'], data['phase1name'], data['c_proposal'], data['dhgrp'], data['keylife'],
                                data['src_addr_type'], data['dst_addr_type'], data['src_net'], data['dst_net'],
                                data['src_ip'], data['dst_ip'])


@dataclass
class FgData:
    dhcp_server: List[FgDhcpServer] = dc_field(default_factory=list)
    net_alias: List[FgNetAlias] = dc_field(default_factory=list)
    net_alias_group: List[FgNetAliasGroup] = dc_field(default_factory=list)
    ip_alias: List[FgIPAlias] = dc_field(default_factory=list)
    policy: List[FgPolicy] = dc_field(default_factory=list)
    service: List[FgService] = dc_field(default_factory=list)
    service_group: List[FgServiceGroup] = dc_field(default_factory=list)
    service_category: List[FgServiceCategory] = dc_field(default_factory=list)
    interface: List[FgInterface] = dc_field(default_factory=list)
    vpn_cert_ca: List[FgVpnCertCa] = dc_field(default_factory=list)
    vpn_cert_local: List[FgVpnCertLocal] = dc_field(default_factory=list)
    vpn_ipsec_phase_1: List[FgVpnIpsecPhase1] = dc_field(default_factory=list)
    vpn_ipsec_phase_2: List[FgVpnIpsecPhase2] = dc_field(default_factory=list)


class FgDataSchema(Schema):
    dhcp_server = mm_fields.List(mm_fields.Nested(FgDhcpServerSchema), required=True)
    net_alias = mm_fields.List(mm_fields.Nested(FgNetAliasSchema), required=True)
    net_alias_group = mm_fields.List(mm_fields.Nested(FgNetAliasGroupSchema), required=True)
    ip_alias = mm_fields.List(mm_fields.Nested(FgIPAliasSchema), required=True)
    policy = mm_fields.List(mm_fields.Nested(FgPolicySchema), required=True)
    service = mm_fields.List(mm_fields.Nested(FgServiceSchema), required=True)
    service_group = mm_fields.List(mm_fields.Nested(FgServiceGroupSchema), required=True)
    service_category = mm_fields.List(mm_fields.Nested(FgServiceCategorySchema), required=True)
    interface = mm_fields.List(mm_fields.Nested(FgInterfaceSchema), required=True)
    vpn_cert_ca = mm_fields.List(mm_fields.Nested(FgVpnCertCaSchema), required=True)
    vpn_cert_local = mm_fields.List(mm_fields.Nested(FgVpnCertLocalSchema), required=True)
    vpn_ipsec_phase_1 = mm_fields.List(mm_fields.Nested(FgVpnIpsecPhase1Schema), required=True)
    vpn_ipsec_phase_2 = mm_fields.List(mm_fields.Nested(FgVpnIpsecPhase2Schema), required=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FgData(data['dhcp_server'], data['net_alias'], data['net_alias_group'], data['ip_alias'],
                      data['policy'], data['service'], data['service_group'], data['service_category'],
                      data['interface'], data['vpn_cert_ca'], data['vpn_cert_local'], data['vpn_ipsec_phase_1'],
                      data['vpn_ipsec_phase_2'])
