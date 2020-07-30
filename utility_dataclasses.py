from dataclasses import dataclass, field as dc_field
from ipaddress import IPv4Network, IPv4Address
from typing import Optional, List

from marshmallow import Schema, fields as mm_fields, post_load, ValidationError


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
class FgData:
    dhcp_server: List[FgDhcpServer] = dc_field(default_factory=list)
    net_alias: List[FgNetAlias] = dc_field(default_factory=list)
    net_alias_group: List[FgNetAliasGroup] = dc_field(default_factory=list)
    ip_alias: List[FgIPAlias] = dc_field(default_factory=list)
    policy: List[FgPolicy] = dc_field(default_factory=list)
    service: List[FgService] = dc_field(default_factory=list)
    service_group: List[FgServiceGroup] = dc_field(default_factory=list)
    service_category: List[FgServiceCategory] = dc_field(default_factory=list)


class FgDataSchema(Schema):
    dhcp_server = mm_fields.List(mm_fields.Nested(FgDhcpServerSchema), required=True)
    net_alias = mm_fields.List(mm_fields.Nested(FgNetAliasSchema), required=True)
    net_alias_group = mm_fields.List(mm_fields.Nested(FgNetAliasGroupSchema), required=True)
    ip_alias = mm_fields.List(mm_fields.Nested(FgIPAliasSchema), required=True)
    policy = mm_fields.List(mm_fields.Nested(FgPolicySchema), required=True)
    service = mm_fields.List(mm_fields.Nested(FgServiceSchema), required=True)
    service_group = mm_fields.List(mm_fields.Nested(FgServiceGroupSchema), required=True)
    service_category = mm_fields.List(mm_fields.Nested(FgServiceCategorySchema), required=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FgData(data['dhcp_server'], data['net_alias'], data['net_alias_group'], data['ip_alias'],
                      data['policy'], data['service'], data['service_group'], data['service_category'])
