from dataclasses import dataclass
from ipaddress import IPv4Network, IPv4Address
from typing import Optional, List

from marshmallow import Schema, fields, post_load, ValidationError


class IPv4NetworkSchema(fields.Field):
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


class IPv4AddressSchema(fields.Field):
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
class FwNetAliasGroup:
    name: str
    comment: str
    net_alias_list: List[str]


class FwNetAliasGroupSchema(Schema):
    name = fields.String(required=True)
    comment = fields.String(required=True)
    net_alias_list = fields.List(fields.String, required=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FwNetAliasGroup(data['name'], data['comment'], data['net_alias_list'])


@dataclass
class FwNetAlias:
    name: str
    comment: str
    net_list: List[IPv4Network]


class FwNetAliasSchema(Schema):
    name = fields.String(required=True)
    comment = fields.String(required=True)
    net_list = fields.List(IPv4NetworkSchema, required=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FwNetAlias(data['name'], data['comment'], data['net_list'])


@dataclass
class FwIPAlias:
    name: str
    comment: str
    ip: IPv4Address


class FwIPAliasSchema(Schema):
    name = fields.String(required=True)
    comment = fields.String(required=True)
    ip = IPv4AddressSchema(required=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FwNetAlias(data['name'], data['comment'], data['ip'])


@dataclass
class FwServiceCategory:
    name: str
    comment: str
    members: List[str]


class FwServiceCategorySchema(Schema):
    name = fields.String(required=True)
    comment = fields.String(required=True)
    members = fields.List(fields.String, required=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FwNetAlias(data['name'], data['comment'], data['members'])


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


class FwPolicySchema(Schema):
    src_interface = fields.String(required=True)
    dst_interface = fields.String(required=True)
    src_alias_list = fields.List(fields.String, required=True)
    dst_alias_list = fields.List(fields.String, required=True)
    action = fields.String(required=True)
    service = fields.List(fields.String, required=True)
    log_traffic = fields.String(required=True)
    comment = fields.String(required=True)
    label = fields.String(required=True)
    nat = fields.Boolean(required=True)
    session_ttl = fields.Integer(allow_none=True)
    ippool = fields.Boolean(required=True)
    poolname = fields.String(allow_none=True)
    voip_profile = fields.String(allow_none=True)
    utm_status = fields.Boolean(required=True)
    nat_ip = IPv4NetworkSchema(allow_none=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FwPolicy(data['src_interface'], data['dst_interface'], data['src_alias_list'], data['dst_alias_list'],
                        data['action'], data['service'], data['log_traffic'], data['comment'], data['label'],
                        data['nat'], data['session_ttl'], data['ippool'], data['poolname'], data['voip_profile'],
                        data['utm_status'], data['nat_ip'])


@dataclass
class PortRange:
    start: int
    end: int


class PortRangeSchema(Schema):
    start = fields.Integer(required=True)
    end = fields.Integer(required=True)

    @post_load
    def make_object(self, data, **kwargs):
        return PortRange(data['start'], data['end'])


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


class FwServiceSchema(Schema):
    name = fields.String(required=True)
    comment = fields.String(allow_none=True)
    category = fields.String(allow_none=True)
    protocol = fields.String(allow_none=True)
    icmp_type = fields.Integer(allow_none=True)
    tcp_range = fields.Nested(PortRangeSchema, allow_none=True)
    udp_range = fields.Nested(PortRangeSchema, allow_none=True)
    session_ttl = fields.String(allow_none=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FwService(data['name'], data['comment'], data['category'], data['protocol'],
                         data['icmp_type'], data['tcp_range'], data['udp_range'], data['session_ttl'])


@dataclass
class FwServiceGroup:
    name: str
    comment: Optional[str]
    members: List[str]


class FwServiceGroupSchema(Schema):
    name = fields.String(required=True)
    comment = fields.String(allow_none=True)
    members = fields.List(fields.String, required=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FwServiceGroup(data['name'], data['comment'], data['members'])


@dataclass
class FwDhcpServer:
    lease_time: int
    dns_server: List[IPv4Address]
    domain: Optional[str]
    netmask: Optional[IPv4Address]
    gateway: Optional[IPv4Address]
    ip_range_start: IPv4Address
    ip_range_end: IPv4Address


class FwDhcpServerSchema(Schema):
    lease_time = fields.Integer(required=True)
    dns_server = fields.List(IPv4AddressSchema, required=True)
    domain = fields.String(allow_none=True)
    netmask = IPv4AddressSchema(allow_none=True)
    gateway = IPv4AddressSchema(allow_none=True)
    ip_range_start = IPv4AddressSchema(required=True)
    ip_range_end = IPv4AddressSchema(required=True)

    @post_load
    def make_object(self, data, **kwargs):
        return FwDhcpServer(data['lease_time'], data['dns_server'], data['domain'], data['netmask'],
                            data['gateway'], data['ip_range_start'], data['ip_range_end'])
