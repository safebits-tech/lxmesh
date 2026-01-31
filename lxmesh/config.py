from __future__ import annotations

__all__ = ['AgentConfig']

import collections.abc
import ipaddress
import logging
import re
import typing
from datetime import timedelta
from decimal import Decimal

import pydantic
import yaml

from lxmesh.exceptions import ApplicationError


T = typing.TypeVar('T')


class Duration(timedelta):
    duration_re = re.compile(r'(\s*\+)?\s*(?P<value>(-\s*)?\d+(\.\d+)?)\s*(?P<suffix>us|microseconds?|ms|milliseconds?|s|secs?|seconds?|m|mins?|minutes?|h|hours?|d|days?|w|weeks?|f|fortnights?)(?=-|\d|\s|$)')

    def __new__(cls, description: typing.Any) -> typing.Self:
        microseconds = Decimal(0)
        description = str(description)
        while description:
            match = cls.duration_re.match(description)
            if match is None:
                raise ValueError("string '{}' is not a duration".format(description))
            value = Decimal(match.group('value').replace(' ', ''))
            suffix = match.group('suffix')
            if len(suffix) > 2 and suffix[-1] == 's' and value == Decimal(1):
                raise ValueError("invalid English grammar: {}".format(match.group()))
            if len(suffix) > 2 and suffix[-1] != 's' and value != Decimal(1):
                raise ValueError("invalid English grammar: {}".format(match.group()))
            if suffix in ('us', 'microsecond', 'microseconds'):
                microseconds += value
            elif suffix in ('ms', 'millisecond', 'milliseconds'):
                microseconds += value * 1000
            elif suffix in ('s', 'sec', 'secs', 'second', 'seconds'):
                microseconds += value * 1000 * 1000
            elif suffix in ('m', 'min', 'mins', 'minute', 'minutes'):
                microseconds += value * 1000 * 1000 * 60
            elif suffix in ('h', 'hour', 'hours'):
                microseconds += value * 1000 * 1000 * 60 * 60
            elif suffix in ('d', 'day', 'days'):
                microseconds += value * 1000 * 1000 * 60 * 60 * 24
            elif suffix in ('w', 'week', 'weeks'):
                microseconds += value * 1000 * 1000 * 60 * 60 * 24 * 7
            elif suffix in ('f', 'fortnight', 'fortnights'):
                microseconds += value * 1000 * 1000 * 60 * 60 * 24 * 7 * 2
            else:
                raise ValueError("unknown suffix in '{}'".format(match.group()))
            description = description[match.end():]
        return super().__new__(cls,
                               days=int(microseconds // (1000 * 1000 * 60 * 60 * 24)),
                               seconds=int(microseconds // (1000 * 1000) % (60 * 60 * 24)),
                               microseconds=int(microseconds % (1000 * 1000)))

    # This method is needed becase pydantic deepcopies the objects.
    def __reduce__(self) -> tuple[typing.Any, ...]:
        return (type(self), (f'{self.days} days {self.seconds} seconds {self.microseconds} microseconds',))

    # This method is needed to allow pydantic v1 to use this as a type.
    @classmethod
    def __get_validators__(cls) -> collections.abc.Iterator[collections.abc.Callable[[typing.Any], typing.Self]]:
        yield lambda value: cls(value)


class LogLevel(int):
    def __new__(cls, value: typing.Any) -> typing.Self:
        try:
            if isinstance(value, int):
                result = value
            else:
                result = {
                    'debug':    logging.DEBUG,
                    'info':     logging.INFO,
                    'warning':  logging.WARNING,
                    'error':    logging.ERROR,
                    'critical': logging.CRITICAL,
                }[str(value).lower()]
        except KeyError:
            raise ValueError("invalid log level: {}".format(value)) from None
        else:
            return int.__new__(cls, result)

    # this method is needed to allow pydantic v1 to use this as a type.
    @classmethod
    def __get_validators__(cls) -> collections.abc.Iterator[collections.abc.Callable[[typing.Any], typing.Self]]:
        yield lambda value: cls(value)


class BaseModel(pydantic.BaseModel):
    class Config:
        frozen = True
        alias_generator = lambda field: field.replace('_', '-')


class GeneralConfig(BaseModel):
    log_level:              LogLevel                        = LogLevel(logging.INFO)
    ip4_all_nodes_address:  ipaddress.IPv4Address | None    = None
    ip6_all_nodes_address:  ipaddress.IPv6Address | None    = None


class DHCPServerConfig(BaseModel):
    executable:         str | None  = None
    arguments:          list[str]   = pydantic.Field(default_factory=list)
    restart_interval:   Duration    = Duration('10s')
    terminate_timeout:  Duration    = Duration('10s')


class DHCPConfig(BaseModel):
    config_file:        str | None  = None
    hosts_file:         str | None  = None
    file_group:         str | None  = None
    ip4_lease_time:     Duration    = Duration('1h')
    ip6_lease_time:     Duration    = Duration('1h')
    reload_interval:    Duration    = Duration('60s')
    reload_jitter:      Duration    = Duration('5s')
    retry_interval:     Duration    = Duration('10s')

    server:             DHCPServerConfig


class LXDConfig(BaseModel):
    enforce_eth_address:        bool        = True
    enforce_ip6_ll_address:     bool        = True
    reload_interval:            Duration    = Duration('60s')
    reload_jitter:              Duration    = Duration('5s')
    initial_reload_interval:    Duration    = Duration('10s')
    id_attribute:               str


class TagConfig(BaseModel):
    name:           str
    netfilter_mark: int


class NetlinkConfig(BaseModel):
    reload_interval:    Duration    = Duration('60s')
    reload_jitter:      Duration    = Duration('5s')
    retry_interval:     Duration    = Duration('10s')
    table:              str         = 'lxmesh'


class SVIConfig(BaseModel):
    name:               str | None  = None
    netfilter_mark:     int | None  = None
    host_routes:        bool | None = None
    host_routes_table:  str | None  = None
    multicast:          bool | None = None


class AgentConfig(pydantic.BaseModel):
    general:    GeneralConfig
    dhcp:       DHCPConfig
    lxd:        LXDConfig
    tags:       list[TagConfig]
    netlink:    NetlinkConfig
    svi:        list[SVIConfig]

    @property
    def tag_items(self) -> list[tuple[str, int]]:
        return [(tag.name, tag.netfilter_mark) for tag in self.tags]

    @property
    def default_svi_config(self) -> SVIConfig:
        if 'default_svi_config' not in self.__dict__:
            for svi_config in self.svi:
                if svi_config.name is None:
                    self.__dict__['default_svi_config'] = svi_config
                    break
            else:
                self.__dict__['default_svi_config'] = SVIConfig()
        return typing.cast(SVIConfig, self.__dict__['default_svi_config'])

    @property
    def svi_config(self) -> dict[str, SVIConfig]:
        if 'svi_config' not in self.__dict__:
            self.__dict__['svi_config'] = {}
            for svi_config in self.svi:
                if svi_config.name is not None:
                    self.__dict__['svi_config'][svi_config.name] = svi_config
        return typing.cast(dict[str, SVIConfig], self.__dict__['svi_config'])

    @classmethod
    def from_file(cls, filename: str) -> typing.Self:
        try:
            config = yaml.load(open(filename, 'r'), Loader=yaml.SafeLoader)
        except yaml.YAMLError as e:
            mark = getattr(e, 'problem_mark', None)
            if mark is not None:
                raise ApplicationError("invalid configuration file syntax at line '{}' position '{}': {}".format(mark.line + 1, mark.column + 1, e)) from None
            else:
                raise ApplicationError("invalid configuration file syntax: {}".format(e)) from None
        obj = cls.parse_obj(config)

        # Check there is only one default SVI configuration.
        default_svi_configs = sum(1 if svi_config.name is None else 0 for svi_config in obj.svi)
        if default_svi_configs > 1:
            raise ApplicationError("cannot have more than one default SVI configuration (without name)")

        return obj
