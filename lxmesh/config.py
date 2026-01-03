from __future__ import annotations

__all__ = ['AgentConfig']

import dataclasses
import functools
import ipaddress
import logging
import operator
import re
import sys
import types
import typing
from datetime import timedelta
from decimal import Decimal

import yaml

from lxmesh.exceptions import ApplicationError


T = typing.TypeVar('T')


class Boolean(int):
    def __new__(cls, value: typing.Any) -> bool:  # type: ignore # Yes, we want to return an instance of a superclass.
        if value in (True, False):
            return typing.cast(bool, value)
        elif isinstance(value, int):
            return bool(value)
        else:
            value = str(value)
        if value.lower() in ('true', 'yes', 'on', 'active', '1'):
            return True
        elif value.lower() in ('false', 'no', 'off', 'inactive', '1'):
            return False
        else:
            raise ValueError("invalid boolean value: {!r}".format(value))


class Duration(timedelta):
    duration_re = re.compile(r'(\s*\+)?\s*(?P<value>(-\s*)?\d+(\.\d+)?)\s*(?P<suffix>us|microseconds?|ms|milliseconds?|s|secs?|seconds?|m|mins?|minutes?|h|hours?|d|days?|w|weeks?|f|fortnights?)(?=-|\d|\s|$)')

    # FIXME: Replace return annotation with typing.Self in Python 3.11+.
    def __new__(cls, description: typing.Any) -> Duration:
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


class ConfigSection:
    def __init_subclass__(cls) -> None:
        if not dataclasses.is_dataclass(cls):
            return

        def validate_union(type: types.UnionType) -> None:
            type_args = typing.get_args(type)
            assert len(type_args) > 0
            for subtype in type_args:
                assert typing.get_origin(subtype) is None

        for field in dataclasses.fields(cls):
            field_type = ConfigSection.evaluate_type(field.type, cls)
            type_origin = typing.get_origin(field_type)
            type_args = typing.get_args(field_type)
            assert type_origin in (None, list, typing.Union, types.UnionType)
            if type_origin is list:
                assert len(type_args) == 1
                subtype = typing.get_origin(type_args[0])
                assert subtype in (None, typing.Union, types.UnionType)
                if subtype in (typing.Union, types.UnionType):
                    validate_union(subtype)
            elif type_origin in (typing.Union, types.UnionType):
                validate_union(typing.cast(types.UnionType, field_type))

    @staticmethod
    def evaluate_type(typename: typing.Any, cls: type) -> typing.Any:
        if not isinstance(typename, str):
            return typename

        cls_globals = vars(sys.modules[cls.__module__])
        cls_locals = functools.reduce(operator.or_, map(vars, reversed(cls.mro())))

        return eval(typename, cls_globals, cls_locals)

    @staticmethod
    def convert_basic(type: type[T], value: typing.Any) -> T:
        if type is bool:
            value = Boolean(value)
        elif not isinstance(value, type):
            try:
                value = type(value)  # type: ignore  # This is fine.
            except TypeError:
                raise ValueError("unconvertable value") from None
        return typing.cast(T, value)

    @classmethod
    def convert_complex(cls, type: typing.Any, value: typing.Any) -> typing.Any:
        type_origin = typing.get_origin(type)
        type_args = typing.get_args(type)

        if type_origin is list:
            if not isinstance(value, list):
                raise ValueError("must be a list")
            return [cls.convert_complex(type_args[0], subvalue) for subvalue in value]
        elif type_origin in (typing.Union, types.UnionType):
            if isinstance(value, (list, dict)):
                raise ValueError("must be a value")
            elif not isinstance(value, type_args):
                if value is None:
                    raise ValueError("must not be empty")
                value = cls.convert_basic(type_args[0], value)
            return value
        elif value is None:
            raise ValueError("must not be empty")
        else:
            return cls.convert_basic(type, value)

    @classmethod
    def from_yaml(cls, /,
                  config: dict[str, typing.Any]) -> typing.Self:
        if not dataclasses.is_dataclass(cls):
            raise RuntimeError("method can only be called on dataclass subclasses")
        fields = {field.name.replace('_', '-'): field for field in dataclasses.fields(cls)}
        missing_fields = {field_name for field_name, field in fields.items()
                          if (field.default is dataclasses.MISSING
                              and field.default_factory is dataclasses.MISSING)}

        arguments = {}

        for key, value in config.items():
            try:
                field = fields[key]
            except KeyError:
                logging.warning("Unknown configuration option: '{}'.".format(key))
                continue

            field_type = ConfigSection.evaluate_type(field.type, cls)

            if isinstance(field_type, type) and issubclass(field_type, ConfigSection):
                if value is not None and not isinstance(value, dict):
                    logging.warning("Ignoring confiduration for key '{}', which must be an object.".format(key))
                    continue
                value = field_type.from_yaml(value or {})
            else:
                type_origin = typing.get_origin(field_type)
                type_args = typing.get_args(field_type)
                if type_origin is list and issubclass(type_args[0], ConfigSection):
                    if value is not None and not isinstance(value, list):
                        logging.warning("Ignoring configuration for key '{}', which must be a list.".format(key))
                        continue
                    subobjects = []
                    for subvalue in value or []:
                        if subvalue is None:
                            continue
                        if not isinstance(subvalue, dict):
                            logging.warning("Ignoring item in configuration for key '{}', which must be an object.".format(key))
                            continue
                        try:
                            subobjects.append(type_args[0].from_yaml(subvalue))
                        except ApplicationError as e:
                            logging.warning("Ignoring invalid item in configuration for key '{}': {}.".format(key, e))
                    value = subobjects
                else:
                    try:
                        value = ConfigSection.convert_complex(field_type, value)
                    except ValueError as e:
                        logging.warning("Ignoring invalid value for configuration option '{}': {} ({}).".format(key, value, e))
                        continue

            missing_fields.discard(key)
            arguments[field.name] = value

        for key in list(missing_fields):
            field = fields[key]
            field_type = ConfigSection.evaluate_type(field.type, cls)
            if issubclass(field_type, ConfigSection):
                value = field_type.from_yaml({})
            else:
                type_origin = typing.get_origin(field_type)
                type_args = typing.get_args(field_type)
                if type_origin is list and issubclass(type_args[0], ConfigSection):
                    value = []
                else:
                    continue
            missing_fields.discard(key)
            arguments[field.name] = value

        if missing_fields:
            raise ApplicationError("missing configuration options: {}".format(", ".join(missing_fields)))

        return cls(**arguments)  # type: ignore[return-value]  # mypy restricts type to DataclassInstance after dataclass test


@dataclasses.dataclass(kw_only=True, frozen=True, slots=True)
class GeneralConfig(ConfigSection):
    log_level:              LogLevel                        = LogLevel(logging.INFO)
    ip4_all_nodes_address:  ipaddress.IPv4Address | None    = None
    ip6_all_nodes_address:  ipaddress.IPv6Address | None    = None


@dataclasses.dataclass(kw_only=True, frozen=True, slots=True)
class DHCPServerConfig(ConfigSection):
    executable:         str | None  = None
    arguments:          list[str]   = dataclasses.field(default_factory=list)
    restart_interval:   Duration    = Duration('10s')
    terminate_timeout:  Duration    = Duration('10s')


@dataclasses.dataclass(kw_only=True, frozen=True, slots=True)
class DHCPConfig(ConfigSection):
    config_file:        str | None  = None
    hosts_file:         str | None  = None
    file_group:         str | None  = None
    ip4_lease_time:     Duration    = Duration('1h')
    ip6_lease_time:     Duration    = Duration('1h')
    reload_interval:    Duration    = Duration('60s')
    reload_jitter:      Duration    = Duration('5s')
    retry_interval:     Duration    = Duration('10s')

    server:             DHCPServerConfig


@dataclasses.dataclass(kw_only=True, frozen=True, slots=True)
class LXDConfig(ConfigSection):
    enforce_eth_address:        bool        = True
    enforce_ip6_ll_address:     bool        = True
    reload_interval:            Duration    = Duration('60s')
    reload_jitter:              Duration    = Duration('5s')
    initial_reload_interval:    Duration    = Duration('10s')
    id_attribute:               str


@dataclasses.dataclass(kw_only=True, frozen=True, slots=True)
class TagConfig(ConfigSection):
    name:           str
    netfilter_mark: int


@dataclasses.dataclass(kw_only=True, frozen=True, slots=True)
class NetlinkConfig(ConfigSection):
    reload_interval:    Duration    = Duration('60s')
    reload_jitter:      Duration    = Duration('5s')
    retry_interval:     Duration    = Duration('10s')
    table:              str         = 'lxmesh'


@dataclasses.dataclass(kw_only=True, frozen=True, slots=True)
class SVIConfig(ConfigSection):
    name:               str | None  = None
    netfilter_mark:     int | None  = None
    host_routes:        bool | None = None
    host_routes_table:  str | None  = None
    multicast:          bool | None = None


@dataclasses.dataclass(kw_only=True, frozen=True, slots=False)
class AgentConfig(ConfigSection):
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
    def from_file(cls, filename: str) -> AgentConfig:
        try:
            config = yaml.load(open(filename, 'r'), Loader=yaml.SafeLoader)
        except yaml.YAMLError as e:
            mark = getattr(e, 'problem_mark', None)
            if mark is not None:
                raise ApplicationError("invalid configuration file syntax at line '{}' position '{}': {}".format(mark.line + 1, mark.column + 1, e)) from None
            else:
                raise ApplicationError("invalid configuration file syntax: {}".format(e)) from None
        obj = cls.from_yaml(config)

        # Check there is only one default SVI configuration.
        default_svi_configs = sum(1 if svi_config.name is None else 0 for svi_config in obj.svi)
        if default_svi_configs > 1:
            raise ApplicationError("cannot have more than one default SVI configuration (without name)")

        return obj
