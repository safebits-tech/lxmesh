from __future__ import annotations

__all__ = ['EventContext', 'InitialiseContext', 'LoadContext', 'OperationContext', 'StateManager', 'StateObject', 'StateTable']

import abc
import collections.abc
import dataclasses
import logging
import types
import typing
import weakref
from collections import deque

from lxmesh.exceptions import ApplicationError


# FIXME: replace with generics syntax when mypy supports it.


T = typing.TypeVar('T')

TE = typing.TypeVar('TE', bound='EventContext[typing.Any, typing.Any, typing.Any, typing.Any]')
TI = typing.TypeVar('TI', bound='InitialiseContext[typing.Any, typing.Any, typing.Any, typing.Any]')
TL = typing.TypeVar('TL', bound='LoadContext[typing.Any, typing.Any, typing.Any, typing.Any]')
TO = typing.TypeVar('TO', bound='OperationContext[typing.Any, typing.Any, typing.Any, typing.Any]')

TSO = typing.TypeVar('TSO', bound='StateObject[typing.Any, typing.Any, typing.Any, typing.Any]')


class BaseContext(typing.Generic[TE, TI, TL, TO]):
    def __init__(self, *,
                 manager: StateManager[TE, TI, TL, TO],
                 **kw: typing.Any) -> None:
        super().__init__(**kw)
        self.__manager = manager

    def add(self, /, obj: StateObject[TE, TI, TL, TO]) -> None:
        self.__manager.add(obj)

    def remove(self, /, obj: StateObject[TE, TI, TL, TO]) -> None:
        self.__manager.remove(obj)


class EventContext(BaseContext[TE, TI, TL, TO]):
    def __init__(self, *,
                 active: StateTable[TE, TI, TL, TO],
                 pending_add: StateTable[TE, TI, TL, TO],
                 pending_remove: StateTable[TE, TI, TL, TO],
                 **kw: typing.Any) -> None:
        super().__init__(**kw)
        self.active = active
        self.pending_add = pending_add
        self.pending_remove = pending_remove


class InitialiseContext(BaseContext[TE, TI, TL, TO]):
    def __init__(self, *,
                 event_context_factory: collections.abc.Callable[[], TE],
                 **kw: typing.Any) -> None:
        super().__init__(**kw)
        self.event_context_factory_ref: weakref.ref[collections.abc.Callable[[], TE]]
        if isinstance(event_context_factory, types.MethodType):
            self.event_context_factory_ref = weakref.WeakMethod(event_context_factory)
        else:
            self.event_context_factory_ref = weakref.ref(event_context_factory)


class LoadContext(BaseContext[TE, TI, TL, TO]):
    def __init__(self, *,
                 active: StateTable[TE, TI, TL, TO],
                 pending_add: StateTable[TE, TI, TL, TO],
                 pending_remove: StateTable[TE, TI, TL, TO],
                 **kw: typing.Any) -> None:
        super().__init__(**kw)
        self.active = active
        self.pending_add = pending_add
        self.pending_remove = pending_remove


class OperationContext(BaseContext[TE, TI, TL, TO]):
    pass


@typing.dataclass_transform(kw_only_default=True, frozen_default=True)
class StateObjectType(abc.ABCMeta):
    def __new__(typecls, name: str, bases: tuple[type, ...], namespace: dict[str, typing.Any]) -> StateObjectType:
        namespace['key'] = []
        cls = super().__new__(typecls, name, bases, namespace)
        if '__slots__' in cls.__dict__:
            return cls
        cls = dataclasses.dataclass(frozen=True, kw_only=True, slots=True)(cls)  # type: ignore[assignment, arg-type] # type hints use type[T]
        cls.__dict__['key'].extend(field.name for field in dataclasses.fields(cls) if field.metadata.get('lxmesh_key', True))  # type: ignore[arg-type] # StateObjectType is compatible with type[DataclassInstance]
        return cls

    @property
    def key(cls) -> tuple[str, ...]:
        return tuple(cls.__dict__['key'])


class StateObject(typing.Generic[TE, TI, TL, TO], metaclass=StateObjectType):
    @typing.overload
    @staticmethod
    def field(*, default: T, key: bool, **kw: typing.Any) -> T:
        ...

    @typing.overload
    @staticmethod
    def field(*, default_factory: collections.abc.Callable[[], T], key: bool, **kw: typing.Any) -> T:
        ...

    @typing.overload
    @staticmethod
    def field(*, key: bool, **kw: typing.Any) -> typing.Any:
        ...

    @staticmethod  # type: ignore[misc] # Cannot define default and default_factory, as these are processed by dataclasses.
    def field(*, key: bool = True, **kw: typing.Any) -> typing.Any:
        metadata = kw.pop('metadata', None)
        if metadata is None:
            metadata = {}
        metadata['lxmesh_key'] = key
        return dataclasses.field(metadata=metadata, **kw)

    @classmethod
    @abc.abstractmethod
    def init(cls, context: TI) -> None:
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def load(cls, context: TL) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def add(self, context: TO) -> None:
        raise NotImplementedError

    def modify(self, context: TO, old: typing.Self) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def delete(self, context: TO) -> None:
        pass


class StateTableType(type):
    def __new__(clstype, name: str, bases: tuple[type, ...], namespace: dict[str, typing.Any]) -> StateTableType:
        namespace['types'] = []
        cls = super().__new__(clstype, name, bases, namespace)

        consumed_names: set[str] = set()
        for supercls in cls.mro():
            for attr_name, attr_value in supercls.__dict__.items():
                if attr_name in consumed_names:
                    continue
                consumed_names.add(attr_name)
                if isinstance(attr_value, StateObjectType):
                    namespace['types'].append(attr_value)

        return cls

    @property
    def types(cls) -> tuple[type[StateObject[TE, TI, TL, TO]]]:
        return typing.cast(tuple[type[StateObject[TE, TI, TL, TO]]], tuple(cls.__dict__['types']))


class StateTable(typing.Generic[TE, TI, TL, TO], metaclass=StateTableType):
    types: typing.ClassVar[tuple[type[StateObject[TE, TI, TL, TO]]]]  # type: ignore[misc] # FIXME: supported in mypy 1.18+

    def __init__(self) -> None:
        self.tables: dict[str, dict[tuple[typing.Any, ...], StateObject[TE, TI, TL, TO]]] = {}
        for type_class in type(self).types:
            self.tables[type_class.__name__] = {}

    def __repr__(self) -> str:
        return repr(self.tables)

    def __len__(self) -> int:
        return sum(map(len, self.tables.values()))

    def len_by_type(self, type: type[StateObject[TE, TI, TL, TO]]) -> int:
        return len(self.tables[type.__name__])

    def add(self, obj: StateObject[TE, TI, TL, TO], /) -> None:
        key = tuple(getattr(obj, key_item) for key_item in type(obj).key)
        old_obj = self.tables[type(obj).__name__].get(key, None)
        if old_obj is not None:
            raise ValueError("state object with same key already exists in table ('{!r}')".format(old_obj))
        self.tables[type(obj).__name__][key] = obj

    def get(self, obj: TSO, default: TSO | None = None, /) -> TSO:
        key = tuple(getattr(obj, key_item) for key_item in type(obj).key)
        return self.tables[type(obj).__name__].get(key, default)  # type: ignore[arg-type, return-value] # It's acceptable to pass None as second argument to Mapping.get()

    def pop(self, obj: TSO, /) -> TSO:
        key = tuple(getattr(obj, key_item) for key_item in type(obj).key)
        return typing.cast(TSO, self.tables[type(obj).__name__].pop(key))

    def popitem(self, *, reverse_tables: bool = False) -> StateObject[TE, TI, TL, TO]:
        table_iterator = reversed(self.tables.values()) if reverse_tables else self.tables.values()
        for table in table_iterator:
            try:
                key, value = table.popitem()
            except KeyError:
                continue
            else:
                return value
        raise KeyError("state is empty")

    def popitem_by_type(self, type: type[TSO]) -> TSO:
        key, value = self.tables[type.__name__].popitem()
        return typing.cast(TSO, value)

    def remove_must_match(self, obj: StateObject[TE, TI, TL, TO], /) -> None:
        key = tuple(getattr(obj, key_item) for key_item in type(obj).key)
        old_obj = self.tables[type(obj).__name__][key]
        if old_obj != obj:
            raise ValueError("state object does not match (requested '{!r}', have '{!r}')".format(obj, old_obj))
        self.tables[type(obj).__name__].pop(key)

    def remove_if_exact(self, obj: StateObject[TE, TI, TL, TO], /) -> None:
        key = tuple(getattr(obj, key_item) for key_item in type(obj).key)
        old_obj = self.tables[type(obj).__name__][key]
        if old_obj != obj:
            raise KeyError("state object does not exist")
        self.tables[type(obj).__name__].pop(key)

    def contains_must_match(self, obj: StateObject[TE, TI, TL, TO], /) -> bool:
        key = tuple(getattr(obj, key_item) for key_item in type(obj).key)
        old_obj = self.tables[type(obj).__name__].get(key, None)
        if old_obj is None:
            return False
        if old_obj != obj:
            raise ValueError("state object does not match (requested '{!r}', have '{!r}')".format(obj, old_obj))
        return True

    def contains_need_not_match(self, obj: StateObject[TE, TI, TL, TO], /) -> bool:
        key = tuple(getattr(obj, key_item) for key_item in type(obj).key)
        return key in self.tables[type(obj).__name__]

    def contains_exact(self, obj: StateObject[TE, TI, TL, TO], /) -> bool:
        key = tuple(getattr(obj, key_item) for key_item in type(obj).key)
        old_obj = self.tables[type(obj).__name__].get(key, None)
        return obj is not None and old_obj == obj

    def clear(self) -> None:
        for table in self.tables.values():
            table.clear()

    def update(self, other: typing.Self, /) -> None:
        for table_name, table in self.tables.items():
            table.update(other.tables[table_name])

    def __bool__(self) -> bool:
        return any(self.tables.values())

    def __iter__(self) -> collections.abc.Iterator[StateObject[TE, TI, TL, TO]]:
        for subtable in self.tables.values():
            yield from subtable.values()


class StateManager(abc.ABC, typing.Generic[TE, TI, TL, TO]):
    __state_type__: typing.ClassVar[type[StateTable[TE, TI, TL, TO]]]  # type: ignore[misc] # FIXME: supported in mypy 1.18+

    def __init_subclass__(cls, *, state_type: type[StateTable[TE, TI, TL, TO]], **kw: typing.Any):
        cls.__state_type__ = state_type
        super().__init_subclass__(**kw)

    def __init__(self, *args: typing.Any, init_context: TI, **kw: typing.Any) -> None:
        self.active = self.__state_type__()
        self.pending_add = self.__state_type__()
        self.pending_remove = self.__state_type__()
        self.transactions: deque[deque[tuple[typing.Literal['add', 'remove'], StateObject[TE, TI,  TL, TO]]]] = deque()

        for type_class in self.__state_type__.types:
            try:
                type_class.init(init_context)
            except NotImplementedError:
                logging.critical("Missing initialisation handler for object type '{}'.".format(type_class.__name__))
            except ApplicationError as e:
                logging.error(e.message_sentence)
            except Exception:
                logging.exception("Unexpected exception while initialising objects of type '{}':".format(type_class.__name__))

        super().__init__(*args, **kw)

    @property
    def dirty(self) -> bool:
        return bool(self.pending_add or self.pending_remove)

    def __enter__(self) -> None:
        self.transactions.append(deque())

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: types.TracebackType | None) -> None:
        operations = self.transactions.pop()
        if exc_type is not None:
            # Rollback operations and forget them. Temporarily hide transaction
            # stack so that add() and remove() do not operate on it.
            self.transactions, transactions = deque(), self.transactions
            while operations:
                op, obj = operations.pop()
                match op:
                    case 'add':
                        self.remove(obj)
                    case 'remove':
                        self.add(obj)
            self.transactions = transactions
        elif self.transactions:
            # Operations are committed, but may be rolled back by an outer
            # transaction.
            self.transactions[-1].extend(operations)

    def add(self, obj: StateObject[TE, TI, TL, TO]) -> None:
        # If we're adding an object, an object with an identical key must not
        # have been added previously, even if with a different value, without
        # it being removed first. The method 'contains_must_match()' raises a
        # ValueError if an object with the same key but a different value
        # exists.
        if self.active.contains_must_match(obj) or self.pending_add.contains_must_match(obj):
            raise ValueError("object '{!r}' already requested to be added".format(obj))
        # If an identical object (same key and same value) is marked for
        # removal, we unmark it and consider the state synchronised. Otherwise,
        # we schedule the addition of the new object. An object with the same
        # key but a different value must still be marked for removal.
        try:
            self.pending_remove.remove_if_exact(obj)
        except KeyError:
            self.pending_add.add(obj)
        else:
            self.active.add(obj)
        if self.transactions:
            self.transactions[-1].append(('add', obj))

    def remove(self, obj: StateObject[TE, TI, TL, TO]) -> None:
        # If we're removing an object, an object with the same key may already
        # be marked for removal, but this is not an error. The object we're
        # removing could have a different value and must either be scheduled
        # for addition, or be already synchronised (active).
        if self.pending_remove.contains_exact(obj):
            raise ValueError("object '{!r}' already requested to be removed".format(obj))
        # The method 'remove_must_match()" raises a ValueError if an object with
        # the same key, but a different value exists. This ensures that the object
        # requested for removal was previously added.
        #
        # It's not technically possible for an object with the same key, but a
        # different value to be scheduled for removal, while the object that we
        # wish to remove to be synchronised (active). This case is handled by
        # the fact that the 'add()' method raises a ValueError if an object
        # with the same key exists.
        try:
            self.active.remove_must_match(obj)
        except KeyError:
            self.pending_add.remove_must_match(obj)
        else:
            try:
                self.pending_remove.add(obj)
            except ValueError:
                self.active.add(obj)
                raise
        if self.transactions:
            self.transactions[-1].append(('remove', obj))

    @abc.abstractmethod
    def reload(self) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def commit(self) -> None:
        raise NotImplementedError

    def reload_objects(self, load_context: TL) -> None:
        for type_class in self.__state_type__.types:
            try:
                type_class.load(load_context)
            except NotImplementedError:
                logging.critical("Missing load handler for object type '{}'.".format(type_class.__name__))
            except ApplicationError as e:
                logging.error(e.message_sentence)
            except Exception:
                logging.exception("Unexpected exception while loading objects of type '{}':".format(type_class.__name__))

    def commit_objects(self, op_context: TO) -> None:
        failed_add = self.__state_type__()
        failed_remove = self.__state_type__()

        replacements: deque[tuple[StateObject[TE, TI, TL, TO], StateObject[TE, TI, TL, TO]]] = deque()
        while True:
            try:
                obj = self.pending_remove.popitem(reverse_tables=True)
            except KeyError:
                break
            if type(obj).modify is not StateObject.modify:
                try:
                    replace_obj = self.pending_add.pop(obj)
                except KeyError:
                    # No replacement found, remove object.
                    pass
                else:
                    # Replacement found, might be able to modify atomically.
                    replacements.append((obj, replace_obj))
                    continue
            logging.debug("Removing state object '{!r}'.".format(obj))
            try:
                obj.delete(op_context)
            except ApplicationError as e:
                logging.error(e.message_sentence)
                failed_remove.add(obj)
            except Exception:
                logging.exception("Unexpected exception while deleting object of type '{}':".format(type(obj).__name__))
                failed_remove.add(obj)

        while True:
            try:
                old_obj, new_obj = replacements.pop()
            except IndexError:
                break
            else:
                logging.debug("Replacing state object '{!r}' with {!r}.".format(old_obj, new_obj))
                try:
                    new_obj.modify(op_context, old_obj)
                except ApplicationError as e:
                    logging.error(e.message_sentence)
                    failed_remove.add(old_obj)
                    failed_add.add(new_obj)
                except Exception:
                    logging.exception("Unexpected exception while replacing object of type '{}':".format(type(new_obj).__name__))
                    failed_remove.add(old_obj)
                    failed_add.add(new_obj)
                else:
                    self.active.add(new_obj)

        while True:
            try:
                obj = self.pending_add.popitem()
            except KeyError:
                break
            logging.debug("Adding state object '{!r}'.".format(obj))
            try:
                obj.add(op_context)
            except ApplicationError as e:
                logging.error(e.message_sentence)
                failed_add.add(obj)
            except Exception:
                logging.exception("Unexpected exception while adding object of type '{}':".format(type(obj).__name__))
                failed_add.add(obj)
            else:
                self.active.add(obj)

        self.pending_add = failed_add
        self.pending_remove = failed_remove
