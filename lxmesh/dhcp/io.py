from __future__ import annotations

__all__ = ['FileReplacement']

import contextlib
import grp
import io
import logging
import os
import types
import typing

from lxmesh.dhcp.exceptions import DHCPError


@io.TextIOBase.register  # type: ignore  # This is fine, mypy complains for no reason.
class FileReplacement:
    def __init__(self, path: str, mode: int, group: str | None) -> None:
        dirname, filename = os.path.split(path)
        if not filename:
            raise DHCPError("file must not be a directory: {}".format(path))
        self.dirname = dirname
        self.filename = filename

        with contextlib.ExitStack() as exit_stack:
            try:
                dir_fd = os.open(self.dirname, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            except OSError as e:
                raise DHCPError("failed to open file parent directory '{}': {}".format(self.dirname, e.strerror)) from None
            else:
                @exit_stack.push
                def close_on_error(exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: types.TracebackType | None) -> bool:
                    if exc_type is not None:
                        os.close(dir_fd)
                    return False

            try:
                file = open(os.open('.', os.O_WRONLY | os.O_TMPFILE | os.O_CLOEXEC,
                                    mode=mode, dir_fd=dir_fd),
                            mode='w')
            except OSError as e:
                raise DHCPError("failed to create new temporary file in directory '{}': {}.".format(self.dirname, e.strerror))
            if group is not None:
                try:
                    group_obj = grp.getgrnam(group)
                except KeyError:
                    logging.warning("Could not find group '{}'; retaining default group ownership of file '{}'.".format(group, os.path.join(self.dirname, self.filename)))
                else:
                    try:
                        os.fchown(file.fileno(), -1, group_obj.gr_gid)
                    except OSError as e:
                        raise DHCPError("failed to change group ownership of new temporary file '{}': {}".format(os.path.join(self.dirname, self.filename), e.strerror))

        self.file:      io.TextIOWrapper | None = file
        self.dir_fd:    int | None              = dir_fd

    def __enter__(self) -> FileReplacement:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: types.TracebackType | None) -> typing.Literal[False]:
        self.close()
        return False

    def close(self) -> None:
        if self.dir_fd is not None:
            os.close(self.dir_fd)
            self.dir_fd = None
        if self.file is not None:
            self.file.close()
            self.file = None

    def link(self) -> None:
        if self.file is None or self.dir_fd is None:
            raise DHCPError("file replacement is already closed")
        self.file.flush()
        try:
            os.fsync(self.file)
        except OSError as e:
            raise DHCPError("failed to flush contents of temporary file '{}': {}".format(os.path.join(self.dirname, self.filename), e.strerror))

        temp_filename = '.{}.tmp'.format(self.filename)
        while True:
            try:
                os.unlink(temp_filename, dir_fd=self.dir_fd)
            except FileNotFoundError:
                pass
            except OSError as e:
                raise DHCPError("failed to remove old temporary file '{}': {}".format(os.path.join(self.dirname, temp_filename), e.strerror))
            try:
                os.link('/proc/self/fd/{}'.format(self.file.fileno()), temp_filename, dst_dir_fd=self.dir_fd)
            except FileExistsError:
                continue
            except OSError as e:
                raise DHCPError("failed to create temporary file '{}': {}".format(os.path.join(self.dirname, temp_filename), e.strerror))
            try:
                os.rename(temp_filename, self.filename, src_dir_fd=self.dir_fd, dst_dir_fd=self.dir_fd)
            except FileNotFoundError:
                continue
            except OSError as e:
                raise DHCPError("failed to replace file '{}': {}.".format(os.path.join(self.dirname, self.filename), e.strerror))
            else:
                break

        try:
            os.fsync(self.dir_fd)
        except OSError as e:
            raise DHCPError("failed to flush contents of file parent directory '{}': {}".format(self.dirname, e.strerror))

    def __getattribute__(self, name: str) -> typing.Any:
        try:
            return super().__getattribute__(name)
        except AttributeError:
            if self.file is None:
                raise ValueError("file is not opened")
            return getattr(self.file, name)
