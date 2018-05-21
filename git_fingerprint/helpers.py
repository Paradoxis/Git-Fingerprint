#!/usr/bin/env python3
from argparse import HelpFormatter
from collections import OrderedDict, Callable
from functools import wraps
from tempfile import mkdtemp
from shutil import rmtree


class OrderedDefaultDict(OrderedDict):
    def __init__(self, default_factory=None, *a, **kw):
        if (default_factory is not None and
           not isinstance(default_factory, Callable)):
            raise TypeError('first argument must be callable')
        OrderedDict.__init__(self, *a, **kw)
        self.default_factory = default_factory

    def __getitem__(self, key):
        try:
            return OrderedDict.__getitem__(self, key)
        except KeyError:
            return self.__missing__(key)

    def __missing__(self, key):
        if self.default_factory is None:
            raise KeyError(key)
        self[key] = value = self.default_factory()
        return value

    def __reduce__(self):
        if self.default_factory is None:
            args = tuple()
        else:
            args = self.default_factory,
        return type(self), args, None, None, self.items()

    def copy(self):
        return self.__copy__()

    def __copy__(self):
        return type(self)(self.default_factory, self)

    def __deepcopy__(self, memo):
        import copy
        return type(self)(self.default_factory, copy.deepcopy(self.items()))

    def __repr__(self):
        return 'OrderedDefaultDict(%s, %s)' % (self.default_factory, OrderedDict.__repr__(self))


class CustomHelpFormatter(HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, indent_increment=2, max_help_position=7, width=None)

    def _format_action(self, action):
        return super(CustomHelpFormatter, self)._format_action(action) + "\n"


def temporary_directory(func):
    """
    Create a temporary directory and allow it to be used as a decorator
    :return: Function with a directory name
    """
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        temp = mkdtemp("_git-fingerprint")
        try:
            return func(self, temp, *args, **kwargs)
        finally:
            rmtree(temp, ignore_errors=True)
    return wrapper


def chunks(iterable: list, amount: int):
    """
    Split a list into x chunks
    :param iterable: List of stuff to chunk
    :param amount: How many chunks?
    :return: List of lists
    """
    avg = len(iterable) / float(amount)
    out = []
    last = 0.0

    while last < len(iterable):
        out.append(iterable[int(last):int(last + avg)])
        last += avg

    return out
