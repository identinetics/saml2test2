import importlib
from aatest.contenthandler.robobrowser import ContentHandler


def factory(spec):
    ch = ContentHandler(spec)
    return ch