"""
Class loader

The class loader inspects a given list of files (modules) and loads the
named class from these modules.

It will automagically select the class, that is derived from the others.
"""

from .loader import Loader

__all__ = ["Loader"]