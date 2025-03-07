# flake8: noqa
# noreorder
"""
Underscore-to-camelCase converter (and vice versa) for strings and dict keys in Python.
"""
__title__ = "pyhumps"
__version__ = "3.7.3"
__author__ = "Nick Ficano"
__license__ = "Unlicense License"
__copyright__ = "Copyright 2019 Nick Ficano"

from humps.main import (
    camelize,
    decamelize,
    kebabize,
    dekebabize,
    depascalize,
    is_camelcase,
    is_pascalcase,
    is_kebabcase,
    is_snakecase,
    pascalize,
)
