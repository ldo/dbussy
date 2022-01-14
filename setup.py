#+
# Distutils script to install DBussy. Invoke from the command line
# in this directory as follows:
#
#     python3 setup.py build
#     sudo python3 setup.py install
#
# Written by Lawrence D'Oliveiro <ldo@geek-central.gen.nz>.
#-

import sys
import setuptools

if sys.version_info < (3, 5):
    sys.stderr.write("This module requires Python 3.5 or later.\n")
    sys.exit(-1)

setuptools.setup(
    name = "DBussy",
    version = "1.3",
    description = "language bindings for libdbus, for Python 3.5 or later",
    long_description = "language bindings for libdbus, for Python 3.5 or later",
    author = "Lawrence D'Oliveiro",
    author_email = "ldo@geek-central.gen.nz",
    url = "https://github.com/ldo/dbussy",
    license = "LGPL v2.1+",
    python_requires='>=3.5',
    py_modules = ["dbussy", "ravel"],
)
