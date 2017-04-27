#+
# Distutils script to install DBussy. Invoke from the command line
# in this directory as follows:
#
#     python3 setup.py build
#     sudo python3 setup.py install
#
# Written by Lawrence D'Oliveiro <ldo@geek-central.gen.nz>.
#-

import distutils.core

distutils.core.setup \
  (
    name = "DBussy",
    version = "0.6",
    description = "language bindings for libdbus, for Python 3.5 or later",
    author = "Lawrence D'Oliveiro",
    author_email = "ldo@geek-central.gen.nz",
    url = "http://github.com/ldo/dbussy",
    py_modules = ["dbussy", "ravel"],
  )
