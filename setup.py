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
import distutils.core
from distutils.command.build import \
    build as std_build

class my_build(std_build) :
    "customization of build to perform additional validation."

    def run(self) :
        try :
            exec \
              (
                "async def dummy() :\n"
                "    pass\n"
                "#end dummy\n"
              )
        except SyntaxError :
            sys.stderr.write("This module requires Python 3.5 or later.\n")
            sys.exit(-1)
        #end try
        super().run()
    #end run

#end my_build

distutils.core.setup \
  (
    name = "DBussy",
    version = "0.95",
    description = "language bindings for libdbus, for Python 3.5 or later",
    author = "Lawrence D'Oliveiro",
    author_email = "ldo@geek-central.gen.nz",
    url = "http://github.com/ldo/dbussy",
    py_modules = ["dbussy", "ravel"],
    cmdclass =
        {
            "build" : my_build,
        },
  )
