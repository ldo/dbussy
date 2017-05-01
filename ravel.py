"""
Simplified higher-level Python binding for D-Bus, implementing proxy
Python objects to represent D-Bus objects. The API is vaguely
modelled on dbus-python <http://dbus.freedesktop.org/doc/dbus-python/>.
"""
#+
# Copyright 2017 Lawrence D'Oliveiro <ldo@geek-central.gen.nz>.
# Licensed under the GNU Lesser General Public License v2.1 or later.
#-

import types
from weakref import \
    WeakValueDictionary
import asyncio
import dbussy as dbus
from dbussy import \
    DBUS

def max_type(*args) :
    if len(args) == 1 and isinstance(args[0], (tuple, list)) :
        args = args[0]
    #end if
    signed_ints = (chr(DBUS.TYPE_INT16), chr(DBUS.TYPE_INT32), chr(DBUS.TYPE_INT64))
    unsigned_ints = (chr(DBUS.TYPE_BYTE), chr(DBUS.TYPE_UINT16), chr(DBUS.TYPE_UINT32), chr(DBUS.TYPE_UINT64))
    result = None
    i = 0
    while True :
        this_type = guess_signature(args[i])
        if len(this_type) > 1 and result != None and result != this_type :
            # incompatible container types
            result = None
            break
        #end if
        if result == None :
            result = this_type
        elif this_type in signed_ints and result in signed_ints :
            if signed_ints.index(this_type) > signed_ints.index(result) :
                result = this_type
             #end if
        elif this_type in unsigned_ints and result in unsigned_ints :
            if unsigned_ints.index(this_type) > unsigned_ints.index(result) :
                result = this_type
             #end if
        elif this_type == chr(DBUS.TYPE_DOUBLE) and result in signed_ints + unsigned_ints :
            result = this_type
        else :
            #print("cannot find max_type between %s and %s" % (repr(result), repr(this_type))) # debug
            result = None
            break
        #end if
        i += 1
        if i == len(args) :
            break
    #end while
    return \
        result
#end max_type

def guess_signature(obj) :
    if isinstance(obj, int) :
        try_types = (DBUS.TYPE_INT32, DBUS.TYPE_UINT32, DBUS.TYPE_INT64, DBUS.TYPE_UINT64)
        i = 0
        while True :
            try :
                DBUS.int_convert[try_types[i]](obj)
                signature = chr(try_types[i])
                break
            except ValueError :
                i += 1
                if i == len(try_types) :
                    raise
                #end if
            #end try
        #end while
    elif isinstance(obj, float) :
        signature = chr(DBUS.TYPE_DOUBLE)
    elif isinstance(obj, bool) :
        signature = chr(DBUS.TYPE_BOOLEAN)
    elif isinstance(obj, (bytes, bytearray)) :
        signature = chr(DBUS.TYPE_ARRAY) + chr(DBUS.TYPE_BYTE)
    elif isinstance(obj, (tuple, list)) :
        common_elt_type = max_type(obj)
        if (
                common_elt_type != None
            and
                common_elt_type[:-1] == "a" * (len(common_elt_type) - 1)
            and
                common_elt_type[-1] in DBUS.basic_to_ctypes
        ) :
            signature = chr(DBUS.TYPE_ARRAY) + common_elt_type
        else :
            signature = "(" + "".join(guess_signature(elt) for elt in obj) + ")"
        #end if
    elif isinstance(obj, dict) :
        common_key_type = max_type(tuple(dict.keys()))
        if common_key_type == None or common_key_type not in DBUS.basic_to_ctypes :
            raise TypeError("no suitable dict key type for %s" % repr(obj))
        #end if
        common_value_type = max_type(tuple(dict.values()))
        if common_value_type == None :
            common_value_type = chr(DBUS.TYPE_VARIANT)
        #end if
        signature = "%c{%s%s}" % (DBUS.TYPE_ARRAY, common_key_type, common_value_type)
    elif isinstance(obj, str) :
        try_types = (DBUS.TYPE_SIGNATURE, DBUS.TYPE_OBJECT_PATH)
        i = 0
        while True :
            if isinstance(obj, DBUS.basic_subclasses[try_types[i]]) :
                signature = chr(try_types[i])
                break
            #end if
            i += 1
            if i == len(try_types) :
                signature = chr(DBUS.TYPE_STRING)
                break
            #end if
        #end while
    else :
        raise TypeError \
          (
                "cannot guess D-Bus type signature for value “%s” of type “%s”"
            %
                (repr(obj), type(obj).__name__)
          )
    #end if
    return \
        signature
#end guess_signature

def guess_sequence_signature(args) :
    if isinstance(args, (tuple, list)) :
        result = "".join(guess_signature(a) for a in args)
    else :
        result = guess_signature(args)
    #end if
    return \
        result
#end guess_sequence_signature

class Bus :

    __slots__ = ("__weakref__", "connection", "loop", "_dispatch") # to forestall typos

    _instances = WeakValueDictionary()

    def __new__(celf, connection) :
        # always return the same Bus for the same Connection.
        if not isinstance(connection, dbus.Connection) :
            raise TypeError("connection must be a Connection")
        #end if
        self = celf._instances.get(connection)
        if self == None :
            self = super().__new__(celf)
            self.connection = connection
            self.loop = None
            self._dispatch = None # only used server-side
            celf._instances[connection] = self
        #end if
        return \
            self
    #end __new__

    def attach_asyncio(self, loop = None) :
        "attaches this Bus object to an asyncio event loop. If none is" \
        " specified, the default event loop (as returned from asyncio.get_event_loop()" \
        " is used."
        self.connection.attach_asyncio(loop)
        self.loop = self.connection.loop
        return \
            self
    #end attach_asyncio

    class Name :
        __slots__ = ("bus", "name")

        def __init__(self, bus, name) :
            self.bus = bus
            self.name = name
        #end __init__

        def __del__(self) :
            self.bus.connection.bus_release_name(self.name)
        #end __del__

    #end Name

    def request_name(self, bus_name, flags) :
        self.connection.bus_request_name(bus_name, flags)
        return \
            type(self).Name(self, bus_name)
    #end request_name

    def get_object(self, bus_name, path) :
        "for client-side use; returns a CObject instance for communicating" \
        " with a specified server object. Pass the result, along with the interface" \
        " name, to CInterface to create an object that can be used to call any" \
        " method defined on the server by that interface."
        return \
            CObject(self, bus_name, path)
    #end get_object

    def register(self, path, subdir, interface, user_data) :
        "for server-side use; registers an instance of the specified SInterface" \
        " for handling method calls on the specified path, and also on subpaths" \
        " if subdir."
        if not issubclass(interface, SInterface) :
            raise TypeError("interface must be an SInterface subclass")
        #end if
        if self._dispatch == None :
            self._dispatch = {}
            self.connection.add_filter(_message_sinterface_dispatch, self)
        #end if
        level = self._dispatch
        for component in dbus.split_path(path) :
            if not "subdir" in level :
                level["subdir"] = {}
            #end if
            if component not in level["subdir"] :
                level["subdir"][component] = {}
            #end if
            level = level["subdir"][component]
        #end for
        if "dispatch" not in level :
            level["dispatch"] = {}
        #end if
        interface_name = interface._sinterface_name
        if interface_name in level["dispatch"] :
            raise KeyError("already registered an interface named “%s”" % interface_name)
        #end if
        level["dispatch"][interface_name] = {"interface" : interface(user_data), "subdir" : bool(subdir)}
    #end register

    def unregister(self, path, subdir, interface = None) :
        "for server-side use; unregisters the specified SInterface (or all registered" \
        " SInterfaces, if None) from handling method calls on path, and also on" \
        " subpaths if subdir."
        if interface != None and not issubclass(interface, SInterface) :
            raise TypeError("interface must be None or an SInterface subclass")
        #end if
        if self._dispatch != None :
            level = self._dispatch
            levels = iter(dbus.split_path(path))
            while True :
                component = next(levels, None)
                if component == None :
                    if "dispatch" in level :
                        if interface != None :
                            level["dispatch"].pop(interface._sinterface_name, None)
                        else :
                            level["dispatch"].clear() # wipe it all out
                        #end if
                    #end if
                    break
                #end if
                if "subdir" not in level or component not in level["subdir"] :
                    break
                level = level["subdir"][component]
            #end while
        #end if
    #end unregister

    def defsignal(self, interface, name, docstring = None, signature = None) :
        "for server-side use; returns a function that, when called like this:\n" \
        "\n" \
        "    signal(path, *args)\n" \
        "\n" \
        " will send a signal with the specified path, interface and name on" \
        " the bus. docstring is an optional docstring for the generated" \
        " function."

        def gen_signal(path, *args) :
            message = dbus.Message.new_signal \
              (
                path = path,
                iface = interface._sinterface_name,
                name = name
              )
            if len(args) != 0 :
                # fixme: if signature is not None, args should be required?
                message.append_objects \
                  (
                    (lambda : guess_sequence_signature(args), lambda : signature)[signature != None](),
                    args
                  )
            #end if
            self.connection.send(message)
        #end gen_signal

    #begin defsignal
        if not (isinstance(interface, type) and issubclass(interface, SInterface)) and not isinstance(interface, SInterface) :
            raise TypeError("interface must be an SInterface subclass or instance")
        #end if
        gen_signal.__name__ = name
        if docstring != None :
            gen_signal.__doc__ = docstring
        #end if
        return \
            gen_signal
    #end defsignal

#end Bus

def session_bus() :
    "returns a Bus object for the current D-Bus session bus."
    return \
        Bus(dbus.Connection.bus_get(DBUS.BUS_SESSION, private = False))
#end session_bus

def system_bus() :
    "returns a Bus object for the D-Bus system bus."
    return \
        Bus(dbus.Connection.bus_get(DBUS.BUS_SYSTEM, private = False))
#end system_bus

#+
# Client-side proxies for server-side objects
#-

class CObject :
    "identifies an object by a bus, a bus name and a path."

    __slots__ = ("bus", "name", "path")

    def __init__(self, bus, name, path) :
        if not isinstance(bus, Bus) :
            raise TypeError("bus must be a Bus")
        #end if
        self.bus = bus
        self.name = name
        self.path = path
    #end __init__

#end CObject

class CInterface :
    "identifies an interface for communicating synchronously with a CObject."

    __slots__ = ("object", "name", "timeout")

    def __init__(self, object, name, timeout = DBUS.TIMEOUT_USE_DEFAULT) :
        if not isinstance(object, CObject) :
            raise TypeError("object must be a CObject")
        #end if
        self.object = object
        self.name = name
        self.timeout = timeout
    #end __init__

    def __getattr__(self, attrname) :
        return \
            CMethod(self, attrname)
    #end __getattr__

#end CInterface

class CAsyncInterface(CInterface) :
    "identifies an interface for communicating asynchronously with a CObject." \
    " Methods can be called, for example in “await” expressions."

    def __getattr__(self, attrname) :
        return \
            CAsyncMethod(self, attrname)
    #end __getattr__

#end CAsyncInterface

class CMethod :
    "names a method of a CInterface that is to be called synchronously. The" \
    " calling thread is blocked until the reply is received. Do not instantiate" \
    " directly; call the appropriate method name on the parent CInterface."

    __slots__ = ("interface", "method")

    def __init__(self, interface, method) :
        if not isinstance(interface, CInterface) :
            raise TypeError("interface must be a CInterface")
        #end if
        self.interface = interface
        self.method = method
    #end __init__

    def _construct_message(self, args) :
        message = dbus.Message.new_method_call \
          (
            destination = self.interface.object.name,
            path = self.interface.object.path,
            iface = self.interface.name,
            method = self.method
          )
        if len(args) != 0 :
            #print("guess signature for %s = %s" % (repr(args), repr(guess_sequence_signature(args)))) # debug
            message.append_objects(guess_sequence_signature(args), args)
        #end if
        return \
            message
    #end _construct_message

    def _process_reply(self, reply) :
        if reply.type == DBUS.MESSAGE_TYPE_METHOD_RETURN :
            result = list(reply.objects)
            if len(result) == 1 :
                result = result[0]
            #end if
        elif reply.type == DBUS.MESSAGE_TYPE_ERROR :
            raise dbus.DBusError(reply.member, list(reply.objects)[0])
        else :
            raise ValueError("unexpected reply type %d" % reply.type)
        #end if
        return \
            result
    #end _process_reply

    def __call__(self, *args) :
        message = self._construct_message(args)
        reply = self.interface.object.bus.connection.send_with_reply_and_block(message, timeout = self.interface.timeout)
        return \
            self._process_reply(reply)
    #end __call__

#end CMethod

class CAsyncMethod(CMethod) :
    "names a method of a CInterface that is to be called asynchronously," \
    " for example in an “await” expression. Do not instantiate directly;" \
    " call the appropriate method name on the parent CAsyncInterface."

    async def __call__(self, *args) :
        message = self._construct_message(args)
        reply = await self.interface.object.bus.connection.send_await_reply(message, timeout = self.interface.timeout)
        return \
            self._process_reply(reply)
    #end _call__

#end CAsyncMethod

#+
# Server-side utilities
#-

def _message_sinterface_dispatch(connection, message, bus) :
    result = DBUS.HANDLER_RESULT_NOT_YET_HANDLED # to begin with
    if message.type in (DBUS.MESSAGE_TYPE_METHOD_CALL, DBUS.MESSAGE_TYPE_SIGNAL) :
        fallback = None # to begin with
        level = bus._dispatch
        levels = iter(message.path_decomposed)
        interface_name = message.interface
        while True :
            component = next(levels, None)
            iface = None # to begin with
            if component == None :
                if "dispatch" in level and interface_name in level["dispatch"] :
                    iface = level["dispatch"][interface_name]["interface"]
                #end if
            #end if
            if (
                    component == None
                      # reached bottom of path
                or
                    "subdir" not in level
                or
                    component not in level["subdir"]
                      # no handlers to be found further down path
            ) :
                if iface == None :
                    iface = fallback
                #end if
                if iface != None :
                    method_name = message.member
                    methods = {DBUS.MESSAGE_TYPE_METHOD_CALL : iface._sinterface_methods, DBUS.MESSAGE_TYPE_SIGNAL : iface._sinterface_signals}[message.type]
                    if method_name in methods :
                        method = methods[method_name]
                        args = list(message.objects)
                          # fixme: should I pay any attention to method._smethod_info["signature"]?
                        result = method(iface, connection, message, *args)
                        if isinstance(result, types.CoroutineType) :
                            assert bus.loop != None, "no event loop to attach coroutine to"
                            bus.loop.create_task(result)
                            result = DBUS.HANDLER_RESULT_HANDLED
                        #end if
                    #end if
                #end if
                break
            #end if
            if (
                    "dispatch" in level
                and
                    interface_name in level["dispatch"]
                and
                    level["dispatch"][interface_name]["subdir"]
            ) :
                # find a fallback as far down the path as I can
                fallback = level["dispatch"][interface_name]["interface"]
            #end if
            level = level["subdir"][component]
              # search another step down the path
        #end while
    #end if
    return \
         result
#end _message_sinterface_dispatch

class _SInterface_Meta(type) :
    # metaclass for SInterface and its subclasses. Collects methods
    # identified by @smethod() and @ssignal() decorator calls into a
    # dispatch table for easy lookup.

    def __init__(self, *args, **kwargs) :
        # needed to prevent passing kwargs to type.__init__
        pass
    #end __init__

    def __new__(celf, name, bases, namespace, **kwargs) :
        self = type.__new__(celf, name, bases, namespace)
        if len(bases) != 0 : # ignore SInterface base class itself
            assert SInterface in bases
            self._sinterface_name = kwargs["iface_name"]
            self._sinterface_methods = \
                dict \
                  (
                    (f._smethod_info["name"], f)
                    for f in namespace.values()
                    if hasattr(f, "_smethod_info")
                  )
            self._sinterface_signals = \
                dict \
                  (
                    (f._ssignal_info["name"], f)
                    for f in namespace.values()
                    if hasattr(f, "_ssignal_info")
                  )
        #end if
        return \
            self
    #end __new__

#end _SInterface_Meta

class SInterface(metaclass = _SInterface_Meta) :
    "base class for defining server-side interfaces. The class definition should" \
    " specify an “iface_name” keyword argument giving the interface name. Interface methods" \
    " and signals should be invocable as\n" \
    "\n" \
    "    method(self, path, *message_args)\n" \
    "\n" \
    " and definitions should call the “@smethod()” or “@ssignal()” decorator" \
    " to identify them."

    __slots__ = ("user_data",)

    def __init__(self, user_data) :
        self.user_data = user_data
    #end __init__

#end SInterface

def smethod(name = None, signature = None) :
    "put a call to this function as a decorator for each method of an SInterface" \
    " subclass that is to be registered as a method of the interface. “name” is the" \
    " name of the method as specified in the D-Bus message; if omitted, it defaults" \
    " to the name of the function."

    def decorate(func) :
        nonlocal name
        if name == None :
            name = func.__name__
        #end if
        func._smethod_info = {"name" : name, "signature" : signature}
        return \
            func
    #end decorate

#begin smethod
    return \
        decorate
#end smethod

def ssignal(name = None, signature = None) :
    "put a call to this function as a decorator for each method of an SInterface" \
    " subclass that is to be registered as a signal of the interface. “name” is the" \
    " name of the signal as specified in the D-Bus message; if omitted, it defaults" \
    " to the name of the function."

    def decorate(func) :
        nonlocal name
        if name == None :
            name = func.__name__
        #end if
        func._ssignal_info = {"name" : name, "signature" : signature}
        return \
            func
    #end decorate

#begin ssignal
    return \
        decorate
#end ssignal

class Server :
    "listens for connections on a particular socket address, separate from" \
    " the D-Bus daemon. Requires asyncio."

    __slots__ = ("server",)

    def __init__(self, address, loop = None) :
        self.server = dbus.Server.listen(address)
        self.server.attach_asyncio(loop)
    #end __init__

    def __del__(self) :
        self.server.disconnect()
    #end __del__

    async def await_connection(self, timeout = DBUS.TIMEOUT_INFINITE) :
        "waits for a new connection attempt and returns a wrapping Bus object." \
        " If no connection appears within the specified timeout, returns None."
        conn = await self.server.await_new_connection(timeout)
        if conn != None :
            result = Bus(conn)
        else :
            result = None
        #end if
        return \
            result
    #end await_connection

#end Server
