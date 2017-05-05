"""
Simplified higher-level Python binding for D-Bus on top of dbussy.
Provides a framework for dispatching method and signal calls, and also
for on-the-fly invocation of method calls in the server from the
client using proxy objects, all with the option of running via an
asyncio event loop.
"""
#+
# Copyright 2017 Lawrence D'Oliveiro <ldo@geek-central.gen.nz>.
# Licensed under the GNU Lesser General Public License v2.1 or later.
#-

import types
import enum
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
        #print("guess prev %s this %s" % (repr(result), repr(this_type))) # debug
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
        elif this_type != result :
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
        common_elt_type = max_type(*obj)
        #print("comment_elt_type for %s = %s" % (repr(obj), repr(common_elt_type))) # debug
        if (
                common_elt_type != None
            and
                common_elt_type[:-1] == "a" * (len(common_elt_type) - 1)
            and
                ord(common_elt_type[-1]) in DBUS.basic_to_ctypes
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

    def register(self, path, subdir, interface, args = None, kwargs = None) :
        "for server-side use; registers an instance of the specified interface" \
        " class for handling method calls on the specified path, and also on subpaths" \
        " if subdir."
        if not is_interface(interface) :
            raise TypeError("interface must be an @interface() class")
        #end if
        if self._dispatch == None :
            self._dispatch = {}
            self.connection.add_filter(_message_interface_dispatch, self)
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
        interface_name = interface._interface_name
        if interface_name in level["dispatch"] :
            raise KeyError("already registered an interface named “%s”" % interface_name)
        #end if
        if args == None :
            args = ()
        #end if
        if kwargs == None :
            kwargs = {}
        #end if
        level["dispatch"][interface_name] = {"interface" : interface(*args, **kwargs), "subdir" : bool(subdir)}
    #end register

    def unregister(self, path, subdir, interface = None) :
        "for server-side use; unregisters the specified interface class (or all" \
        " registered interface classes, if None) from handling method calls on path," \
        " and also on subpaths if subdir."
        if interface != None and not is_interface(interface) :
            raise TypeError("interface must be None or an @interface() class")
        #end if
        if self._dispatch != None :
            level = self._dispatch
            levels = iter(dbus.split_path(path))
            while True :
                component = next(levels, None)
                if component == None :
                    if "dispatch" in level :
                        if interface != None :
                            level["dispatch"].pop(interface._interface_name, None)
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

    def get_dispatch(self, path, interface_name) :
        "returns the appropriate instance of a previously-registered interface" \
        " class for handling calls to the specified interface name for the" \
        " specified object path, or None if no such."
        fallback = None # to begin with
        level = self._dispatch
        levels = iter(dbus.split_path(path))
        while True :
            component = next(levels, None)
            if (
                    "dispatch" in level
                and
                    interface_name in level["dispatch"]
                and
                    (level["dispatch"][interface_name]["subdir"] or component == None)
            ) :
                iface = level["dispatch"][interface_name]["interface"]
            else :
                iface = None
            #end if
            if (
                    component == None
                      # reached bottom of path
                or
                    "subdir" not in level
                      # reached bottom of registered paths
                or
                    component not in level["subdir"]
                      # no handlers to be found further down path
            ) :
                if iface == None :
                    iface = fallback
                #end if
                break
            #end if
            fallback = iface
            level = level["subdir"][component]
              # search another step down the path
        #end while
        return \
            iface
    #end get_dispatch

    def send_signal(self, *, path, interface, name, args) :
        "sends a signal with the specified interface and name from the" \
        " specified object path. There must already be a registered" \
        " interface instance with that name which will handle that" \
        " signal for that path."
        iface = self.get_dispatch(path, interface)
        if iface == None :
            raise TypeError("no suitable interface %s for object %s" % (interface, dbus.unsplit_path(path)))
        #end if
        iface_type = type(iface)
        if iface_type._interface_kind == INTERFACE.CLIENT :
            raise TypeError("cannot send signal from client side")
        #end if
        if name not in iface_type._interface_signals :
            raise KeyError \
              (
                "name %s is not a signal of interface %s" % (name, iface_type._interface_name)
              )
        #end if
        call_info = iface_type._interface_signals[name]._signal_info
        message = dbus.Message.new_signal \
          (
            path = dbus.unsplit_path(path),
            iface = iface_type._interface_name,
            name = name
          )
        message.append_objects \
          (
            (
                lambda : guess_sequence_signature(args),
                lambda : call_info["in_signature"],
            )[call_info["in_signature"] != None](),
            args
          )
        self.connection.send(message)
    #end send_signal

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

def connect_server(address) :
    "opens a connection to a server at the specified network address and" \
    " returns a Bus object for the connection."
    return \
        Bus(dbus.Connection.open(address, private = False))
#end connect_server

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

    async def await_new_connection(self, timeout = DBUS.TIMEOUT_INFINITE) :
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
    #end await_new_connection

#end Server

#+
# Client-side proxies for server-side objects
#
# These calls provide a simple mechanism for clients to call interface
# methods on the fly. The basic call sequence looks like
#
#     result = \
#         «bus».get_object(«bus-name», «object-path») \
#             .get_interface(«interface-name») \
#             .«method-name»(«args»)
#
# or substitute get_interface with get_async_interface to do an asynchronous
# call.
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

    def get_interface(self, name, timeout = DBUS.TIMEOUT_USE_DEFAULT) :
        return \
            CInterface(object = self, name = name, timeout = timeout)
    #end get_interface

    def get_async_interface(self, name, timeout = DBUS.TIMEOUT_USE_DEFAULT) :
        return \
            CAsyncInterface(object = self, name = name, timeout = timeout)
    #end get_async_interface

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
            result = reply.all_objects
            if len(result) == 1 :
                result = result[0]
            #end if
        elif reply.type == DBUS.MESSAGE_TYPE_ERROR :
            raise dbus.DBusError(reply.member, reply.all_objects[0])
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
# Interface-dispatch mechanism
#-

class INTERFACE(enum.Enum) :
    "what kind of @interface() is this:\n" \
    "  * CLIENT -- client-side, for sending method calls to server and" \
        " receiving signals from server\n" \
    "  * SERVER -- server-side, for receiving method calls from clients and" \
        " sending signals to clients\n" \
    "  * CLIENT_AND_SERVER -- this side is both client and server."

    CLIENT = 1
    SERVER = 2
    CLIENT_AND_SERVER = 3
#end INTERFACE

def _message_interface_dispatch(connection, message, bus) :
    # installed as message filter on a connection to handle dispatch
    # to registered @interface() classes.
    result = DBUS.HANDLER_RESULT_NOT_YET_HANDLED # to begin with
    if message.type in (DBUS.MESSAGE_TYPE_METHOD_CALL, DBUS.MESSAGE_TYPE_SIGNAL) :
        is_method = message.type == DBUS.MESSAGE_TYPE_METHOD_CALL
        interface_name = message.interface
        iface = bus.get_dispatch(message.path, interface_name)
        if iface != None :
            method_name = message.member
            methods = (iface._interface_signals, iface._interface_methods)[is_method]
            if (
                    iface._interface_kind != (INTERFACE.SERVER, INTERFACE.CLIENT)[is_method]
                and
                    method_name in methods
            ) :
                method = methods[method_name]
                call_info = getattr(method, ("_signal_info", "_method_info")[is_method])
                args = message.all_objects
                  # fixme: pay attention to method._method/signal_info["in_signature"]?
                kwargs = {}
                for keyword_keyword, value in \
                    (
                        ("connection_keyword", lambda : connection),
                        ("message_keyword", lambda : message),
                        ("path_keyword", lambda : message.path),
                    ) \
                :
                    if call_info[keyword_keyword] != None :
                        kwargs[call_info[keyword_keyword]] = value()
                    #end if
                #end for
                if call_info["args_keyword"] != None :
                    kwargs[call_info["args_keyword"]] = args
                    args = ()
                #end if
                to_return_result = None
                allow_set_result = True
                if is_method and call_info["set_result_keyword"] != None :
                    def set_result(the_result) :
                        "Call this to set the args for the reply message."
                        nonlocal to_return_result
                        if not allow_set_result :
                            raise RuntimeError("set_result must not be called from a coroutine")
                        #end if
                        to_return_result = the_result
                    #end set_result
                    kwargs[call_info["set_result_keyword"]] = set_result
                #end if
                result = method(iface, *args, **kwargs)
                allow_set_result = False
                  # block further calls to this instance of set_result from this point
                if result == None :
                    if to_return_result != None :
                        # handler used set_result mechanism
                        reply = message.new_method_return()
                        reply.append_objects \
                          (
                            (
                                lambda : guess_sequence_signature(to_return_result),
                                lambda : call_info["out_signature"],
                            )[call_info["out_signature"] != None](),
                            to_return_result
                          )
                        connection.send(reply)
                    #end if
                    result = DBUS.HANDLER_RESULT_HANDLED
                elif isinstance(result, types.CoroutineType) :
                    assert bus.loop != None, "no event loop to attach coroutine to"
                    if call_info["out_signature"] != None :
                        # await function result and generate reply message on behalf of handler
                        out_signature = dbus.parse_signature(call_info["out_signature"])
                        async def await_result(coro) :
                            result = await coro
                            reply = message.new_method_return()
                            reply.append_objects(out_signature, reply)
                            connection.send(reply)
                        #end await_result
                        bus.loop.create_task(await_result(result))
                    else :
                        bus.loop.create_task(result)
                    #end if
                    result = DBUS.HANDLER_RESULT_HANDLED
                elif (
                        result
                    not in
                        (
                            DBUS.HANDLER_RESULT_HANDLED,
                            DBUS.HANDLER_RESULT_NOT_YET_HANDLED,
                            DBUS.HANDLER_RESULT_NEED_MEMORY,
                        )
                ) :
                    raise ValueError("invalid handler result %s" % repr(result))
                #end if
            #end if
        #end if
    #end if
    return \
         result
#end _message_interface_dispatch

def interface(kind, *, name) :
    "class decorator creator for defining interface classes. “kind” is an" \
    " INTERFACE.xxx value indicating whether this is for use on the client side" \
    " (send methods, receive signals), server side (receive methods, send signals)" \
    " or both. “name” (required) is the interface name that will be known to D-Bus." \
    " Interface methods and signals should be invocable as\n" \
    "\n" \
    "    method(self, ...)\n" \
    "\n" \
    " and definitions should be prefixed with calls to the “@method()” or “@signal()”" \
    " decorator to identify them. The return result can be a DBUS.HANDLER_RESULT_xxx" \
    " code, or None (equivalent to DBUS.DBUS.HANDLER_RESULT_HANDLED), or a coroutine" \
    " to queue for execution after indicating that the message has been handled. Note" \
    " that if you declare the method with “async def”, then the return result seen" \
    " will be such a coroutine."

    if not isinstance(kind, INTERFACE) :
        raise TypeError("kind must be an INTERFACE enum value")
    #end if
    if not isinstance(name, str) :
        raise ValueError("name is required")
    #end if

    def decorate(celf) :
        if not isinstance(celf, type) :
            raise TypeError("only apply decorator to classes.")
        #end if
        celf._interface_kind = kind
        celf._interface_name = name
        celf._interface_methods = \
            dict \
              (
                (f._method_info["name"], f)
                for fname in dir(celf)
                for f in (getattr(celf, fname),)
                if hasattr(f, "_method_info")
              )
        celf._interface_signals = \
            dict \
              (
                (f._signal_info["name"], f)
                for fname in dir(celf)
                for f in (getattr(celf, fname),)
                if hasattr(f, "_signal_info")
              )
        return \
            celf
    #end decorate

#begin interface
    return \
        decorate
#end interface

def is_interface(cłass) :
    "is cłass defined as an interface class."
    return \
        isinstance(cłass, type) and hasattr(cłass, "_interface_name")
#end is_interface

def is_interface_instance(obj) :
    "is obj an instance of an interface class."
    return \
        is_interface(type(obj))
#end is_interface_instance

def method \
  (*,
    name = None,
    in_signature = None,
    out_signature = None,
    args_keyword = None,
    connection_keyword = None,
    message_keyword = None,
    path_keyword = None,
    set_result_keyword = None
  ) :
    "put a call to this function as a decorator for each method of an @interface()" \
    " class that is to be registered as a method of the interface." \
    " “name” is the name of the method as specified in the D-Bus message; if omitted," \
    " it defaults to the name of the function.\n" \
    "\n" \
    "This is really only useful on the server side. On the client side, omit the" \
    " method definition, and even leave out the interface definition and registration" \
    " altogether, unless you want to receive signals from the server; instead, use" \
    " Bus.get_object() to send method calls to the server."

    def decorate(func) :
        if not isinstance(func, types.FunctionType) :
            raise TypeError("only apply decorator to functions.")
        #end if
        if name != None :
            func_name = name
        else :
            func_name = func.__name__
        #end if
        func._method_info = \
            {
                "name" : func_name,
                "in_signature" : in_signature,
                "out_signature" : out_signature,
                "args_keyword" : args_keyword,
                "connection_keyword" : connection_keyword,
                "message_keyword" : message_keyword,
                "path_keyword" : path_keyword,
                "set_result_keyword" : set_result_keyword,
            }
        return \
            func
    #end decorate

#begin method
    return \
        decorate
#end method

def signal \
  (*,
    name = None,
    in_signature = None,
    args_keyword = None,
    connection_keyword = None,
    message_keyword = None,
    path_keyword = None
  ) :
    "put a call to this function as a decorator for each method of an @interface()" \
    " class that is to be registered as a signal of the interface." \
    " “name” is the name of the signal as specified in the D-Bus message; if omitted," \
    " it defaults to the name of the function.\n" \
    "\n" \
    "On the server side, the actual function need only be a dummy, since it is just" \
    " a placeholder for storing the information used by Bus.send_signal()."

    def decorate(func) :
        if not isinstance(func, types.FunctionType) :
            raise TypeError("only apply decorator to functions.")
        #end if
        if name != None :
            func_name = name
        else :
            func_name = func.__name__
        #end if
        func._signal_info =  \
            {
                "name" : func_name,
                "in_signature" : in_signature,
                "args_keyword" : args_keyword,
                "connection_keyword" : connection_keyword,
                "message_keyword" : message_keyword,
                "path_keyword" : path_keyword,
            }
        return \
            func
    #end decorate

#begin signal
    return \
        decorate
#end signal
