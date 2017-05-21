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
import atexit
import dbussy as dbus
from dbussy import \
    DBUS, \
    Introspection

#+
# Signature-guessing
#-

def max_type(*args) :
    if len(args) == 1 and isinstance(args[0], (tuple, list)) :
        args = args[0]
    #end if
    signed_ints = (chr(DBUS.TYPE_INT16), chr(DBUS.TYPE_INT32), chr(DBUS.TYPE_INT64))
    unsigned_ints = (chr(DBUS.TYPE_BYTE), chr(DBUS.TYPE_UINT16), chr(DBUS.TYPE_UINT32), chr(DBUS.TYPE_UINT64))
    result = None
    i = 0
    while True :
        if i == len(args) :
            break
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
        if len(obj) != 0 :
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
        else :
            # doesn’t really matter what elttype I use
            signature = "as"
        #end if
    elif isinstance(obj, dict) :
        if len(obj) != 0 :
            common_key_type = max_type(tuple(obj.keys()))
            if common_key_type == None or common_key_type not in DBUS.basic_to_ctypes :
                raise TypeError("no suitable dict key type for %s" % repr(obj))
            #end if
            common_value_type = max_type(tuple(obj.values()))
            if common_value_type == None :
                common_value_type = chr(DBUS.TYPE_VARIANT)
            #end if
        else :
            # doesn’t really matter what I use
            common_key_type = chr(DBUS.TYPE_STRING)
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

#+
# High-level bus connection
#-

class HandlerError(Exception) :
    "Dispatch handlers can raise this to report an error that will be returned" \
    " in a message back to the other end of the connection."

    def __init__(self, name, message) :
        self.args = (name, message)
    #end __init__

    def as_error(self) :
        "fills in and returns an Error object that reports the specified error name and message."
        result = dbus.Error.init()
        result.set(self.args[0], self.args[1])
        return \
            result
    #end as_error

#end HandlerError

def _signal_key(fallback, interface, name) :
    # constructs a key for the signal-listener dictionary from the
    # given args.
    return \
        (fallback, interface, name)
#end _signal_key

def _signal_rule(path, fallback, interface, name) :
    # constructs a D-Bus match rule from the given args. extra, if present,
    # is a dict of additional keys and values for the match rule.
    return \
        dbus.format_rule \
          (
            {
                "type" : "signal",
                ("path", "path_namespace")[fallback] : dbus.unsplit_path(path),
                "interface" : interface,
                "member" : name,
            }
          )
#end _signal_rule

class _DispatchNode :

    __slots__ = ("children", "interfaces", "signal_listeners", "user_data")

    class _Interface :

        __slots__ = ("interface", "fallback", "listening")

        def __init__(self, interface, fallback) :
            self.interface = interface
            self.fallback = fallback
            self.listening = set() # of match rule strings
        #end __init

    #end _Interface

    class _UserDataDict(dict) :
        # for holding user data, does automatic cleaning up of object
        # tree as items are removed.

        __slots__ = ("_ravel_bus",)

        def __init__(self, bus) :
            super().__init__(self)
            self._ravel_bus = bus
        #end __init

        def __delitem__(self, key) :
            super().__delitem__(key)
            if len(self) == 0 :
                self._ravel_bus._trim_dispatch()
            #end if
        #end __delitem__

    #end _UserDataDict

    def __init__(self, bus) :
        self.children = {} # dict of path component => _DispatchNode
        self.interfaces = {} # dict of interface name => _Interface
        self.signal_listeners = {} # dict of _signal_key() => list of functions
          # Note these are independent of registered interfaces
        self.user_data = self._UserDataDict(bus) # for caller use
    #end __init__

    @property
    def is_empty(self) :
        return \
            (
                    len(self.children) == 0
                and
                    len(self.interfaces) == 0
                and
                    len(self.signal_listeners) == 0
                and
                    len(self.user_data) == 0
            )
    #end is_empty

#end _DispatchNode

class _UserData :

    __slots__ = ("conn",)

    def __init__(self, conn) :
        self.conn = conn
    #end __init__

    def __getitem__(self, path) :
        node = self.conn._get_dispatch_node(path, True)
        return \
            node.user_data
    #end __getitem__

#end _UserData

class Connection :
    "higher-level wrapper around dbussy.Connection. Do not instantiate directly: use" \
    " the session_bus() and system_bus() calls in this module, or obtain from accepting" \
    " connections on a Server().\n" \
    "\n" \
    "This class provides various functions, some more suited to client-side use and" \
    " some more suitable to the server side. Allows for registering of @interface()" \
    " classes for automatic dispatching of method calls at appropriate points in" \
    " the object hierarchy."

    __slots__ = \
        (
            "__weakref__",
            "connection",
            "loop",
            "props_change_notify_delay",
            "user_data",
            "_dispatch",
            "_props_changed",
        ) # to forestall typos

    _instances = WeakValueDictionary()

    def __new__(celf, connection) :
        # always return the same Connection for the same dbus.Connection.
        if not isinstance(connection, dbus.Connection) :
            raise TypeError("connection must be a Connection")
        #end if
        self = celf._instances.get(connection)
        if self == None :
            self = super().__new__(celf)
            self.connection = connection
            self.loop = None
            self.props_change_notify_delay = 0
            self._dispatch = None # only used server-side
            self._props_changed = None
            self.user_data = _UserData(self)
            celf._instances[connection] = self
            for interface in \
                (
                    PeerStub,
                    IntrospectionHandler,
                    PropertyHandler,
                ) \
            :
                self.register \
                  (
                    path = "/",
                    interface = interface(),
                    fallback = True
                  )
            #end for
        #end if
        return \
            self
    #end __new__

    def __del__(self) :

        def remove_listeners(level, path) :
            for node, child in level.children.items() :
                remove_listeners(child, path + [node])
            #end for
            for interface in level.interfaces :
                for rulestr in interface.listening :
                    ignore = dbus.Error.init()
                    self.connection.bus_remove_match(rulestr, ignore)
                #end for
            #end for
            for rulekey in level.signal_listeners :
                fallback, interface, name = rulekey
                ignore = dbus.Error.init()
                self.connection.bus_remove_match \
                  (
                    _signal_rule(path, fallback, interface, name),
                    ignore
                  )
            #end for
        #end remove_listeners

    #begin __del__
        if self._dispatch != None :
            remove_listeners(self._dispatch, [])
        #end if
    #end __del__

    def attach_asyncio(self, loop = None) :
        "attaches this Connection object to an asyncio event loop. If none is" \
        " specified, the default event loop (as returned from asyncio.get_event_loop()" \
        " is used."
        self.connection.attach_asyncio(loop)
        self.loop = self.connection.loop
        return \
            self
    #end attach_asyncio

    class BusName :
        __slots__ = ("conn", "name")

        def __init__(self, conn, name) :
            self.conn = conn
            self.name = name
        #end __init__

        def __del__(self) :
            self.conn.connection.bus_release_name(self.name)
        #end __del__

    #end BusName

    def request_name(self, bus_name, flags) :
        "registers a bus name, returning a Connection.BusName object; hold on" \
        " to this for as long as you want the name registered. When Python" \
        " disposes of the object, the name will be released."
        self.connection.bus_request_name(bus_name, flags)
        return \
            type(self).BusName(self, bus_name)
    #end request_name

    def get_object(self, bus_name, path) :
        "for client-side use; returns a CObject instance for communicating" \
        " with a specified server object. You can then call get_interface" \
        " on the result to create an interface object that can be used to" \
        " call any method defined on the server by that interface."
        return \
            CObject(self, bus_name, path)
    #end get_object

    def _trim_dispatch(self) :
        # removes empty subtrees from the object tree.

        def trim_dispatch_node(level) :
            to_delete = set()
            for node, child in level.children.items() :
                trim_dispatch_node(child)
                if child.is_empty :
                    to_delete.add(node)
                #end if
            #end for
            for node in to_delete :
                del level.children[node]
            #end for
        #end trim_dispatch_node

    #begin _trim_dispatch
        if self._dispatch != None :
            trim_dispatch_node(self._dispatch)
            if self._dispatch.is_empty :
                self._dispatch = None
            #end if
        #end if
    #end _trim_dispatch

    def _get_dispatch_node(self, path, create_if) :
        # returns the appropriate _DispatchNode entry in the dispatch
        # tree for the specified path, or None if no such and not
        # create_if.
        if create_if and self._dispatch == None :
            self._dispatch = _DispatchNode(self)
        #end if
        level = self._dispatch
        if level != None :
            levels = iter(dbus.split_path(path))
            while True :
                component = next(levels, None)
                if component == None :
                    break # found if level != None
                if component not in level.children :
                    if not create_if :
                        level = None
                        break
                    #end if
                    level.children[component] = _DispatchNode(self)
                #end if
                level = level.children[component]
                  # search another step down the path
            #end while
        #end if
        return \
            level
    #end _get_dispatch_node

    def _remove_matches(self, dispatch) :
        for rulestr in dispatch.listening :
            ignore = dbus.Error.init()
            self.connection.bus_remove_match(rulestr, ignore)
        #end for
    #end _remove_matches

    def register(self, path, fallback, interface, replace = True) :
        "for server-side use; registers the specified instance of an @interface()" \
        " class for handling method calls on the specified path, and also on subpaths" \
        " if fallback."
        if is_interface_instance(interface) :
            iface_type = type(interface)
        elif is_interface(interface) :
            # assume can instantiate without arguments
            iface_type = interface
            interface = iface_type()
        else :
            raise TypeError("interface must be an @interface() class or instance thereof")
        #end if
        if self._dispatch == None :
            self._dispatch = _DispatchNode(self)
            self.connection.add_filter(_message_interface_dispatch, self)
        #end if
        level = self._dispatch
        for component in dbus.split_path(path) :
            if component not in level.children :
                level.children[component] = _DispatchNode(self)
            #end if
            level = level.children[component]
        #end for
        interface_name = iface_type._interface_name
        if interface_name in level.interfaces :
            entry = level.interfaces[interface_name]
            existing_kind = type(entry.interface)._interface_kind
            if not replace or existing_kind != iface_type._interface_kind :
                raise KeyError \
                  (
                        "already registered an interface named “%s” of kind %s"
                    %
                        (interface_name, existing_kind)
                  )
            #end if
            self._remove_matches(entry)
        #end if
        entry = _DispatchNode._Interface(interface, fallback)
        if iface_type._interface_kind != INTERFACE.SERVER :
            signals = iface_type._interface_signals
            for name in signals :
                if not iface_type._interface_signals[name]._signal_info["stub"] :
                    rulestr = _signal_rule(path, fallback, interface_name, name)
                    self.connection.bus_add_match(rulestr)
                    entry.listening.add(rulestr)
                #end if
            #end for
        #end for
        level.interfaces[interface_name] = entry
    #end register

    def unregister(self, path, interface = None) :
        "for server-side use; unregisters the specified interface class (or all" \
        " registered interface classes, if None) from handling method calls on path."
        if interface != None and not is_interface(interface) :
            raise TypeError("interface must be None or an @interface() class")
        #end if
        if self._dispatch != None :
            level = self._dispatch
            levels = iter(dbus.split_path(path))
            while True :
                component = next(levels, None)
                if component == None :
                    if interface != None :
                        interfaces = [level.interfaces[interface._interface_name]]
                    else :
                        interfaces = set(level.interfaces.keys())
                    #end if
                    for iface_name in interfaces :
                        self._remove_matches(level.interface[iface_name])
                        del level.interface[iface_name]
                    #end for
                    break
                #end if
                if component not in level.children :
                    break
                level = level.children[component]
            #end while
            self._trim_dispatch()
        #end if
    #end unregister

    def listen_signal(self, path, fallback, interface, name, func) :
        "for client-side use; registers a callback which will be invoked when a" \
        " signal is received for the specified path, interface and name."
        if not hasattr(func, "_signal_info") :
            raise TypeError("callback must have @signal() decorator applied")
        #end if
        signal_info = func._signal_info
        entry = self._get_dispatch_node(path, True)
        # should I bother to check it matches a registered interface and
        # defined signal therein?
        listeners = entry.signal_listeners
        rulekey = _signal_key(fallback, interface, name)
        if rulekey not in listeners :
            self.connection.bus_add_match(_signal_rule(path, fallback, interface, name))
            listeners[rulekey] = []
        #end if
        listeners[rulekey].append(func)
    #end listen_signal

    def unlisten_signal(self, path, fallback, interface, name, func) :
        "for client-side use; unregisters a previously-registered callback" \
        " which would have been invoked when a signal is received for the" \
        " specified path, interface and name."
        entry = self._get_dispatch_node(path, False)
        if entry != None :
            listeners = entry.signal_listeners
            rulekey = _signal_key(fallback, interface, name)
            if rulekey in listeners :
                listeners = listeners[rulekey]
                try :
                    listeners.pop(listeners.index(func))
                except ValueError :
                    pass
                #end try
                if len(listeners) == 0 :
                    ignore = dbus.Error.init()
                    self.connection.bus_remove_match \
                      (
                        _signal_rule(path, fallback, interface, name),
                        ignore
                      )
                    del listeners[rulekey]
                      # as a note to myself that I will need to call bus_add_match
                      # if a new listener is added
                #end if
            #end if
            self._trim_dispatch()
        #end if
    #end unlisten_signal

    def listen_propchanged(self, path, fallback, interface, func) :
        "special case of Connection.listen_signal specifically for listening" \
        " for properties-changed signals."
        self.listen_signal \
          (
            path = path,
            fallback = fallback,
            interface = DBUS.INTERFACE_PROPERTIES,
            name = "PropertiesChanged",
            func = func,
          )
    #end listen_propchanged

    def unlisten_propchanged(self, path, fallback, interface, func) :
        "special case of Connection.unlisten_signal specifically for listening" \
        " for properties-changed signals."
        self.unlisten_signal \
          (
            path = path,
            fallback = fallback,
            interface = DBUS.INTERFACE_PROPERTIES,
            name = "PropertiesChanged",
            func = func,
          )
    #end unlisten_propchanged

    def get_dispatch_interface(self, path, interface_name) :
        "returns the appropriate instance of a previously-registered interface" \
        " class for handling calls to the specified interface name for the" \
        " specified object path, or None if no such."
        fallback = None # to begin with
        level = self._dispatch
        if level != None :
            levels = iter(dbus.split_path(path))
            while True :
                component = next(levels, None)
                if (
                        interface_name in level.interfaces
                    and
                        (level.interfaces[interface_name].fallback or component == None)
                ) :
                    iface = level.interfaces[interface_name].interface
                else :
                    iface = fallback
                #end if
                if (
                        component == None
                          # reached bottom of path
                    or
                        component not in level.children
                          # no handlers to be found further down path
                ) :
                    break
                #end if
                fallback = iface
                level = level.children[component]
                  # search another step down the path
            #end while
        else :
            iface = None
        #end if
        return \
            iface
    #end get_dispatch_interface

    def send_signal(self, *, path, interface, name, args) :
        "intended for server-side use: sends a signal with the specified" \
        " interface and name from the specified object path. There must" \
        " already be a registered interface instance with that name which" \
        " defines that signal for that path."
        iface = self.get_dispatch_interface(path, interface)
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
        message.append_objects(call_info["in_signature"], *args)
        self.connection.send(message)
    #end send_signal

    def send_method_with_reply_and_block(self, *, destination, path, interface, name, args, timeout = DBUS.TIMEOUT_USE_DEFAULT) :
        "intended for client-side use: sends a method call with the specified" \
        " interface and name to the specified object path. There must already" \
        " be a registered interface instance with that name which defines" \
        " that method for that path.\n" \
        "\n" \
        "An exception is raised if the return is an error; otherwise a list of" \
        " the reply args is returned."
        iface = self.get_dispatch_interface(path, interface)
        if iface == None :
            raise TypeError("no suitable interface %s for object %s" % (interface, dbus.unsplit_path(path)))
        #end if
        iface_type = type(iface)
        if iface_type._interface_kind == INTERFACE.SERVER :
            raise TypeError("cannot send method call from server side")
        #end if
        if name not in iface_type._interface_methods :
            raise KeyError \
              (
                "name %s is not a method of interface %s" % (name, iface_type._interface_name)
              )
        #end if
        call_info = iface_type._interface_methods[name]._method_info
        if not call_info["reply"] :
            raise TypeError("method %s does not reply" % name)
        #end if
        message = dbus.Message.new_method_call \
          (
            destination = destination,
            path = dbus.unsplit_path(path),
            iface = iface_type._interface_name,
            method = name
          )
        if len(args) != 0 :
            message.append_objects(call_info["in_signature"], *args)
        #end if
        reply = self.send_with_reply_and_block(message, timeout)
        if reply != None :
            result = reply.expect_return_objects(call_info["out_signature"])
        else :
            result = None
        #end if
        return \
            result
    #end send_method_with_reply_and_block

    async def send_method_await_reply(self, *, destination, path, interface, name, args, timeout = DBUS.TIMEOUT_USE_DEFAULT) :
        "intended for client-side use: sends a method call with the specified" \
        " interface and name to the specified object path. There must already" \
        " be a registered interface instance with that name which defines" \
        " that method for that path.\n" \
        "\n" \
        "An exception is raised if the return is an error; otherwise a list of" \
        " the reply args is returned."
        assert self.loop != None, "no event loop to attach coroutine to"
        iface = self.get_dispatch_interface(path, interface)
        if iface == None :
            raise TypeError("no suitable interface %s for object %s" % (interface, dbus.unsplit_path(path)))
        #end if
        iface_type = type(iface)
        if iface_type._interface_kind == INTERFACE.SERVER :
            raise TypeError("cannot send method call from server side")
        #end if
        if name not in iface_type._interface_methods :
            raise KeyError \
              (
                "name %s is not a method of interface %s" % (name, iface_type._interface_name)
              )
        #end if
        call_info = iface_type._interface_methods[name]._method_info
        if not call_info["reply"] :
            raise TypeError("method %s does not reply" % name)
        #end if
        message = dbus.Message.new_method_call \
          (
            destination = destination,
            path = dbus.unsplit_path(path),
            iface = iface_type._interface_name,
            method = name
          )
        if len(args) != 0 :
            message.append_objects(call_info["in_signature"], *args)
        #end if
        reply = await self.connection.send_await_reply(message, timeout)
        if reply != None :
            result = reply.expect_return_objects(call_info["out_signature"])
        else :
            result = None
        #end if
        return \
            result
    #end send_method_await_reply

    def introspect(self, destination, path, timeout = DBUS.TIMEOUT_USE_DEFAULT) :
        "sends an Introspect request to the specified bus name and object path," \
        " and returns the resulting parsed Introspection structure."
        message = dbus.Message.new_method_call \
          (
            destination = destination,
            path = dbus.unsplit_path(path),
            iface = DBUS.INTERFACE_INTROSPECTABLE,
            method = "Introspect"
          )
        reply = self.connection.send_with_reply_and_block(message, timeout)
        return \
            dbus.Introspection.parse(reply.expect_return_objects("s")[0])
    #end introspect

    async def introspect_async(self, destination, path, timeout = DBUS.TIMEOUT_USE_DEFAULT) :
        "sends an Introspect request to the specified bus name and object path," \
        " and returns the resulting parsed Introspection structure."
        message = dbus.Message.new_method_call \
          (
            destination = destination,
            path = dbus.unsplit_path(path),
            iface = DBUS.INTERFACE_INTROSPECTABLE,
            method = "Introspect"
          )
        reply = await self.connection.send_await_reply(message, timeout)
        return \
            dbus.Introspection.parse(reply.expect_return_objects("s")[0])
    #end introspect_async

    def _notify_props_changed(self) :
        # callback that is queued on the event loop to actually send the
        # properties-changed notification signals.
        if self._props_changed != None :
            done = set()
            now = self.loop.time()
            for key in self._props_changed :
                entry = self._props_changed[key]
                path, interface = key
                if entry["at"] <= now :
                    self.send_signal \
                      (
                        path = path,
                        interface = DBUS.INTERFACE_PROPERTIES,
                        name = "PropertiesChanged",
                        args = (interface, entry["changed"], sorted(entry["invalidated"]))
                      )
                    done.add(key)
                #end if
            #end for
            for key in done :
                del self._props_changed[key]
            #end for
            if len(self._props_changed) == 0 :
                # all done for now
                self._props_changed = None # indicates I am not pending to be called any more
            else :
                # another notification waiting to be sent later
                next_time = min(entry["at"] for entry in self._props_changed.values())
                self.loop.call_at(next_time, self._notify_props_changed)
            #end if
        #end if
    #end _notify_props_changed

    def prop_changed(self, path, interface, propname, proptype, propvalue) :
        "indicates that a signal should be sent notifying of a change to the specified" \
        " property of the specified object path in the specified interface. propvalue" \
        " is either the new value to be included in the signal, or None to indicate" \
        " that the property has merely become invalidated, and its new value needs" \
        " to be obtained explicitly.\n" \
        "\n" \
        "If there is an event loop attached, then multiple calls to this with different" \
        " properties on the same path and interface can be batched up into a single" \
        " signal notification."
        assert (proptype != None) == (propvalue != None), \
            "either specify both of proptype and propvalue, or neither"
        if self.loop != None :
            queue_task = False
            if self._props_changed == None :
                self._props_changed = {}
                queue_task = True
            #end if
            key = (path, interface)
            if key not in self._props_changed :
                self._props_changed[key] = \
                    {
                        "at" : self.loop.time() + self.props_change_notify_delay,
                        "changed" : {},
                        "invalidated" : set(),
                    }
            #end if
            if propvalue != None :
                self._props_changed[key]["changed"][propname] = (proptype, propvalue)
            else :
                self._props_changed[key]["invalidated"].add(propname)
            #end if
            if queue_task :
                if self.props_change_notify_delay != 0 :
                    self.loop.call_later(self.props_change_notify_delay, self._notify_props_changed)
                else :
                    self.loop.call_soon(self._notify_props_changed)
                #end if
            #end if
        else :
            # cannot batch them up--send message immediately
            changed = {}
            invalidated = []
            if propvalue != None :
                changed[propname] = (proptype, propvalue)
            else :
                invalidated.append(propname)
            #end if
            self.send_signal \
              (
                path = path,
                interface = DBUS.INTERFACE_PROPERTIES,
                name = "PropertiesChanged",
                args = (interface, changed, invalidated)
              )
        #end if
    #end prop_changed

#end Connection

def session_bus() :
    "returns a Connection object for the current D-Bus session bus."
    return \
        Connection(dbus.Connection.bus_get(DBUS.BUS_SESSION, private = False))
#end session_bus

def system_bus() :
    "returns a Connection object for the D-Bus system bus."
    return \
        Connection(dbus.Connection.bus_get(DBUS.BUS_SYSTEM, private = False))
#end system_bus

def connect_server(address) :
    "opens a connection to a server at the specified network address and" \
    " returns a Connection object for the connection."
    return \
        Connection(dbus.Connection.open(address, private = False))
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
        "waits for a new connection attempt and returns a wrapping Connection object." \
        " If no connection appears within the specified timeout, returns None."
        conn = await self.server.await_new_connection(timeout)
        if conn != None :
            result = Connection(conn)
        else :
            result = None
        #end if
        return \
            result
    #end await_new_connection

#end Server

#+
# Ad-hoc client-side proxies for server-side objects
#
# These calls provide a simple mechanism for clients to call interface
# methods on the fly. The basic call sequence looks like
#
#     result = \
#         «connection».get_object(«bus-name», «object-path») \
#             .get_interface(«interface-name») \
#             .«method-name»(«args»)
#
# or substitute get_interface with get_async_interface to do an asynchronous
# call.
#-

class CObject :
    "identifies an object by a bus, a bus name and a path."

    __slots__ = ("conn", "name", "path")

    def __init__(self, conn, name, path) :
        if not isinstance(conn, Connection) :
            raise TypeError("conn must be a Connection")
        #end if
        self.conn = conn
        self.name = name
        self.path = path
    #end __init__

    def get_interface(self, name, timeout = DBUS.TIMEOUT_USE_DEFAULT) :
        if name in dbus.standard_interfaces :
            definition = dbus.standard_interfaces[name]
        else :
            introspection = self.conn.introspect(self.name, self.path, timeout)
            interfaces = introspection.interfaces_by_name
            if name not in interfaces :
                raise dbus.DBusError \
                  (
                    DBUS.ERROR_UNKNOWN_INTERFACE,
                    "object “%s” does not understand interface “%s”" % (self.path, name)
                  )
            #end if
            definition = interfaces[name]
        #end if
        return \
            def_proxy_interface \
              (
                INTERFACE.CLIENT,
                name = name,
                introspected = definition,
                is_async = False
              )(
                connection = self.conn.connection,
                dest = self.name,
                timeout = timeout
              )[self.path]
    #end _get_interface

    async def get_async_interface(self, name, timeout = DBUS.TIMEOUT_USE_DEFAULT) :
        if name in dbus.standard_interfaces :
            definition = dbus.standard_interfaces[name]
        else :
            introspection = await self.conn.introspect_async(self.name, self.path, timeout)
            interfaces = introspection.interfaces_by_name
            if name not in interfaces :
                raise dbus.DBusError \
                  (
                    DBUS.ERROR_UNKNOWN_INTERFACE,
                    "object “%s” does not understand interface “%s”" % (self.path, name)
                  )
            #end if
            definition = interfaces[name]
        #end if
        return \
            def_proxy_interface \
              (
                INTERFACE.CLIENT,
                name = name,
                introspected = definition,
                is_async = True
              )(
                connection = self.conn.connection,
                dest = self.name,
                timeout = timeout
              )[self.path]
    #end get_async_interface

#end CObject

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
    CLIENT_AND_SERVER = 3 # CLIENT | SERVER
#end INTERFACE

def _send_method_return(connection, message, sig, args) :
    reply = message.new_method_return()
    reply.append_objects(sig, *args)
    connection.send(reply)
#end _send_method_return

def _message_interface_dispatch(connection, message, bus) :
    # installed as message filter on a connection to handle dispatch
    # to registered @interface() classes.

    def dispatch_signal(level, path) :
        # Note I ignore handled/not handled status and pass the signal
        # to all registered handlers.
        if len(path) != 0 and path[0] in level.children :
            # call lower-level (more-specific) signal handlers first,
            # not that it’s important
            dispatch_signal(level.children[path[0]], path[1:])
        #end if
        listeners = level.signal_listeners
        name = message.member
        for fallback in (False, True) :
            # again, call more-specific (fallback = False) handlers first,
            # not that it’s important
            rulekey = _signal_key(fallback, interface_name, name)
            if rulekey in listeners and (len(path) == 0 or fallback) :
                funcs = listeners[rulekey]
                for func in funcs :
                    try :
                        call_info = func._signal_info
                        try :
                            args = message.expect_objects(call_info["in_signature"])
                        except (TypeError, ValueError) :
                            raise HandlerError \
                              (
                                name = DBUS.ERROR_INVALID_ARGS,
                                message = "message arguments do not match expected signature"
                              )
                        #end try
                        kwargs = {}
                        for keyword_keyword, value in \
                            (
                                ("connection_keyword", lambda : connection),
                                ("message_keyword", lambda : message),
                                ("path_keyword", lambda : message.path),
                                ("bus_keyword", lambda : bus),
                            ) \
                        :
                            if call_info[keyword_keyword] != None :
                                kwargs[call_info[keyword_keyword]] = value()
                            #end if
                        #end for
                        if call_info["args_keyword"] != None :
                            if call_info["arg_keys"] != None :
                                args =  dict \
                                  (
                                    (key, value)
                                    for key, value in zip(call_info["arg_keys"], args)
                                  )
                                if "args_constructor" in call_info :
                                    args = call_info["args_constructor"](**args)
                                #end if
                            #end if
                            kwargs[call_info["args_keyword"]] = args
                            args = ()
                        else :
                            if call_info["arg_keys"] != None :
                                for key, value in zip(call_info["arg_keys"], args) :
                                    kwargs[key] = value
                                #end for
                                args = ()
                            #end if
                        #end if
                        result = func(*args, **kwargs)
                        if isinstance(result, types.CoroutineType) :
                            async def await_result(coro) :
                                # just to gobble any HandlerError
                                try :
                                    await coro
                                except HandlerError :
                                    pass
                                #end try
                            #end await_result
                            bus.loop.create_task(await_result(result))
                        elif result != None :
                            raise ValueError \
                              (
                                "invalid result from signal handler: %s" % repr(result)
                              )
                        #end if
                    except HandlerError :
                        pass
                    #end try
                #end for
            #end if
        #end for
    #end dispatch_signal

    def return_result_common(call_info, result) :
        # handles list, tuple, dict or Error returned from method handler;
        # packs into reply message and sends it off.
        if isinstance(result, dbus.Error) :
            assert result.is_set, "unset Error object returned from handler"
            reply = message.new_error(result.name, result.message)
            connection.send(reply)
        else :
            sig = dbus.parse_signature(call_info["out_signature"])
            if isinstance(result, dict) and call_info["result_keys"] != None :
                result = list(result[key] for key in call_info["result_keys"])
                  # convert result items to list in right order
            elif (
                    "result_constructor" in call_info
                and
                    isinstance(result, call_info["result_constructor"])
            ) :
                result = list(result)
            elif not isinstance(result, (tuple, list)) :
                raise ValueError("invalid handler result %s" % repr(result))
            #end if
            _send_method_return \
              (
                connection = connection,
                message = message,
                sig = sig,
                args = result
              )
        #end if
    #end return_result_common

#begin _message_interface_dispatch
    result = DBUS.HANDLER_RESULT_NOT_YET_HANDLED # to begin with
    if message.type in (DBUS.MESSAGE_TYPE_METHOD_CALL, DBUS.MESSAGE_TYPE_SIGNAL) :
        is_method = message.type == DBUS.MESSAGE_TYPE_METHOD_CALL
        interface_name = message.interface
        if not is_method :
            dispatch_signal(bus._dispatch, dbus.split_path(message.path))
        #end if
        iface = bus.get_dispatch_interface(message.path, interface_name)
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
                if is_method or not call_info["stub"] :
                    to_return_result = None
                    try :
                        try :
                            args = message.expect_objects(call_info["in_signature"])
                        except (TypeError, ValueError) :
                            raise HandlerError \
                              (
                                name = DBUS.ERROR_INVALID_ARGS,
                                message = "message arguments do not match expected signature"
                              )
                        #end try
                        kwargs = {}
                        for keyword_keyword, value in \
                            (
                                ("connection_keyword", lambda : connection),
                                ("message_keyword", lambda : message),
                                ("path_keyword", lambda : message.path),
                                ("bus_keyword", lambda : bus),
                            ) \
                        :
                            if call_info[keyword_keyword] != None :
                                kwargs[call_info[keyword_keyword]] = value()
                            #end if
                        #end for
                        if call_info["args_keyword"] != None :
                            if call_info["arg_keys"] != None :
                                args =  dict \
                                  (
                                    (key, value)
                                    for key, value in zip(call_info["arg_keys"], args)
                                  )
                                if "args_constructor" in call_info :
                                    args = call_info["args_constructor"](**args)
                                #end if
                            #end if
                            kwargs[call_info["args_keyword"]] = args
                            args = ()
                        else :
                            if call_info["arg_keys"] != None :
                                for key, value in zip(call_info["arg_keys"], args) :
                                    kwargs[key] = value
                                #end for
                                args = ()
                            #end if
                        #end if
                        if is_method :
                            if call_info["result_keyword"] != None :
                                # construct a mutable result object that handler will update in place
                                to_return_result = [None] * len(call_info["out_signature"])
                                if call_info["result_keys"] != None :
                                    to_return_result = dict \
                                      (
                                        (key, val)
                                        for key, val in zip(call_info["result_keys"], to_return_result)
                                      )
                                    if "result_constructor" in call_info :
                                        to_return_result = call_info["result_constructor"](**to_return_result)
                                    #end if
                                #end if
                                kwargs[call_info["result_keyword"]] = to_return_result
                            elif call_info["set_result_keyword"] != None :
                                # caller wants to return result via callback
                                def set_result(the_result) :
                                    "Call this to set the args for the reply message."
                                    nonlocal to_return_result
                                    to_return_result = the_result
                                #end set_result
                                kwargs[call_info["set_result_keyword"]] = set_result
                            #end if
                        #end if
                        result = method(iface, *args, **kwargs)
                    except HandlerError as err :
                        result = err.as_error()
                    #end try
                    allow_set_result = False
                      # block further calls to this instance of set_result from this point
                    if result == None :
                        if to_return_result != None :
                            # method handler used set_result mechanism
                            return_result_common(call_info, to_return_result)
                        #end if
                        result = DBUS.HANDLER_RESULT_HANDLED
                    elif isinstance(result, types.CoroutineType) :
                        if is_method :
                            assert bus.loop != None, "no event loop to attach coroutine to"
                            # wait for result
                            async def await_result(coro) :
                                try :
                                    result = await coro
                                except HandlerError as err :
                                    result = err.as_error()
                                #end try
                                if result == None and to_return_result != None :
                                    # method handler used set_result mechanism
                                    result = to_return_result
                                #end if
                                return_result_common(call_info, result)
                            #end await_result
                            bus.loop.create_task(await_result(result))
                        else :
                            bus.loop.create_task(result)
                        #end if
                        result = DBUS.HANDLER_RESULT_HANDLED
                    elif isinstance(result, bool) :
                        # slightly tricky: interpret True as handled, False as not handled,
                        # even though DBUS.HANDLER_RESULT_HANDLED is zero and
                        # DBUS.HANDLER_RESULT_NOT_YET_HANDLED is nonzero.
                        result = \
                            (DBUS.HANDLER_RESULT_NOT_YET_HANDLED, DBUS.HANDLER_RESULT_HANDLED)[result]
                    elif (
                            result
                        in
                            (
                                DBUS.HANDLER_RESULT_HANDLED,
                                DBUS.HANDLER_RESULT_NOT_YET_HANDLED,
                                DBUS.HANDLER_RESULT_NEED_MEMORY,
                            )
                    ) :
                        pass
                    else :
                        return_result_common(call_info, result)
                        result = DBUS.HANDLER_RESULT_HANDLED
                    #end if
                #end if
            #end if
        #end if
    #end if
    return \
         result
#end _message_interface_dispatch

def def_attr_class(name, attrs) :
    "defines a class with read/write attributes with names from the sequence attrs." \
    " Objects of this class can be coerced to lists or tuples, and attributes can" \
    " also be accessed by index, like a list."

    class result :
        __slots__ = tuple(attrs)

        def __init__(self, **kwargs) :
            for name in type(self).__slots__ :
                setattr(self, name, None)
            #end for
            for name in kwargs :
                setattr(self, name, kwargs[name])
            #end for
        #end __init__

        def __repr__(self) :
            return \
                (
                        "%s(%s)"
                    %
                        (
                            type(self).__name__,
                            ", ".join
                              (
                                    "%s = %s"
                                %
                                    (name, repr(getattr(self, name)))
                                    for name in type(self).__slots__
                              ),
                        )
                )
        #end __repr__

        def __len__(self) :
            return \
                len(type(self).__slots__)
        #end __len__

        def __getitem__(self, i) :
            return \
                getattr(self, type(self).__slots__[i])
        #end __getitem__

        def  __setitem__(self, i, val) :
            setattr(self, type(self).__slots__[i], val)
        #end __setitem__

    #end class

#begin def_attr_class
    result.__name__ = name
    return \
        result
#end def_attr_class

def interface \
  (
    kind, *,
    name,
    property_change_notification = Introspection.PROP_CHANGE_NOTIFICATION.NEW_VALUE,
    deprecated = False
  ) :
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
    " code, or None (equivalent to DBUS.HANDLER_RESULT_HANDLED), or a coroutine" \
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
        if not isinstance(property_change_notification, Introspection.PROP_CHANGE_NOTIFICATION) :
            raise TypeError \
              (
                "property_change_notification must be an Introspection."
                "PROP_CHANGE_NOTIFICATION value"
              )
        #end if
        celf._interface_kind = kind
        celf._interface_name = name
        celf._interface_property_change_notification = property_change_notification
        celf._interface_deprecated = deprecated
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
        props = {}
        for info_type, meth_type in \
            (
                ("_propgetter_info", "getter"), # do first so setter can check change_notification
                ("_propsetter_info", "setter"),
            ) \
        :
            for fname in dir(celf) :
                func = getattr(celf, fname)
                if hasattr(func, info_type) :
                    propinfo = getattr(func, info_type)
                    propname = propinfo["name"]
                    if propname not in props :
                        props[propname] = {"type" : None}
                    #end if
                    propentry = props[propname]
                    if propinfo["type"] != None :
                        if propentry["type"] != None :
                            if propentry["type"] != propinfo["type"] :
                                raise ValueError \
                                  (
                                        "disagreement on type for property “%s” between"
                                        " getter and setter: “%s” versus “%s”"
                                    %
                                        (
                                            propname,
                                            dbus.unparse_signature(propentry["type"]),
                                            dbus.unparse_signature(propinfo["type"]),
                                        )
                                  )
                            #end if
                        else :
                            propentry["type"] = propinfo["type"]
                        #end if
                    #end if
                    if (
                            meth_type == "setter"
                        and
                            "getter" in propentry
                        and
                                propentry["change_notification"]
                            ==
                                Introspection.PROP_CHANGE_NOTIFICATION.CONST
                    ) :
                        raise ValueError \
                          (
                            "mustn’t specify @propsetter() for a"
                            " PROP_CHANGE_NOTIFICATION.CONST property"
                          )
                    #end if
                    if meth_type == "getter" :
                        if propinfo["change_notification"] != None :
                            propentry["change_notification"] = propinfo["change_notification"]
                        else :
                            propentry["change_notification"] = property_change_notification
                        #end if
                    #end if
                    propentry[meth_type] = func
                #end if
            #end for
        #end for
        celf._interface_props = props
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
    in_signature,
    out_signature,
    args_keyword = None,
    arg_keys = None,
    arg_attrs = None,
    result_keyword = None,
    result_keys = None,
    result_attrs = None,
    connection_keyword = None,
    message_keyword = None,
    path_keyword = None,
    bus_keyword = None,
    set_result_keyword = None,
    reply = True,
    deprecated = False
  ) :
    "Put a call to this function as a decorator for each method of an @interface()" \
    " class that is to be registered as a method of the interface." \
    " “name” is the name of the method as specified in the D-Bus message; if omitted," \
    " it defaults to the name of the function.\n" \
    "\n" \
    "This is really only useful on the server side. On the client side, omit the" \
    " method definition, and even leave out the interface definition and registration" \
    " altogether, unless you want to receive signals from the server; instead, use" \
    " Connection.get_object() to send method calls to the server."

    in_signature = dbus.parse_signature(in_signature)
    out_signature = dbus.parse_signature(out_signature)
    for cond, msg in \
        (
            (
                    (result_keyword != None or result_keys != None or result_attrs != None)
                and
                    not reply,
                "result_keyword, result_keys and result_attrs are"
                " meaningless if method does not reply",
            ),
            (arg_keys != None and arg_attrs != None, "specify arg_keys or arg_attrs, not both"),
            (arg_attrs != None and args_keyword == None, "need args_keyword with arg_attrs"),
            (
                arg_keys != None and len(arg_keys) != len(in_signature),
                "number of arg_keys should match number of items in in_signature",
            ),
            (
                arg_attrs != None and len(arg_attrs) != len(in_signature),
                "number of arg_attrs should match number of items in in_signature",
            ),
            (
                set_result_keyword != None and result_keyword != None,
                "specify set_result_keyword or result_keyword, not both",
            ),
            (
                result_keys != None and result_attrs != None,
                "specify result_keys or result_attrs, not both",
            ),
            (
                result_attrs != None and result_keyword == None,
                "need result_keyword with result_attrs",
            ),
            (
                result_keys != None and len(result_keys) != len(out_signature),
                "number of result_keys should match number of items in out_signature",
            ),
            (
                result_attrs != None and len(result_attrs) != len(out_signature),
                "number of result_attrs should match number of items in out_signature",
            ),
        ) \
    :
        if cond :
            raise ValueError(msg)
        #end if
    #end for
    if arg_keys == None :
        args_keys = arg_attrs
    #end if
    if result_keys == None :
        result_keys = result_attrs
    #end if

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
                "arg_keys" : arg_keys,
                "result_keyword" : result_keyword,
                "result_keys" : result_keys,
                "connection_keyword" : connection_keyword,
                "message_keyword" : message_keyword,
                "path_keyword" : path_keyword,
                "bus_keyword" : bus_keyword,
                "set_result_keyword" : set_result_keyword,
                "reply" : reply,
                "deprecated" : deprecated,
            }
        if arg_attrs != None :
            func._method_info["args_constructor"] = def_attr_class("%s_args" % func_name, arg_attrs)
        #end if
        if result_attrs != None :
            func._method_info["result_constructor"] = \
                def_attr_class("%s_result" % func_name, result_attrs)
        #end if
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
    in_signature,
    args_keyword = None,
    arg_keys = None,
    arg_attrs = None,
    stub = False,
    connection_keyword = None,
    message_keyword = None,
    path_keyword = None,
    bus_keyword = None,
    deprecated = False # can signals be deprecated?
  ) :
    "Put a call to this function as a decorator for each method of an @interface()" \
    " class that is to be registered as a signal of the interface." \
    " “name” is the name of the signal as specified in the D-Bus message; if omitted," \
    " it defaults to the name of the function.\n" \
    "\n" \
    "On the server side, the actual function need only be a dummy, since it is just" \
    " a placeholder for storing the information used by Connection.send_signal()."

    in_signature = dbus.parse_signature(in_signature)
    if arg_attrs != None and args_keyword == None :
        raise ValueError("need args_keyword with arg_attrs")
    #end if
    if arg_keys != None and len(arg_keys) != len(in_signature) :
        raise ValueError("number of arg_keys should match number of items in in_signature")
    #end if
    if arg_attrs != None and len(arg_attrs) != len(in_signature) :
        raise ValueError("number of arg_attrs should match number of items in in_signature")
    #end if
    if arg_keys == None :
        args_keys = arg_attrs
    #end if

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
                "arg_keys" : arg_keys,
                "stub" : stub,
                "connection_keyword" : connection_keyword,
                "message_keyword" : message_keyword,
                "path_keyword" : path_keyword,
                "bus_keyword" : bus_keyword,
                "deprecated" : deprecated,
            }
        if arg_attrs != None :
            func._signal_info["args_constructor"] = def_attr_class("%s_args" % func_name, arg_attrs)
        #end if
        return \
            func
    #end decorate

#begin signal
    return \
        decorate
#end signal

def propgetter \
  (*,
    name,
    type,
    name_keyword = None,
    connection_keyword = None,
    message_keyword = None,
    path_keyword = None,
    bus_keyword = None,
    change_notification = None
  ) :
    "Put a call to this function as a decorator for a method of an @interface()" \
    " class that is to be the getter of the named property."

    def decorate(func) :
        if not isinstance(func, types.FunctionType) :
            raise TypeError("only apply decorator to functions.")
        #end if
        assert isinstance(name, str), "property name is mandatory"
        if (
                change_notification != None
            and
                not isinstance(change_notification, Introspection.PROP_CHANGE_NOTIFICATION)
        ) :
            raise TypeError \
              (
                "change_notification must be None or an Introspection."
                "PROP_CHANGE_NOTIFICATION value"
              )
        #end if
        func._propgetter_info = \
            {
                "name" : name,
                "type" : dbus.parse_single_signature(type),
                "name_keyword" : name_keyword,
                "connection_keyword" : connection_keyword,
                "message_keyword" : message_keyword,
                "path_keyword" : path_keyword,
                "bus_keyword" : bus_keyword,
                "change_notification" : change_notification,
            }
        return \
            func
    #end decorate

#begin propgetter
    return \
        decorate
#end propgetter

def propsetter \
  (*,
    name,
    type,
    name_keyword = None,
    type_keyword = None,
    value_keyword,
    connection_keyword = None,
    message_keyword = None,
    path_keyword = None,
    bus_keyword = None
  ) :
    "Put a call to this function as a decorator for a method of an @interface()" \
    " class that is to be the setter of the named property."

    def decorate(func) :
        if not isinstance(func, types.FunctionType) :
            raise TypeError("only apply decorator to functions.")
        #end if
        assert isinstance(name, str), "property name is mandatory"
        func._propsetter_info = \
            {
                "name" : name,
                "type" : dbus.parse_single_signature(type),
                "name_keyword" : name_keyword,
                "type_keyword" : type_keyword,
                "value_keyword" : value_keyword,
                "connection_keyword" : connection_keyword,
                "message_keyword" : message_keyword,
                "path_keyword" : path_keyword,
                "bus_keyword" : bus_keyword,
            }
        return \
            func
    #end decorate

#begin propsetter
    return \
        decorate
#end propsetter

#+
# Introspection
#-

def introspect(interface) :
    "returns an Introspection.Interface object that describes the specified" \
    " @interface() class."
    if not is_interface(interface) :
        raise TypeError("interface must be an @interface()-type class")
    #end if

    def add_deprecated(annots, deprecated) :
        # common routine for generating “deprecated” annotations.
        if deprecated :
            annots.append \
              (
                Introspection.Annotation(name = "org.freedesktop.DBus.Deprecated", value = "true")
              )
        #end if
    #end add_deprecated

#begin introspect
    methods = []
    for name in interface._interface_methods :
        method = interface._interface_methods[name]
        annots = []
        add_deprecated(annots, method._method_info["deprecated"])
        if not method._method_info["reply"] :
            annots.append \
              (
                Introspection.Annotation
                  (
                    name = "org.freedesktop.DBus.Method.NoReply",
                    value = "true"
                  )
              )
        #end if
        args = []
        for keys_keyword, sig_keyword, direction in \
            (
                ("arg_keys", "in_signature", Introspection.DIRECTION.IN),
                ("result_keys", "out_signature", Introspection.DIRECTION.OUT),
            ) \
        :
            arg_sigs = dbus.parse_signature(method._method_info[sig_keyword])
            arg_names = method._method_info[keys_keyword]
            if arg_names == None :
                arg_names = [None] * len(arg_sigs)
            #end if
            for arg_name, arg_sig in zip(arg_names, arg_sigs) :
                args.append \
                  (
                    Introspection.Interface.Method.Arg
                      (
                        name = arg_name,
                        type = arg_sig,
                        direction = direction
                      )
                  )
            #end for
        #end for
        methods.append \
          (
            Introspection.Interface.Method
              (
                name = name,
                args = args,
                annotations = annots
              )
          )
    #end for
    signals = []
    for name in interface._interface_signals :
        signal = interface._interface_signals[name]
        annots = []
        add_deprecated(annots, signal._signal_info["deprecated"])
        args = []
        arg_sigs = dbus.parse_signature(signal._signal_info["in_signature"])
        arg_names = signal._signal_info["arg_keys"]
        if arg_names == None :
            arg_names = [None] * len(arg_sigs)
        #end if
        for arg_name, arg_sig in zip(arg_names, arg_sigs) :
            args.append \
              (
                Introspection.Interface.Signal.Arg(name = arg_name, type = arg_sig)
              )
        #end for
        signals.append \
          (
            Introspection.Interface.Signal
              (
                name = name,
                args = args,
                annotations = annots
              )
          )
    #end for
    properties = []
    for name in interface._interface_props :
        prop = interface._interface_props[name]
        annots = []
        if (
                "getter" in prop
            and
                prop["change_notification"] != interface._interface_property_change_notification
        ) :
            annots.append \
              (
                Introspection.Annotation
                  (
                    name = "org.freedesktop.DBus.Property.EmitsChangedSignal",
                    value = prop["change_notification"].value
                  )
              )
        #end if
        properties.append \
          (
            Introspection.Interface.Property
              (
                name = name,
                type = dbus.parse_single_signature(prop["type"]),
                access =
                    (
                        None,
                        Introspection.ACCESS.READ,
                        Introspection.ACCESS.WRITE,
                        Introspection.ACCESS.READWRITE,
                    )[
                            int("getter" in prop)
                        |
                            int("setter" in prop) << 1
                    ],
                annotations = annots
              )
          )
    #end for
    annots = []
    if (
            interface._interface_property_change_notification
        !=
            Introspection.PROP_CHANGE_NOTIFICATION.NEW_VALUE
    ) :
        annots.append \
          (
            Introspection.Annotation
              (
                name = "org.freedesktop.DBus.Property.EmitsChangedSignal",
                value = interface._interface_property_change_notification.value
              )
          )
    #end if
    add_deprecated(annots, interface._interface_deprecated)
    return \
        Introspection.Interface \
          (
            name = interface._interface_name,
            methods = methods,
            signals = signals,
            properties = properties,
            annotations = annots
          )
#end introspect

def _append_args(message, call_info, args, kwargs) :
    message_args = [None] * len(call_info.in_signature)
    if len(args) != 0 :
        if len(args) > len(message_args) :
            raise ValueError("too many args")
        #end if
        message_args[:len(args)] = args
    #end if
    if len(kwargs) != 0 :
        arg_positions = {}
        idx = 0
        for arg in call_info.args :
            if (
                    isinstance(arg, Introspection.Interface.Signal.Arg)
                or
                    arg.direction == Introspection.DIRECTION.IN
            ) :
                arg_positions[arg.name] = idx
                idx += 1
            #end if
        #end for
        for arg_name in kwargs :
            if arg_name not in arg_positions :
                raise KeyError("no such arg name “%s”" % arg_name)
            #end if
            pos = arg_positions[arg_name]
            if message_args[pos] != None :
                raise ValueError("duplicate value for arg %d" % pos)
            #end if
            message_args[pos] = kwargs[arg_name]
        #end for
    #end if
    missing = set(pos for pos in range(len(message_args)) if message_args[pos] == None)
    if len(missing) != 0 :
        raise ValueError \
          (
                "too few args specified: missing %s"
            %
                ", ".join("%d" % pos for pos in sorted(missing))
          )
    #end if
    message.append_objects(call_info.in_signature, *message_args)
#end _append_args

def def_proxy_interface(kind, *, name, introspected, is_async) :
    "given an Introspection.Interface object, creates a proxy class that can be" \
    " instantiated by a client to send method-call messages to a server," \
    " or by a server to send signal messages to clients. is_async indicates" \
    " whether method calls are done via coroutines as opposed to blocking" \
    " the thread. The resulting class can be instantiated by\n" \
    "\n" \
    "    instance = proxy_class(«connection», «dest»)\n" \
    "\n" \
    " where «connection» is a dbussy.Connection object to use for sending and receiving" \
    " the messages, and «dest» is the bus name to which to send the messages."

    if not isinstance(kind, INTERFACE) :
        raise TypeError("kind must be an INTERFACE enum value")
    #end if
    if not isinstance(introspected, Introspection.Interface) :
        raise TypeError("introspected must be an Introspection.Interface")
    #end if

    class proxy :
        # class that will be be turned, to be instantiated for a given connection,
        # destination and path.

        # class field _iface_name contains interface name.
        __slots__ = ("_parent", "_conn", "_dest", "_path", "_timeout")

        def __init__(self, *, parent, connection, dest, path, timeout = DBUS.TIMEOUT_USE_DEFAULT) :
            if is_async :
                assert connection.loop != None, "no event loop to attach coroutines to"
            #end if
            self._parent = parent
            self._conn = connection
            self._dest = dest
            self._path = path
            self._timeout = timeout
        #end __init__

        # rest filled in dynamically below.

    #end proxy

    def def_method(intr_method) :
        # constructs a method-call method,

        if is_async :

            async def call_method(self, *args, **kwargs) :
                message = dbus.Message.new_method_call \
                  (
                    destination = self._dest,
                    path = dbus.unsplit_path(self._path),
                    iface = self._iface_name,
                    method = intr_method.name
                  )
                _append_args(message, intr_method, args, kwargs)
                if intr_method.expect_reply :
                    reply = await self._conn.send_await_reply(message, self._timeout)
                    result = reply.expect_return_objects(intr_method.out_signature)
                else :
                    message.no_reply = True
                    self._conn.send(message)
                    result = None
                #end if
                return \
                    result
            #end call_method

        else :

            def call_method(self, *args, **kwargs) :
                message = dbus.Message.new_method_call \
                  (
                    destination = self._dest,
                    path = dbus.unsplit_path(self._path),
                    iface = self._iface_name,
                    method = intr_method.name
                  )
                _append_args(message, intr_method, args, kwargs)
                if intr_method.expect_reply :
                    reply = self._conn.send_with_reply_and_block(message, self._timeout)
                    result = reply.expect_return_objects(intr_method.out_signature)
                else :
                    message.no_reply = True
                    self._conn.send(message)
                    result = None
                #end if
                return \
                    result
            #end call_method

        #end if

    #begin def_method
        call_method.__name__ = intr_method.name
        call_method.__doc__ = \
            (
                "method, %(args)s, %(result)s"
            %
                {
                    "args" :
                        (
                            lambda : "no args",
                            lambda : "args %s" % dbus.unparse_signature(intr_method.in_signature),
                        )[len(intr_method.in_signature) != 0](),
                    "result" :
                        (
                            lambda : "no result",
                            lambda : "result %s" % dbus.unparse_signature(intr_method.out_signature),
                        )[len(intr_method.out_signature) != 0](),
                }
            )
        setattr(proxy, intr_method.name, call_method)
    #end def_method

    def def_signal(intr_signal) :
        # constructs a signal method. These are never async, since messages
        # are queued and there is no reply.

        def send_signal(self, *args, **kwargs) :
            message = dbus.Message.new_signal \
              (
                path = dbus.unsplit_path(self._path),
                iface = self._iface_name,
                name = intr_signal.name
              )
            _append_args(message, intr_signal, args, kwargs)
            self._conn.send(message)
        #end send_signal

    #begin def_signal
        send_signal.__name__ = intr_signal.name
        send_signal.__doc__ = \
            (
                    "signal, %(args)s"
                %
                    {
                        "args" :
                            (
                                lambda : "no args",
                                lambda : "args %s" % dbus.unparse_signature(intr_signal.in_signature),
                            )[len(intr_signal.in_signature) != 0](),
                    }
            )
        setattr(proxy, signal.name, send_signal)
    #end def_signal

    def def_prop(intr_prop) :
        # defines getter and/or setter methods as appropriate for a property.

        if is_async :

            async def get_prop(self) :
                message = dbus.Message.new_method_call \
                  (
                    destination = self._dest,
                    path = dbus.unsplit_path(self._path),
                    iface = DBUS.INTERFACE_PROPERTIES,
                    method = "Get"
                  )
                message.append_objects("ss", self._iface_name, intr_prop.name)
                reply = await self._conn.send_await_reply(message, self._timeout)
                return \
                    reply.expect_return_objects("v")[0][1]
            #end get_prop

            def set_prop(self, value) :
                # Unfortunately, Python doesn’t (currently) allow “await”
                # on the LHS of an assignment. So to avoid holding up the
                # thread, I put a task on the event loop to watch over
                # the completion of the send. This means any error is
                # going to be reported asynchronously. C’est la vie.
                message = dbus.Message.new_method_call \
                  (
                    destination = self._dest,
                    path = dbus.unsplit_path(self._path),
                    iface = DBUS.INTERFACE_PROPERTIES,
                    method = "Set"
                  )
                message.append_objects("ssv", self._iface_name, intr_prop.name, (intr_prop.type, value))
                set_prop_pending = self._conn.loop.create_future()
                self._parent._set_prop_pending.append(set_prop_pending)
                pending = self._conn.send_with_reply(message, self._timeout)
                async def sendit() :
                    reply = await pending.await_reply()
                    set_prop_pending.set_result(None)
                    self._parent._set_prop_pending.pop \
                      (
                        self._parent._set_prop_pending.index(set_prop_pending)
                      )
                    if reply.type == DBUS.MESSAGE_TYPE_METHOD_RETURN :
                        pass
                    elif reply.type == DBUS.MESSAGE_TYPE_ERROR :
                        raise dbus.DBusError(reply.error_name, reply.expect_objects("s")[0])
                    else :
                        raise ValueError("unexpected reply type %d" % reply.type)
                    #end if
                #end sendit

                self._conn.loop.create_task(sendit())
            #end set_prop

        else :

            def get_prop(self) :
                message = dbus.Message.new_method_call \
                  (
                    destination = self._dest,
                    path = dbus.unsplit_path(self._path),
                    iface = DBUS.INTERFACE_PROPERTIES,
                    method = "Get"
                  )
                message.append_objects("ss", self._iface_name, intr_prop.name)
                reply = self._conn.send_with_reply_and_block(message, self._timeout)
                return \
                    reply.expect_return_objects("v")[0][1]
            #end get_prop

            def set_prop(self, value) :
                message = dbus.Message.new_method_call \
                  (
                    destination = self._dest,
                    path = dbus.unsplit_path(self._path),
                    iface = DBUS.INTERFACE_PROPERTIES,
                    method = "Set"
                  )
                message.append_objects("ssv", self._iface_name, intr_prop.name, (intr_prop.type, value))
                reply = self._conn.send_with_reply_and_block(message, self._timeout)
                if reply.type == DBUS.MESSAGE_TYPE_METHOD_RETURN :
                    pass
                elif reply.type == DBUS.MESSAGE_TYPE_ERROR :
                    raise dbus.DBusError(reply.error_name, reply.expect_objects("s")[0])
                else :
                    raise ValueError("unexpected reply type %d" % reply.type)
                #end if
            #end set_prop

        #end if

        def get_prop_noaccess(self) :
            raise dbus.DbusError \
              (
                name = DBUS.ERROR_ACCESS_DENIED,
                message = "property “%s” cannot be read" % intro_prop.name
              )
        #end get_prop_noaccess

    #begin def_prop
        if intr_prop.access == Introspection.ACCESS.WRITE :
            get_prop = get_prop_noaccess
        #end if
        if intr_prop.access == Introspection.ACCESS.READ :
            set_prop = None
        #end if
        prop = property(fget = get_prop, fset = set_prop)
        setattr(proxy, intr_prop.name, prop)
    #end def_prop

    class proxy_factory :
        # class that will be returned.

        __slots__ = ("connection", "dest", "timeout", "_set_prop_pending")

        def __init__(self, *, connection, dest, timeout = DBUS.TIMEOUT_USE_DEFAULT) :
            if is_async :
                assert connection.loop != None, "no event loop to attach coroutines to"
            #end if
            self.connection = connection
            self.dest = dest
            self.timeout = timeout
            if is_async :
                self._set_prop_pending = []
            else :
                self._set_prop_pending = None
            #end if
        #end __init__

        def __getitem__(self, path) :
            return \
                self.template \
                  (
                    parent = self,
                    connection = self.connection,
                    dest = self.dest,
                    path = path,
                    timeout = self.timeout
                  )
        #end __getitem__

        async def set_prop_flush(self) :
            "workaround for the fact that prop-setter has to queue a separate" \
            " asynchronous task; caller can await this coroutine to ensure that" \
            " all pending set-property calls have completed."
            if not is_async :
                raise RuntimeError("not without an event loop")
            #end if
            if len(self._set_prop_pending) != 0 :
                await asyncio.wait(self._set_prop_pending, loop = self.connection.loop)
            #end if
        #end set_prop_flush

    #end proxy_factory

#begin def_proxy_interface
    if name != None :
        class_name = name
    else :
        class_name = introspected.name.replace(".", "_")
    #end if
    proxy.__name__ = class_name
    proxy._iface_name = introspected.name
    proxy.__doc__ = "for making method calls on the %s interface." % introspected.name
    if kind != INTERFACE.SERVER :
        for method in introspected.methods :
            def_method(method)
        #end for
        for prop in introspected.properties :
            def_prop(prop)
        #end for
    #end if
    if kind != INTERFACE.CLIENT :
        for signal in introspected.signals :
            def_signal(signal)
        #end for
    #end if
    proxy_factory.__name__ = "%s_factory" % proxy.__name__
    proxy_factory.__doc__ = \
        (
                "proxy factory for a %(kind)s D-Bus interface named %(iname)s. Instantiate as\n"
                "\n"
                "    %(cname)s(connection = «connection»[, dest = «dest»[, timeout = «timeout»]])\n"
                "\n"
                "where «connection» is the dbussy.Connection instance to use for sending"
                " messages and receiving replies, and «dest» is the destination" \
                " bus name for sending method calls (not needed if only sending signals)."
                " The resulting «proxy» object can be indexed by object path, as follows:\n"
                "\n"
                "     «proxy»[«path»]\n"
                "\n"
                "to obtain the actual proxy interface object that can be used to do method"
                " calls or signal calls."
            %
                {
                    "cname" : class_name,
                    "iname" : introspected.name,
                    "kind" :
                        {
                            INTERFACE.CLIENT : "client-side",
                            INTERFACE.SERVER : "server-side",
                            INTERFACE.CLIENT_AND_SERVER : "client-and-server-side",
                        }[kind]
                }
        )
    proxy_factory.template = proxy
    return \
        proxy_factory
#end def_proxy_interface

#+
# Predefined interfaces
#-

@interface(INTERFACE.CLIENT_AND_SERVER, name = DBUS.INTERFACE_PEER)
class PeerStub :
    "This is registered as a fallback at the root of your object tree to get" \
    " automatic introspection of the DBUS.INTERFACE_PEER interface. The" \
    " implementation is hard-coded inside libdbus itself, so the methods" \
    " here will never be called."

    @method \
      (
        name = "Ping",
        in_signature = "",
        out_signature = "",
      )
    def ping(self) :
        raise NotImplementedError("How did you get here?")
    #end ping

    @method \
      (
        name = "GetMachineId",
        in_signature = "",
        out_signature = "s",
        result_keys = ["machine_uuid"],
      )
    def get_machine_id(self) :
        raise NotImplementedError("How did you get here?")
    #end get_machine_id

#end PeerStub

@interface(INTERFACE.CLIENT_AND_SERVER, name = DBUS.INTERFACE_INTROSPECTABLE)
class IntrospectionHandler :
    "Register this as a fallback at the root of your object tree to obtain" \
    " automatic introspection of any point in the tree."

    @method \
      (
        name = "Introspect",
        in_signature = "",
        out_signature = "s",
        path_keyword = "path",
        message_keyword = "message",
        bus_keyword = "bus",
      )
    def introspect(self, message, bus, path) :
        interfaces = {}
        children = None # actually redundant
        level = bus._dispatch
        levels = iter(dbus.split_path(path))
        while True :
            component = next(levels, None)
            for entry in level.interfaces.values() :
                if component == None or entry.fallback :
                    interface = type(entry.interface)
                    if interface._interface_kind != INTERFACE.CLIENT :
                        interfaces[interface._interface_name] = interface
                          # replace any higher-level entry for same name
                    #end if
                #end if
            #end for
            if (
                    component == None
                      # reached bottom of path
                or
                    component not in level.children
                      # no handlers to be found further down path
            ) :
                children = sorted(level.children.keys())
                break
            #end if
            level = level.children[component]
              # search another step down the path
        #end while
        introspection = Introspection \
          (
            interfaces = list
              (
                introspect(iface)
                for iface in sorted(interfaces.values(), key = lambda iface : iface._interface_name)
              ),
            nodes = list
              (
                Introspection.Node(name = child) for child in children
              )
          )
        _send_method_return(bus.connection, message, "s", [introspection.unparse()])
        return \
            DBUS.HANDLER_RESULT_HANDLED
    #end introspect

#end IntrospectionHandler

@interface(INTERFACE.CLIENT_AND_SERVER, name = DBUS.INTERFACE_PROPERTIES)
class PropertyHandler :
    "Register this as a fallback at the root of your object tree to provide" \
    " automatic dispatching to any @propgetter() and @propsetter() methods" \
    " defined for registered interfaces appropriate to an object path."

    @method \
      (
        name = "Get",
        in_signature = "ss",
        out_signature = "v",
        args_keyword = "args",
        path_keyword = "path",
        message_keyword = "message",
        bus_keyword = "bus"
      )
    def getprop(self, bus, message, path, args) :
        interface_name, propname = args
        dispatch = bus.get_dispatch_interface(path, interface_name)
        props = type(dispatch)._interface_props
        if propname in props :
            propentry = props[propname]
            if "getter" in propentry :
                getter = getattr(dispatch, propentry["getter"].__name__)
                kwargs = {}
                for keyword_keyword, value in \
                    (
                        ("name_keyword", lambda : propname),
                        ("connection_keyword", lambda : bus.connection),
                        ("message_keyword", lambda : message),
                        ("path_keyword", lambda : path),
                        ("bus_keyword", lambda : bus),
                    ) \
                :
                    if getter._propgetter_info[keyword_keyword] != None :
                        kwargs[getter._propgetter_info[keyword_keyword]] = value()
                    #end if
                #end for
                try :
                    propvalue = getter(**kwargs)
                except HandlerError as err :
                    propvalue = err.as_error()
                #end try
                if isinstance(propvalue, types.CoroutineType) :
                    assert bus.loop != None, "no event loop to attach coroutine to"
                    async def await_return_value(task) :
                        propvalue = await task
                        _send_method_return \
                          (
                            connection = bus.connection,
                            message = message,
                            sig = [dbus.VariantType()],
                            args = [(propentry["type"], propvalue)]
                          )
                    #end await_return_value
                    bus.loop.create_task(await_return_value(propvalue))
                    reply = None
                elif isinstance(propvalue, dbus.Error) :
                    assert propvalue.is_set, "unset Error object returned from propgetter"
                    reply = message.new_error(propvalue.name, propvalue.nessage)
                else :
                    _send_method_return \
                      (
                        connection = bus.connection,
                        message = message,
                        sig = [dbus.VariantType()],
                        args = [(propentry["type"], propvalue)]
                      )
                    reply = None
                #end if
            else :
                reply = message.new_error \
                  (
                    name = DBUS.ERROR_ACCESS_DENIED,
                    message = "property “%s” cannot be read" % propname
                  )
            #end if
        else :
            reply = message.new_error \
              (
                name = DBUS.ERROR_UNKNOWN_PROPERTY,
                message = "property “%s” cannot be found" % propname
              )
        #end if
        if reply != None :
            bus.connection.send(reply)
        #end if
        return \
            DBUS.HANDLER_RESULT_HANDLED
    #end getprop

    @method \
      (
        name = "Set",
        in_signature = "ssv",
        out_signature = "",
        args_keyword = "args",
        path_keyword = "path",
        message_keyword = "message",
        bus_keyword = "bus"
      )
    def setprop(self, bus, message, path, args) :

        def notify_changed() :
            # sends property-changed signal if appropriate.
            if "getter" in propentry :
                notify = propentry["change_notification"]
                if notify == Introspection.PROP_CHANGE_NOTIFICATION.NEW_VALUE :
                    bus.prop_changed(path, interface_name, propname, proptype, propvalue)
                elif notify == Introspection.PROP_CHANGE_NOTIFICATION.INVALIDATES :
                    bus.prop_changed(path, interface_name, propname, None, None)
                #end if
            #end if
        #end notify_changed

    #begin setprop
        interface_name, propname, (proptype, propvalue) = args
        dispatch = bus.get_dispatch_interface(path, interface_name)
        props = type(dispatch)._interface_props
        if propname in props :
            propentry = props[propname]
            if "setter" in propentry :
                setter = getattr(dispatch, propentry["setter"].__name__)
                try :
                    if propentry["type"] != None and propentry["type"] != dbus.parse_single_signature(proptype) :
                        raise HandlerError \
                          (
                            name = DBUS.ERROR_INVALID_ARGS,
                            message =
                                    "new property type %s does not match expected signature %s"
                                %
                                    (proptype, dbus.unparse_signature(propentry["type"]))
                          )
                    #end if
                    kwargs = {}
                    for keyword_keyword, value in \
                        (
                            ("name_keyword", lambda : propname),
                            ("type_keyword", lambda : proptype),
                            ("value_keyword", lambda : propvalue),
                            ("connection_keyword", lambda : bus.connection),
                            ("message_keyword", lambda : message),
                            ("path_keyword", lambda : path),
                            ("bus_keyword", lambda : bus),
                        ) \
                    :
                        if setter._propsetter_info[keyword_keyword] != None :
                            kwargs[setter._propsetter_info[keyword_keyword]] = value()
                        #end if
                    #end for
                    setresult = setter(**kwargs)
                except HandlerError as err :
                    setresult = err.as_error()
                #end try
                if isinstance(setresult, types.CoroutineType) :
                    assert bus.loop != None, "no event loop to attach coroutine to"
                    async def wait_set_done() :
                        await setresult
                        reply = message.new_method_return()
                        bus.connection.send(reply)
                        notify_changed()
                    #end wait_set_done
                    bus.loop.create_task(wait_set_done())
                    reply = None # for now
                elif isinstance(setresult, dbus.Error) :
                    assert setresult.is_set, "unset Error object returned"
                    reply = message.new_error(setresult.name, setresult.message)
                elif setresult == None :
                    reply = message.new_method_return()
                    notify_changed()
                else :
                    raise ValueError("invalid propsetter result %s" % repr(setresult))
                #end if
            else :
                reply = message.new_error \
                  (
                    name = DBUS.ERROR_PROPERTY_READ_ONLY,
                    message = "property “%s” cannot be written" % propname
                  )
            #end if
        else :
            reply = message.new_error \
              (
                name = DBUS.ERROR_UNKNOWN_PROPERTY,
                message = "property “%s” cannot be found" % propname
              )
        #end if
        if reply != None :
            bus.connection.send(reply)
        #end if
        return \
            DBUS.HANDLER_RESULT_HANDLED
    #end setprop

    @method \
      (
        name = "GetAll",
        in_signature = "s",
        out_signature = "a{sv}",
        args_keyword = "args",
        path_keyword = "path",
        message_keyword = "message",
        bus_keyword = "bus"
      )
    def get_all_props(self, bus, message, path, args) :
        interface_name, = args
        dispatch = bus.get_dispatch_interface(path, interface_name)
        props = type(dispatch)._interface_props
        propnames = iter(props.keys())
        properror = None
        propvalues = {}
        while True :
            propname = next(propnames, None)
            if propname == None :
                break
            propentry = props[propname]
            if "getter" in propentry :
                kwargs = {}
                for keyword_keyword, value in \
                    (
                        ("name_keyword", lambda : propname),
                        ("connection_keyword", lambda : bus.connection),
                        ("message_keyword", lambda : message),
                        ("path_keyword", lambda : path),
                        ("bus_keyword", lambda : bus),
                    ) \
                :
                    if getter._propgetter_info[keyword_keyword] != None :
                        kwargs[getter._propgetter_info[keyword_keyword]] = value()
                    #end if
                #end for
                try :
                    propvalue = getter(**kwargs)
                except HandlerError as err :
                    properror = err.as_error()
                    break
                #end try
                propvalues[propname] = (propentry["type"], propvalue)
            #end if
        #end for
        if properror != None :
            reply = message.new_error(properror.name, properror.message)
            bus.connection.send(reply)
        else :
            _send_method_return(bus.connection, message, "a{sv}", [propvalue])
        #end if
        return \
            DBUS.HANDLER_RESULT_HANDLED
    #end get_all_props

    @signal(name = "PropertiesChanged", in_signature = "sa{sv}as", stub = True)
    def properties_changed(self) :
        "for use with Connection.send_signal."
        pass
    #end properties_changed

#end PropertyHandler

#+
# Cleanup
#-

def _atexit() :
    # disable all __del__ methods at process termination to avoid unpredictable behaviour
    for cls in Connection, Connection.BusName, Server :
        delattr(cls, "__del__")
    #end for
#end _atexit
atexit.register(_atexit)
del _atexit
