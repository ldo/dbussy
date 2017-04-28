"""
Simplified higher-level Python binding for D-Bus, implementing proxy
Python objects to represent D-Bus objects. The API is consciously
modelled on dbus-python <http://dbus.freedesktop.org/doc/dbus-python/>.
"""
#+
# Copyright 2017 Lawrence D'Oliveiro <ldo@geek-central.gen.nz>.
# Licensed under the GNU Lesser General Public License v2.1 or later.
#-

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

class Bus :

    __slots__ = ("__weakref__", "connection", "loop") # to forestall typos

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
            celf._instances[connection] = self
        #end if
        return \
            self
    #end __new__

    def attach_asyncio(self, loop = None) :
        self.connection.attach_asyncio(loop)
        self.loop = self.connection.loop
        return \
            self
    #end attach_asyncio

    def get_object(self, bus_name, path) :
        return \
            Object(self, bus_name, path)
    #end get_object

#end Bus

def SessionBus() :
    return \
        Bus(dbus.Connection.bus_get(DBUS.BUS_SESSION, private = False))
#end SessionBus

def SystemBus() :
    return \
        Bus(dbus.Connection.bus_get(DBUS.BUS_SYSTEM, private = False))
#end SystemBus

class Object :

    __slots__ = ("bus", "name", "path")

    def __init__(self, bus, name, path) :
        if not isinstance(bus, Bus) :
            raise TypeError("bus must be a Bus")
        #end if
        self.bus = bus
        self.name = name
        self.path = path
    #end __init__

#end Object

class Interface :

    __slots__ = ("object", "name", "timeout")

    def __init__(self, object, name, timeout = DBUS.TIMEOUT_USE_DEFAULT) :
        if not isinstance(object, Object) :
            raise TypeError("object must be an Object")
        #end if
        self.object = object
        self.name = name
        self.timeout = timeout
    #end __init__

    def __getattr__(self, attrname) :
        return \
            Method(self, attrname)
    #end __getattr__

#end Interface

class AsyncInterface(Interface) :

    def __getattr__(self, attrname) :
        return \
            AsyncMethod(self, attrname)
    #end __getattr__

#end AsyncInterface

class Method :

    __slots__ = ("interface", "method")

    def __init__(self, interface, method) :
        if not isinstance(interface, Interface) :
            raise TypeError("interface must be a Interface")
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
            #print("guess signature for %s = %s" % (repr(args), repr(guess_signature(args)))) # debug
            message.append_objects(guess_signature(args), args)
        #end if
        return \
            message
    #end _construct_message

    def _process_reply(self, reply) :
        if reply.type == DBUS.MESSAGE_TYPE_METHOD_RETURN :
            result = list(reply.objects)
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

#end Method

class AsyncMethod(Method) :

    async def __call__(self, *args) :
        message = self._construct_message(args)
        reply = await self.interface.object.bus.connection.send_await_reply(message, timeout = self.interface.timeout)
        return \
            self._process_reply(reply)
    #end _call__

#end AsyncMethod
