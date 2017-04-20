#+
# Pure-Python binding for parts of D-Bus <https://www.freedesktop.org/wiki/Software/dbus/>,
# built around libdbus.
#
# libdbus API: <https://dbus.freedesktop.org/doc/api/html/index.html>.
#-

import enum
import ctypes as ct
import atexit

dbus = ct.cdll.LoadLibrary("libdbus-1.so.3")

class DBUS :
    "useful definitions adapted from the D-Bus includes. You will need to use the" \
    " constants, but apart from that, see the more Pythonic wrappers defined outside" \
    " this class in preference to accessing low-level structures directly."

    # General ctypes gotcha: when passing addresses of ctypes-constructed objects
    # to routine calls, do not construct the objects directly in the call. Otherwise
    # the refcount goes to 0 before the routine is actually entered, and the object
    # can get prematurely disposed. Always store the object reference into a local
    # variable, and pass the value of the variable instead.

    bool_t = ct.c_uint

    HandlerResult = ct.c_uint

    ObjectPathUnregisterFunction = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_void_p)
    ObjectPathMessageFunction = ct.CFUNCTYPE(HandlerResult, ct.c_void_p, ct.c_void_p, ct.c_void_p)

    class ObjectPathVTable(ct.Structure) :
        pass
    #end ObjectPathVTable
    ObjectPathVTable._fields_ = \
        [
            ("unregister_function", ObjectPathUnregisterFunction),
            ("message_function", ObjectPathMessageFunction),
            ("internal_pad1", ct.CFUNCTYPE(None, ct.c_void_p)),
            ("internal_pad2", ct.CFUNCTYPE(None, ct.c_void_p)),
            ("internal_pad3", ct.CFUNCTYPE(None, ct.c_void_p)),
            ("internal_pad4", ct.CFUNCTYPE(None, ct.c_void_p)),
        ]
    ObjectPathVTablePtr = ct.POINTER(ObjectPathVTable)

    FreeFunction = ct.CFUNCTYPE(None, ct.c_void_p)

    AddWatchFunction = ct.CFUNCTYPE(bool_t, ct.c_void_p, ct.c_void_p)
    RemoveWatchFunction = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_void_p)
    WatchToggledFunction = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_void_p)

    class Error(ct.Structure) :
        _fields_ = \
            [
                ("name", ct.c_char_p),
                ("message", ct.c_char_p),
                ("padding", 2 * ct.c_void_p),
            ]
    #end Error
    ErrorPtr = ct.POINTER(Error)

#end DBUS

#+
# Library prototypes
#-

dbus.dbus_connection_open.restype = ct.c_void_p
dbus.dbus_connection_open.argtypes = (ct.c_char_p, ct.c_void_p)
dbus.dbus_connection_open_private.restype = ct.c_void_p
dbus.dbus_connection_open_private.argtypes = (ct.c_char_p, ct.c_void_p)
dbus.dbus_connection_read_write.restype = DBUS.bool_t
dbus.dbus_connection_read_write.argtypes = (ct.c_void_p, ct.c_int)
dbus.dbus_connection_read_write_dispatch.restype = DBUS.bool_t
dbus.dbus_connection_read_write_dispatch.argtypes = (ct.c_void_p, ct.c_int)
dbus.dbus_connection_ref.restype = ct.c_void_p
dbus.dbus_connection_ref.argtypes = (ct.c_void_p,)
dbus.dbus_connection_register_fallback.restype = DBUS.bool_t
dbus.dbus_connection_register_fallback.argtypes = (ct.c_void_p, ct.c_char_p, DBUS.ObjectPathVTablePtr, ct.c_void_p)
dbus.dbus_connection_register_object_path.restype = DBUS.bool_t
dbus.dbus_connection_register_object_path.argtypes = (ct.c_void_p, ct.c_char_p, DBUS.ObjectPathVTablePtr, ct.c_void_p)
dbus.dbus_connection_send.restype = DBUS.bool_t
dbus.dbus_connection_send.argtypes = (ct.c_void_p, ct.c_void_p, ct.POINTER(ct.c_uint))
dbus.dbus_connection_send_with_reply.restype = DBUS.bool_t
dbus.dbus_connection_send_with_reply.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_int)
dbus.dbus_connection_set_watch_functions.restype = DBUS.bool_t
dbus.dbus_connection_set_watch_functions.argtypes = (ct.c_void_p, DBUS.AddWatchFunction, DBUS.RemoveWatchFunction, DBUS.WatchToggledFunction, ct.c_void_p, DBUS.FreeFunction)
dbus.dbus_connection_unref.restype = None
dbus.dbus_connection_unref.argtypes = (ct.c_void_p,)
dbus.dbus_connection_unregister_object_path.restype = DBUS.bool_t
dbus.dbus_connection_unregister_object_path.argtypes = (ct.c_void_p, ct.c_char_p)

dbus.dbus_error_init.restype = None
dbus.dbus_error_init.argtypes = (DBUS.ErrorPtr,)
dbus.dbus_error_free.restype = None
dbus.dbus_error_free.argtypes = (DBUS.ErrorPtr,)
dbus.dbus_move_error.restype = None
dbus.dbus_move_error.argtypes = (DBUS.ErrorPtr, DBUS.ErrorPtr)
dbus.dbus_error_has_name.restype = DBUS.bool_t
dbus.dbus_error_has_name.argtypes = (DBUS.ErrorPtr, ct.c_char_p)
dbus.dbus_error_is_set.restype = DBUS.bool_t
dbus.dbus_error_is_set.argtypes = (DBUS.ErrorPtr,)
dbus.dbus_set_error.restype = None
dbus.dbus_set_error.argtypes = (DBUS.ErrorPtr, ct.c_char_p, ct.c_char_p, ct.c_char_p)
  # note I can’t handle varargs

#+
# High-level stuff follows
#-

class Connection :
    "wrapper around a DBusConnection object."
    # <https://dbus.freedesktop.org/doc/api/html/group__DBusConnection.html>
    pass # TBD
#end Connection

class Message :
    "wrapper around a DBusMessage object."
    # <https://dbus.freedesktop.org/doc/api/html/group__DBusMessage.html>
    pass # TBD
#end Message

class Error :
    "wrapper around a DBusError object."
    # <https://dbus.freedesktop.org/doc/api/html/group__DBusErrors.html>

    __slots__ = ("_dbobj",) # to forestall typos

    def __init__(self) :
        dbobj = DBUS.Error()
        dbus.dbus_error_init(dbobj)
        self._dbobj = dbobj
    #end __init__

    def __del__(self) :
        if self._dbobj != None :
            dbus.dbus_error_free(self._dbobj)
            self._dbobj = None
        #end if
    #end __del__

    def set(self, name, msg) :
        dbus.dbus_set_error(self._dbobj, name.encode(), b"%s", msg.encode())
    #end set

    @property
    def is_set(self) :
        return \
            dbus.dbus_error_is_set(self._dbobj) != 0
    #end is_set

    def has_name(self, name) :
        return \
            dbus.dbus_error_has_name(self._dbobj, name.encode()) != 0
    #end has_name

    @property
    def name(self) :
        return \
            self._dbobj.name.decode()
    #end name

    @property
    def message(self) :
        return \
            self._dbobj.message.decode()
    #end message

#end Error

# more TBD

def _atexit() :
    # disable all __del__ methods at process termination to avoid segfaults
    for cls in Connection, Message, Error :
        delattr(cls, "__del__")
    #end for
#end _atexit
# atexit.register(_atexit) # TBD enable later
del _atexit
