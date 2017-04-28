"""
Pure-Python binding for D-Bus <https://www.freedesktop.org/wiki/Software/dbus/>,
built around libdbus <https://dbus.freedesktop.org/doc/api/html/index.html>.

This Python binding supports hooking into event loops via Python’s standard
asyncio module.
"""
#+
# Copyright 2017 Lawrence D'Oliveiro <ldo@geek-central.gen.nz>.
# Licensed under the GNU Lesser General Public License v2.1 or later.
#-

import array
import types
import ctypes as ct
from weakref import \
    ref as weak_ref, \
    WeakValueDictionary
import atexit
import asyncio

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

    # from dbus-protocol.h:

    # Message byte order
    LITTLE_ENDIAN = 'l'
    BIG_ENDIAN = 'B'

    # Protocol version.
    MAJOR_PROTOCOL_VERSION = 1

    # Type code that is never equal to a legitimate type code
    TYPE_INVALID = 0

    # Primitive types
    TYPE_BYTE = ord('y') # 8-bit unsigned integer
    TYPE_BOOLEAN = ord('b') # boolean
    TYPE_INT16 = ord('n') # 16-bit signed integer
    TYPE_UINT16 = ord('q') # 16-bit unsigned integer
    TYPE_INT32 = ord('i') # 32-bit signed integer
    TYPE_UINT32 = ord('u') # 32-bit unsigned integer
    TYPE_INT64 = ord('x') # 64-bit signed integer
    TYPE_UINT64 = ord('t') # 64-bit unsigned integer
    TYPE_DOUBLE = ord('d') # 8-byte double in IEEE 754 format
    TYPE_STRING = ord('s') # UTF-8 encoded, nul-terminated Unicode string
    TYPE_OBJECT_PATH = ord('o') # D-Bus object path
    TYPE_SIGNATURE = ord('g') # D-Bus type signature
    TYPE_UNIX_FD = ord('h') # unix file descriptor

    basic_to_ctypes = \
        { # ctypes objects suitable for holding values of D-Bus types
            TYPE_BYTE : ct.c_ubyte,
            TYPE_BOOLEAN : ct.c_ubyte,
            TYPE_INT16 : ct.c_short,
            TYPE_UINT16 : ct.c_ushort,
            TYPE_INT32 : ct.c_int,
            TYPE_UINT32 : ct.c_uint,
            TYPE_INT64 : ct.c_long,
            TYPE_UINT64 : ct.c_ulong,
            TYPE_DOUBLE : ct.c_double,
            TYPE_STRING : ct.c_char_p,
            TYPE_OBJECT_PATH : ct.c_char_p,
            TYPE_SIGNATURE : ct.c_char_p,
            TYPE_UNIX_FD : ct.c_int,
        }

    def int_subtype(i, bits, signed) :
        "returns integer i after checking that it fits in the given number of bits."
        if signed :
            lo = - 1 << bits - 1
            hi = (1 << bits - 1) - 1
        else :
            lo = 0
            hi = (1 << bits) - 1
        #end if
        if i < lo or i > hi :
            raise ValueError \
              (
                "%d not in range of %s %d-bit value" % (i, ("unsigned", "signed")[signed], bits)
              )
        #end if
        return \
            i
    #end int_subtype

    subtype_byte = lambda i : DBUS.int_subtype(i, 8, False)
    subtype_int16 = lambda i : DBUS.int_subtype(i, 16, True)
    subtype_uint16 = lambda i : DBUS.int_subtype(i, 16, False)
    subtype_int32 = lambda i : DBUS.int_subtype(i, 32, True)
    subtype_uint32 = lambda i : DBUS.int_subtype(i, 32, False)
    subtype_int64 = lambda i : DBUS.int_subtype(i, 64, True)
    subtype_uint64 = lambda i : DBUS.int_subtype(i, 64, False)

    int_convert = \
        { # range checks for the various D-Bus integer types
            TYPE_BYTE : subtype_byte,
            TYPE_INT16 : subtype_int16,
            TYPE_UINT16 : subtype_uint16,
            TYPE_INT32 : subtype_int32,
            TYPE_UINT32 : subtype_uint32,
            TYPE_INT64 : subtype_int64,
            TYPE_UINT64 : subtype_uint64,
        }

    # subclasses for distinguishing various special kinds of D-Bus values:

    class ObjectPath(str) :
        "an object path string."

        def __repr__(self) :
            return \
                "%s(%s)" % (self.__class__.__name__, super().__repr__())
        #end __repr__

    #end ObjectPath

    class Signature(str) :
        "a type-signature string."

        def __repr__(self) :
            return \
                "%s(%s)" % (self.__class__.__name__, super().__repr__())
        #end __repr__

    #end Signature

    class UnixFD(int) :
        "a file-descriptor integer."

        def __repr__(self) :
            return \
                "%s(%s)" % (self.__class__.__name__, super().__repr__())
        #end __repr__

    #end UnixFD

    basic_subclasses = \
        {
            TYPE_OBJECT_PATH : ObjectPath,
            TYPE_SIGNATURE : Signature,
            TYPE_UNIX_FD : UnixFD,
        }

    # Compound types
    TYPE_ARRAY = ord('a') # D-Bus array type
    TYPE_VARIANT = ord('v') # D-Bus variant type

    TYPE_STRUCT = ord('r') # a struct; however, type signatures use STRUCT_BEGIN/END_CHAR
    TYPE_DICT_ENTRY = ord('e') # a dict entry; however, type signatures use DICT_ENTRY_BEGIN/END_CHAR
    NUMBER_OF_TYPES = 16 # does not include TYPE_INVALID or STRUCT/DICT_ENTRY_BEGIN/END_CHAR

    # characters other than typecodes that appear in type signatures
    STRUCT_BEGIN_CHAR = ord('(') # start of a struct type in a type signature
    STRUCT_END_CHAR = ord(')') # end of a struct type in a type signature
    DICT_ENTRY_BEGIN_CHAR = ord('{') # start of a dict entry type in a type signature
    DICT_ENTRY_END_CHAR = ord('}') # end of a dict entry type in a type signature

    MAXIMUM_NAME_LENGTH = 255 # max length in bytes of a bus name, interface or member (object paths are unlimited)

    MAXIMUM_SIGNATURE_LENGTH = 255 # fits in a byte

    MAXIMUM_MATCH_RULE_LENGTH = 1024

    MAXIMUM_MATCH_RULE_ARG_NUMBER = 63

    MAXIMUM_ARRAY_LENGTH = 67108864 # 2 * 26
    MAXIMUM_ARRAY_LENGTH_BITS = 26 # to store the max array size

    MAXIMUM_MESSAGE_LENGTH = MAXIMUM_ARRAY_LENGTH * 2
    MAXIMUM_MESSAGE_LENGTH_BITS = 27

    MAXIMUM_MESSAGE_UNIX_FDS = MAXIMUM_MESSAGE_LENGTH // 4 # FDs are at least 32 bits
    MAXIMUM_MESSAGE_UNIX_FDS_BITS = MAXIMUM_MESSAGE_LENGTH_BITS - 2

    MAXIMUM_TYPE_RECURSION_DEPTH = 32

    # Types of message

    MESSAGE_TYPE_INVALID = 0 # never a valid message type
    MESSAGE_TYPE_METHOD_CALL = 1
    MESSAGE_TYPE_METHOD_RETURN = 2
    MESSAGE_TYPE_ERROR = 3
    MESSAGE_TYPE_SIGNAL = 4

    NUM_MESSAGE_TYPES = 5

    # Header flags

    HEADER_FLAG_NO_REPLY_EXPECTED = 0x1
    HEADER_FLAG_NO_AUTO_START = 0x2
    HEADER_FLAG_ALLOW_INTERACTIVE_AUTHORIZATION = 0x4

    # Header fields

    HEADER_FIELD_INVALID = 0
    HEADER_FIELD_PATH = 1
    HEADER_FIELD_INTERFACE = 2
    HEADER_FIELD_MEMBER = 3
    HEADER_FIELD_ERROR_NAME = 4
    HEADER_FIELD_REPLY_SERIAL = 5
    HEADER_FIELD_DESTINATION = 6
    HEADER_FIELD_SENDER = 7
    HEADER_FIELD_SIGNATURE = 8
    HEADER_FIELD_UNIX_FDS = 9

    HEADER_FIELD_LAST = HEADER_FIELD_UNIX_FDS

    HEADER_SIGNATURE = bytes \
      ((
        TYPE_BYTE,
        TYPE_BYTE,
        TYPE_BYTE,
        TYPE_BYTE,
        TYPE_UINT32,
        TYPE_UINT32,
        TYPE_ARRAY,
        STRUCT_BEGIN_CHAR,
        TYPE_BYTE,
        TYPE_VARIANT,
        STRUCT_END_CHAR,
      ))
    MINIMUM_HEADER_SIZE = 16 # smallest header size that can occur (missing required fields, though)

    # Errors
    ERROR_FAILED = "org.freedesktop.DBus.Error.Failed" # generic error
    ERROR_NO_MEMORY = "org.freedesktop.DBus.Error.NoMemory"
    ERROR_SERVICE_UNKNOWN = "org.freedesktop.DBus.Error.ServiceUnknown"
    ERROR_NAME_HAS_NO_OWNER = "org.freedesktop.DBus.Error.NameHasNoOwner"
    ERROR_NO_REPLY = "org.freedesktop.DBus.Error.NoReply"
    ERROR_IO_ERROR = "org.freedesktop.DBus.Error.IOError"
    ERROR_BAD_ADDRESS = "org.freedesktop.DBus.Error.BadAddress"
    ERROR_NOT_SUPPORTED = "org.freedesktop.DBus.Error.NotSupported"
    ERROR_LIMITS_EXCEEDED = "org.freedesktop.DBus.Error.LimitsExceeded"
    ERROR_ACCESS_DENIED = "org.freedesktop.DBus.Error.AccessDenied"
    ERROR_AUTH_FAILED = "org.freedesktop.DBus.Error.AuthFailed"
    ERROR_NO_SERVER = "org.freedesktop.DBus.Error.NoServer"
    ERROR_TIMEOUT = "org.freedesktop.DBus.Error.Timeout"
    ERROR_NO_NETWORK = "org.freedesktop.DBus.Error.NoNetwork"
    ERROR_ADDRESS_IN_USE = "org.freedesktop.DBus.Error.AddressInUse"
    ERROR_DISCONNECTED = "org.freedesktop.DBus.Error.Disconnected"
    ERROR_INVALID_ARGS = "org.freedesktop.DBus.Error.InvalidArgs"
    ERROR_FILE_NOT_FOUND = "org.freedesktop.DBus.Error.FileNotFound"
    ERROR_FILE_EXISTS = "org.freedesktop.DBus.Error.FileExists"
    ERROR_UNKNOWN_METHOD = "org.freedesktop.DBus.Error.UnknownMethod"
    ERROR_UNKNOWN_OBJECT = "org.freedesktop.DBus.Error.UnknownObject"
    ERROR_UNKNOWN_INTERFACE = "org.freedesktop.DBus.Error.UnknownInterface"
    ERROR_UNKNOWN_PROPERTY = "org.freedesktop.DBus.Error.UnknownProperty"
    ERROR_PROPERTY_READ_ONLY = "org.freedesktop.DBus.Error.PropertyReadOnly"
    ERROR_TIMED_OUT = "org.freedesktop.DBus.Error.TimedOut"
    ERROR_MATCH_RULE_NOT_FOUND = "org.freedesktop.DBus.Error.MatchRuleNotFound"
    ERROR_MATCH_RULE_INVALID = "org.freedesktop.DBus.Error.MatchRuleInvalid"
    ERROR_SPAWN_EXEC_FAILED = "org.freedesktop.DBus.Error.Spawn.ExecFailed"
    ERROR_SPAWN_FORK_FAILED = "org.freedesktop.DBus.Error.Spawn.ForkFailed"
    ERROR_SPAWN_CHILD_EXITED = "org.freedesktop.DBus.Error.Spawn.ChildExited"
    ERROR_SPAWN_CHILD_SIGNALED = "org.freedesktop.DBus.Error.Spawn.ChildSignaled"
    ERROR_SPAWN_FAILED = "org.freedesktop.DBus.Error.Spawn.Failed"
    ERROR_SPAWN_SETUP_FAILED = "org.freedesktop.DBus.Error.Spawn.FailedToSetup"
    ERROR_SPAWN_CONFIG_INVALID = "org.freedesktop.DBus.Error.Spawn.ConfigInvalid"
    ERROR_SPAWN_SERVICE_INVALID = "org.freedesktop.DBus.Error.Spawn.ServiceNotValid"
    ERROR_SPAWN_SERVICE_NOT_FOUND = "org.freedesktop.DBus.Error.Spawn.ServiceNotFound"
    ERROR_SPAWN_PERMISSIONS_INVALID = "org.freedesktop.DBus.Error.Spawn.PermissionsInvalid"
    ERROR_SPAWN_FILE_INVALID = "org.freedesktop.DBus.Error.Spawn.FileInvalid"
    ERROR_SPAWN_NO_MEMORY = "org.freedesktop.DBus.Error.Spawn.NoMemory"
    ERROR_UNIX_PROCESS_ID_UNKNOWN = "org.freedesktop.DBus.Error.UnixProcessIdUnknown"
    ERROR_INVALID_SIGNATURE = "org.freedesktop.DBus.Error.InvalidSignature"
    ERROR_INVALID_FILE_CONTENT = "org.freedesktop.DBus.Error.InvalidFileContent"
    ERROR_SELINUX_SECURITY_CONTEXT_UNKNOWN = "org.freedesktop.DBus.Error.SELinuxSecurityContextUnknown"
    ERROR_ADT_AUDIT_DATA_UNKNOWN = "org.freedesktop.DBus.Error.AdtAuditDataUnknown"
    ERROR_OBJECT_PATH_IN_USE = "org.freedesktop.DBus.Error.ObjectPathInUse"
    ERROR_INCONSISTENT_MESSAGE = "org.freedesktop.DBus.Error.InconsistentMessage"
    ERROR_INTERACTIVE_AUTHORIZATION_REQUIRED = "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired"

    # XML introspection format
    INTROSPECT_1_0_XML_NAMESPACE = "http://www.freedesktop.org/standards/dbus"
    INTROSPECT_1_0_XML_PUBLIC_IDENTIFIER = "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
    INTROSPECT_1_0_XML_SYSTEM_IDENTIFIER = "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd"
    INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE = \
        (
            "<!DOCTYPE node PUBLIC \""
        +
            INTROSPECT_1_0_XML_PUBLIC_IDENTIFIER
        +
            "\"\n\"" + INTROSPECT_1_0_XML_SYSTEM_IDENTIFIER
        +
            "\">\n"
        )

    # from dbus-shared.h:

    # well-known bus types
    BusType = ct.c_uint
    BUS_SESSION = 0
    BUS_SYSTEM = 1
    BUS_STARTER = 2

    # results that a message handler can return
    BusHandlerResult = ct.c_uint
    HANDLER_RESULT_HANDLED = 0 # no need to try more handlers
    HANDLER_RESULT_NOT_YET_HANDLED = 1 # see if other handlers want it
    HANDLER_RESULT_NEED_MEMORY = 2 # try again later with more memory

    # Bus names
    SERVICE_DBUS = "org.freedesktop.DBus" # used to talk to the bus itself

    # Paths
    PATH_DBUS = "/org/freedesktop/DBus" # object path used to talk to the bus itself
    PATH_LOCAL = "/org/freedesktop/DBus/Local" # path used in local/in-process-generated messages

    # Interfaces
    INTERFACE_DBUS = "org.freedesktop.DBus" # interface exported by the object with SERVICE_DBUS and PATH_DBUS
    INTERFACE_MONITORING = "org.freedesktop.DBus.Monitoring" # monitoring interface exported by the dbus-daemon
    INTERFACE_VERBOSE = "org.freedesktop.DBus.Verbose" # verbose interface exported by the dbus-daemon
    INTERFACE_INTROSPECTABLE = "org.freedesktop.DBus.Introspectable" # interface supported by introspectable objects
    INTERFACE_PROPERTIES = "org.freedesktop.DBus.Properties" # interface supported by objects with properties
    INTERFACE_PEER = "org.freedesktop.DBus.Peer" # interface supported by most dbus peers
    INTERFACE_LOCAL = "org.freedesktop.DBus.Local" # methods can only be invoked locally

    # Owner flags for request_name
    NAME_FLAG_ALLOW_REPLACEMENT = 0x1
    NAME_FLAG_REPLACE_EXISTING = 0x2
    NAME_FLAG_DO_NOT_QUEUE = 0x4

    # Replies to request for a name
    REQUEST_NAME_REPLY_PRIMARY_OWNER = 1
    REQUEST_NAME_REPLY_IN_QUEUE = 2
    REQUEST_NAME_REPLY_EXISTS = 3
    REQUEST_NAME_REPLY_ALREADY_OWNER = 4

    # Replies to releasing a name
    RELEASE_NAME_REPLY_RELEASED = 1
    RELEASE_NAME_REPLY_NON_EXISTENT = 2
    RELEASE_NAME_REPLY_NOT_OWNER = 3

    # Replies to service starts
    START_REPLY_SUCCESS = 1
    START_REPLY_ALREADY_RUNNING = 2

    # from dbus-types.h:

    bool_t = ct.c_uint

    # from dbus-memory.h:

    FreeFunction = ct.CFUNCTYPE(None, ct.c_void_p)

    # from dbus-connection.h:

    HandlerResult = ct.c_uint

    class Error(ct.Structure) :
        _fields_ = \
            [
                ("name", ct.c_char_p),
                ("message", ct.c_char_p),
                ("padding", 2 * ct.c_void_p),
            ]
    #end Error
    ErrorPtr = ct.POINTER(Error)

    WatchFlags = ct.c_uint
    WATCH_READABLE = 1 << 0
    WATCH_WRITABLE = 1 << 1
    WATCH_ERROR = 1 << 2
    WATCH_HANGUP = 1 << 3

    DispatchStatus = ct.c_uint
    DISPATCH_DATA_REMAINS = 0 # more data available
    DISPATCH_COMPLETE = 1 # all available data has been processed
    DISPATCH_NEED_MEMORY = 2 # not enough memory to continue

    AddWatchFunction = ct.CFUNCTYPE(bool_t, ct.c_void_p, ct.c_void_p)
    WatchToggledFunction = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_void_p)
    RemoveWatchFunction = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_void_p)

    AddTimeoutFunction = ct.CFUNCTYPE(bool_t, ct.c_void_p, ct.c_void_p)
    TimeoutToggledFunction = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_void_p)
    RemoveTimeoutFunction = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_void_p)

    DispatchStatusFunction = ct.CFUNCTYPE(None, ct.c_void_p, ct.POINTER(DispatchStatus), ct.c_void_p)
    WakeupMainFunction = ct.CFUNCTYPE(None, ct.c_void_p)

    AllowUnixUserFunction = ct.CFUNCTYPE(bool_t, ct.c_void_p, ct.c_void_p, ct.c_void_p)
    AllowWindowsUserFunction = ct.CFUNCTYPE(bool_t, ct.c_void_p, ct.c_void_p, ct.c_void_p)

    PendingCallNotifyFunction = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_void_p)

    HandleMessageFunction = ct.CFUNCTYPE(HandlerResult, ct.c_void_p, ct.c_void_p, ct.c_void_p)

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

    # from dbus-pending-call.h:
    TIMEOUT_INFINITE = 0x7fffffff
    TIMEOUT_USE_DEFAULT = -1

    # from dbus-message.h:
    class MessageIter(ct.Structure) :
        "contains no public fields."
        _fields_ = \
            [
                ("dummy1", ct.c_void_p),
                ("dummy2", ct.c_void_p),
                ("dummy3", ct.c_uint),
                ("dummy4", ct.c_int),
                ("dummy5", ct.c_int),
                ("dummy6", ct.c_int),
                ("dummy7", ct.c_int),
                ("dummy8", ct.c_int),
                ("dummy9", ct.c_int),
                ("dummy10", ct.c_int),
                ("dummy11", ct.c_int),
                ("pad1", ct.c_int),
                ("pad2", ct.c_void_p),
                ("pad3", ct.c_void_p),
            ]
    #end MessageIter
    MessageIterPtr = ct.POINTER(MessageIter)

    # from dbus-server.h:
    NewConnectionFunction = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_void_p, ct.c_void_p)

    # from dbus-signature.h:
    class SignatureIter(ct.Structure) :
        "contains no public fields."
        _fields_ = \
            [
                ("dummy1", ct.c_void_p),
                ("dummy2", ct.c_void_p),
                ("dummy8", ct.c_uint),
                ("dummy12", ct.c_int),
                ("dummy17", ct.c_int),
            ]
    #end SignatureIter
    SignatureIterPtr = ct.POINTER(SignatureIter)

#end DBUS

#+
# Library prototypes
#-

# from dbus-connection.h:
dbus.dbus_connection_open.restype = ct.c_void_p
dbus.dbus_connection_open.argtypes = (ct.c_char_p, DBUS.ErrorPtr)
dbus.dbus_connection_open_private.restype = ct.c_void_p
dbus.dbus_connection_open_private.argtypes = (ct.c_char_p, DBUS.ErrorPtr)
dbus.dbus_connection_ref.restype = ct.c_void_p
dbus.dbus_connection_ref.argtypes = (ct.c_void_p,)
dbus.dbus_connection_unref.restype = None
dbus.dbus_connection_unref.argtypes = (ct.c_void_p,)
dbus.dbus_connection_close.restype = None
dbus.dbus_connection_close.argtypes = (ct.c_void_p,)
dbus.dbus_connection_get_is_connected.restype = DBUS.bool_t
dbus.dbus_connection_get_is_connected.argtypes = (ct.c_void_p,)
dbus.dbus_connection_get_is_authenticated.restype = DBUS.bool_t
dbus.dbus_connection_get_is_authenticated.argtypes = (ct.c_void_p,)
dbus.dbus_connection_get_is_anonymous.restype = DBUS.bool_t
dbus.dbus_connection_get_is_anonymous.argtypes = (ct.c_void_p,)
dbus.dbus_connection_get_server_id.restype = ct.c_void_p
dbus.dbus_connection_get_server_id.argtypes = (ct.c_void_p,)
dbus.dbus_connection_can_send_type.restype = DBUS.bool_t
dbus.dbus_connection_can_send_type.argtypes = (ct.c_void_p, ct.c_int)
dbus.dbus_connection_set_exit_on_disconnect.restype = None
dbus.dbus_connection_set_exit_on_disconnect.argtypes = (ct.c_void_p, DBUS.bool_t)
dbus.dbus_connection_preallocate_send.restype = ct.c_void_p
dbus.dbus_connection_preallocate_send.argtypes = (ct.c_void_p,)
dbus.dbus_connection_free_preallocated_send.restype = None
dbus.dbus_connection_free_preallocated_send.argtypes = (ct.c_void_p, ct.c_void_p)
dbus.dbus_connection_send_preallocated.restype = None
dbus.dbus_connection_send_preallocated.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.POINTER(ct.c_uint))
dbus.dbus_connection_has_messages_to_send.restype = DBUS.bool_t
dbus.dbus_connection_has_messages_to_send.argtypes = (ct.c_void_p,)
dbus.dbus_connection_send.restype = DBUS.bool_t
dbus.dbus_connection_send.argtypes = (ct.c_void_p, ct.c_void_p, ct.POINTER(ct.c_uint))
dbus.dbus_connection_send_with_reply.restype = DBUS.bool_t
dbus.dbus_connection_send_with_reply.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_int)
dbus.dbus_connection_send_with_reply_and_block.restype = ct.c_void_p
dbus.dbus_connection_send_with_reply_and_block.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_int, DBUS.ErrorPtr)
dbus.dbus_connection_flush.restype = None
dbus.dbus_connection_flush.argtypes = (ct.c_void_p,)
dbus.dbus_connection_read_write_dispatch.restype = DBUS.bool_t
dbus.dbus_connection_read_write_dispatch.argtypes = (ct.c_void_p, ct.c_int)
dbus.dbus_connection_read_write.restype = DBUS.bool_t
dbus.dbus_connection_read_write.argtypes = (ct.c_void_p, ct.c_int)
dbus.dbus_connection_borrow_message.restype = ct.c_void_p
dbus.dbus_connection_borrow_message.argtypes = (ct.c_void_p,)
dbus.dbus_connection_return_message.restype = None
dbus.dbus_connection_return_message.argtypes = (ct.c_void_p, ct.c_void_p)
dbus.dbus_connection_steal_borrowed_message.restype = None
dbus.dbus_connection_steal_borrowed_message.argtypes = (ct.c_void_p, ct.c_void_p)
dbus.dbus_connection_pop_message.restype = ct.c_void_p
dbus.dbus_connection_pop_message.argtypes = (ct.c_void_p,)
dbus.dbus_connection_get_dispatch_status.restype = ct.c_uint
dbus.dbus_connection_get_dispatch_status.argtypes = (ct.c_void_p,)
dbus.dbus_connection_dispatch.restype = ct.c_uint
dbus.dbus_connection_dispatch.argtypes = (ct.c_void_p,)
dbus.dbus_connection_set_watch_functions.restype = DBUS.bool_t
dbus.dbus_connection_set_watch_functions.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p)
dbus.dbus_connection_set_timeout_functions.restype = DBUS.bool_t
dbus.dbus_connection_set_timeout_functions.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p)
dbus.dbus_connection_set_wakeup_main_function.restype = None
dbus.dbus_connection_set_wakeup_main_function.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p)
dbus.dbus_connection_set_dispatch_status_function.restype = None
dbus.dbus_connection_set_dispatch_status_function.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p)
dbus.dbus_connection_get_unix_user.restype = DBUS.bool_t
dbus.dbus_connection_get_unix_user.argtypes = (ct.c_void_p, ct.POINTER(ct.c_ulong))
dbus.dbus_connection_get_unix_process_id.restype = DBUS.bool_t
dbus.dbus_connection_get_unix_process_id.argtypes = (ct.c_void_p, ct.POINTER(ct.c_ulong))
dbus.dbus_connection_get_adt_audit_session_data.restype = DBUS.bool_t
dbus.dbus_connection_get_adt_audit_session_data.argtypes = (ct.c_void_p, ct.c_void_p, ct.POINTER(ct.c_uint))
dbus.dbus_connection_set_unix_user_function.restype = None
dbus.dbus_connection_set_unix_user_function.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p)
dbus.dbus_connection_get_windows_user.restype = DBUS.bool_t
dbus.dbus_connection_get_windows_user.argtypes = (ct.c_void_p, ct.c_void_p)
dbus.dbus_connection_set_windows_user_function.restype = None
dbus.dbus_connection_set_windows_user_function.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p)
dbus.dbus_connection_set_allow_anonymous.restype = None
dbus.dbus_connection_set_allow_anonymous.argtypes = (ct.c_void_p, DBUS.bool_t)
dbus.dbus_connection_set_route_peer_messages.restype = None
dbus.dbus_connection_set_route_peer_messages.argtypes = (ct.c_void_p, DBUS.bool_t)

dbus.dbus_connection_add_filter.restype = DBUS.bool_t
dbus.dbus_connection_add_filter.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p)
dbus.dbus_connection_remove_filter.restype = None
dbus.dbus_connection_add_filter.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_void_p)

dbus.dbus_connection_allocate_data_slot.restype = DBUS.bool_t
dbus.dbus_connection_allocate_data_slot.argtypes = (ct.POINTER(ct.c_uint),)
dbus.dbus_connection_free_data_slot.restype = None
dbus.dbus_connection_free_data_slot.argtypes = (ct.c_uint,)
dbus.dbus_connection_set_data.restype = DBUS.bool_t
dbus.dbus_connection_set_data.argtypes = (ct.c_void_p, ct.c_uint, ct.c_void_p, ct.c_void_p)
dbus.dbus_connection_get_data.restype = ct.c_void_p
dbus.dbus_connection_get_data.argtypes = (ct.c_void_p, ct.c_uint)
dbus.dbus_connection_set_change_sigpipe.restype = None
dbus.dbus_connection_set_change_sigpipe.argtypes = (DBUS.bool_t,)
dbus.dbus_connection_set_max_message_size.restype = None
dbus.dbus_connection_set_max_message_size.argtypes = (ct.c_void_p, ct.c_long)
dbus.dbus_connection_get_max_message_size.restype = ct.c_long
dbus.dbus_connection_get_max_message_size.argtypes = (ct.c_void_p,)
dbus.dbus_connection_set_max_received_size.restype = None
dbus.dbus_connection_set_max_received_size.argtypes = (ct.c_void_p, ct.c_long)
dbus.dbus_connection_get_max_received_size.restype = ct.c_long
dbus.dbus_connection_get_max_received_size.argtypes = (ct.c_void_p,)
dbus.dbus_connection_set_max_message_unix_fds.restype = None
dbus.dbus_connection_set_max_message_unix_fds.argtypes = (ct.c_void_p, ct.c_long)
dbus.dbus_connection_get_max_message_unix_fds.restype = ct.c_long
dbus.dbus_connection_get_max_message_unix_fds.argtypes = (ct.c_void_p,)
dbus.dbus_connection_set_max_received_unix_fds.restype = None
dbus.dbus_connection_set_max_received_unix_fds.argtypes = (ct.c_void_p, ct.c_long)
dbus.dbus_connection_get_max_received_unix_fds.restype = ct.c_long
dbus.dbus_connection_get_max_received_unix_fds.argtypes = (ct.c_void_p,)

dbus.dbus_connection_get_outgoing_size.restype = ct.c_long
dbus.dbus_connection_get_outgoing_size.argtypes = (ct.c_void_p,)
dbus.dbus_connection_get_outgoing_unix_fds.restype = ct.c_long
dbus.dbus_connection_get_outgoing_unix_fds.argtypes = (ct.c_void_p,)

dbus.dbus_connection_register_object_path.restype = DBUS.bool_t
dbus.dbus_connection_register_object_path.argtypes = (ct.c_void_p, ct.c_char_p, DBUS.ObjectPathVTablePtr, ct.c_void_p)
dbus.dbus_connection_try_register_object_path.restype = DBUS.bool_t
dbus.dbus_connection_try_register_object_path.argtypes = (ct.c_void_p, ct.c_char_p, DBUS.ObjectPathVTablePtr, ct.c_void_p, DBUS.ErrorPtr)
dbus.dbus_connection_register_fallback.restype = DBUS.bool_t
dbus.dbus_connection_register_fallback.argtypes = (ct.c_void_p, ct.c_char_p, DBUS.ObjectPathVTablePtr, ct.c_void_p)
dbus.dbus_connection_try_register_fallback.restype = DBUS.bool_t
dbus.dbus_connection_try_register_fallback.argtypes = (ct.c_void_p, ct.c_char_p, DBUS.ObjectPathVTablePtr, ct.c_void_p, DBUS.ErrorPtr)
dbus.dbus_connection_get_object_path_data.restype = DBUS.bool_t
dbus.dbus_connection_get_object_path_data.argtypes = (ct.c_void_p, ct.c_char_p, ct.c_void_p)
dbus.dbus_connection_list_registered.restype = DBUS.bool_t
dbus.dbus_connection_list_registered.argtypes = (ct.c_void_p, ct.c_char_p, ct.c_void_p)
dbus.dbus_connection_get_unix_fd.restype = DBUS.bool_t
dbus.dbus_connection_get_unix_fd.argtypes = (ct.c_void_p, ct.POINTER(ct.c_int))
dbus.dbus_connection_get_socket.restype = DBUS.bool_t
dbus.dbus_connection_get_socket.argtypes = (ct.c_void_p, ct.POINTER(ct.c_int))
dbus.dbus_connection_unregister_object_path.restype = DBUS.bool_t
dbus.dbus_connection_unregister_object_path.argtypes = (ct.c_void_p, ct.c_char_p)

dbus.dbus_watch_get_unix_fd.restype = ct.c_int
dbus.dbus_watch_get_unix_fd.argtypes = (ct.c_void_p,)
dbus.dbus_watch_get_socket.restype = ct.c_int
dbus.dbus_watch_get_socket.argtypes = (ct.c_void_p,)
dbus.dbus_watch_get_flags.restype = ct.c_uint
dbus.dbus_watch_get_flags.argtypes = (ct.c_void_p,)
dbus.dbus_watch_get_data.restype = ct.c_void_p
dbus.dbus_watch_get_data.argtypes = (ct.c_void_p,)
dbus.dbus_watch_set_data.restype = None
dbus.dbus_watch_set_data.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_void_p)
dbus.dbus_watch_handle.restype = DBUS.bool_t
dbus.dbus_watch_handle.argtypes = (ct.c_void_p, ct.c_uint)
dbus.dbus_watch_get_enabled.restype = DBUS.bool_t
dbus.dbus_watch_get_enabled.argtypes = (ct.c_void_p,)

dbus.dbus_timeout_get_interval.restype = ct.c_int
dbus.dbus_timeout_get_interval.argtypes = (ct.c_void_p,)
dbus.dbus_timeout_get_data.restype = ct.c_void_p
dbus.dbus_timeout_get_data.argtypes = (ct.c_void_p,)
dbus.dbus_timeout_set_data.restype = None
dbus.dbus_timeout_set_data.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_void_p)
dbus.dbus_timeout_handle.restype = DBUS.bool_t
dbus.dbus_timeout_handle.argtypes = (ct.c_void_p,)
dbus.dbus_timeout_get_enabled.restype = DBUS.bool_t
dbus.dbus_timeout_get_enabled.argtypes = (ct.c_void_p,)

# from dbus-bus.h:
dbus.dbus_bus_get.restype = ct.c_void_p
dbus.dbus_bus_get.argtypes = (ct.c_uint, DBUS.ErrorPtr)
dbus.dbus_bus_get_private.restype = ct.c_void_p
dbus.dbus_bus_get_private.argtypes = (ct.c_uint, DBUS.ErrorPtr)
dbus.dbus_bus_register.restype = DBUS.bool_t
dbus.dbus_bus_register.argtypes = (ct.c_void_p, DBUS.ErrorPtr)
dbus.dbus_bus_set_unique_name.restype = DBUS.bool_t
dbus.dbus_bus_set_unique_name.argtypes = (ct.c_void_p, ct.c_char_p)
dbus.dbus_bus_get_unique_name.restype = ct.c_char_p
dbus.dbus_bus_get_unique_name.argtypes = (ct.c_void_p,)
dbus.dbus_bus_get_unix_user.restype = ct.c_ulong
dbus.dbus_bus_get_unix_user.argtypes = (ct.c_void_p, ct.c_char_p, DBUS.ErrorPtr)
dbus.dbus_bus_get_id.restype = ct.c_void_p
dbus.dbus_bus_get_id.argtypes = (ct.c_void_p, DBUS.ErrorPtr)
dbus.dbus_bus_request_name.restype = ct.c_int
dbus.dbus_bus_request_name.argtypes = (ct.c_void_p, ct.c_char_p, ct.c_uint, DBUS.ErrorPtr)
dbus.dbus_bus_release_name.restype = ct.c_int
dbus.dbus_bus_release_name.argtypes = (ct.c_void_p, ct.c_char_p, DBUS.ErrorPtr)
dbus.dbus_bus_name_has_owner.restype = DBUS.bool_t
dbus.dbus_bus_name_has_owner.argtypes = (ct.c_void_p, ct.c_char_p, DBUS.ErrorPtr)
dbus.dbus_bus_start_service_by_name.restype = DBUS.bool_t
dbus.dbus_bus_start_service_by_name.argtypes = (ct.c_void_p, ct.c_char_p, ct.c_uint, ct.POINTER(ct.c_uint), DBUS.ErrorPtr)
dbus.dbus_bus_add_match.restype = None
dbus.dbus_bus_add_match.argtypes = (ct.c_void_p, ct.c_char_p, DBUS.ErrorPtr)
dbus.dbus_bus_remove_match.restype = None
dbus.dbus_bus_remove_match.argtypes = (ct.c_void_p, ct.c_char_p, DBUS.ErrorPtr)

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

# from dbus-pending-call.h:
dbus.dbus_pending_call_ref.restype = ct.c_void_p
dbus.dbus_pending_call_ref.argtypes = (ct.c_void_p,)
dbus.dbus_pending_call_unref.restype = None
dbus.dbus_pending_call_unref.argtypes = (ct.c_void_p,)
dbus.dbus_pending_call_set_notify.restype = DBUS.bool_t
dbus.dbus_pending_call_set_notify.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p)
dbus.dbus_pending_call_cancel.restype = None
dbus.dbus_pending_call_cancel.argtypes = (ct.c_void_p,)
dbus.dbus_pending_call_get_completed.restype = DBUS.bool_t
dbus.dbus_pending_call_get_completed.argtypes = (ct.c_void_p,)
dbus.dbus_pending_call_steal_reply.restype = ct.c_void_p
dbus.dbus_pending_call_steal_reply.argtypes = (ct.c_void_p,)
dbus.dbus_pending_call_block.restype = None
dbus.dbus_pending_call_block.argtypes = (ct.c_void_p,)
dbus.dbus_pending_call_allocate_data_slot.restype = DBUS.bool_t
dbus.dbus_pending_call_allocate_data_slot.argtypes = (ct.POINTER(ct.c_int),)
dbus.dbus_pending_call_free_data_slot.restype = None
dbus.dbus_pending_call_free_data_slot.argtypes = (ct.c_int,)
dbus.dbus_pending_call_set_data.restype = DBUS.bool_t
dbus.dbus_pending_call_set_data.argtypes = (ct.c_void_p, ct.c_int, ct.c_void_p, ct.c_void_p)
dbus.dbus_pending_call_get_data.restype = ct.c_void_p
dbus.dbus_pending_call_get_data.argtypes = (ct.c_void_p, ct.c_int)

# from dbus-message.h:
dbus.dbus_message_new.restype = ct.c_void_p
dbus.dbus_message_new.argtypes = (ct.c_int,)
dbus.dbus_message_new_method_call.restype = ct.c_void_p
dbus.dbus_message_new_method_call.argtypes = (ct.c_char_p, ct.c_char_p, ct.c_char_p, ct.c_char_p)
dbus.dbus_message_new_method_return.restype = ct.c_void_p
dbus.dbus_message_new_method_return.argtypes = (ct.c_void_p,)
dbus.dbus_message_new_signal.restype = ct.c_void_p
dbus.dbus_message_new_signal.argtypes = (ct.c_char_p, ct.c_char_p, ct.c_char_p)
dbus.dbus_message_new_error.restype = ct.c_void_p
dbus.dbus_message_new_error.argtypes = (ct.c_void_p, ct.c_char_p, ct.c_char_p)
dbus.dbus_message_new_error_printf.restype = ct.c_void_p
dbus.dbus_message_new_error_printf.argtypes = (ct.c_void_p, ct.c_char_p, ct.c_char_p, ct.c_char_p)
  # note I can’t handle varargs
dbus.dbus_message_copy.restype = ct.c_void_p
dbus.dbus_message_copy.argtypes = (ct.c_void_p,)
dbus.dbus_message_ref.restype = ct.c_void_p
dbus.dbus_message_ref.argtypes = (ct.c_void_p,)
dbus.dbus_message_unref.restype = None
dbus.dbus_message_unref.argtypes = (ct.c_void_p,)
dbus.dbus_message_get_type.restype = ct.c_int
dbus.dbus_message_get_type.argtypes = (ct.c_void_p,)
dbus.dbus_message_set_path.restype = DBUS.bool_t
dbus.dbus_message_set_path.argtypes = (ct.c_void_p, ct.c_char_p)
dbus.dbus_message_get_path.restype = ct.c_char_p
dbus.dbus_message_get_path.argtypes = (ct.c_void_p,)
dbus.dbus_message_has_path.restype = DBUS.bool_t
dbus.dbus_message_has_path.argtypes = (ct.c_void_p, ct.c_char_p)
dbus.dbus_message_set_interface.restype = DBUS.bool_t
dbus.dbus_message_set_interface.argtypes = (ct.c_void_p, ct.c_char_p)
dbus.dbus_message_get_interface.restype = ct.c_char_p
dbus.dbus_message_get_interface.argtypes = (ct.c_void_p,)
dbus.dbus_message_has_interface.restype = DBUS.bool_t
dbus.dbus_message_has_interface.argtypes = (ct.c_void_p, ct.c_char_p)
dbus.dbus_message_set_member.restype = DBUS.bool_t
dbus.dbus_message_set_member.argtypes = (ct.c_void_p, ct.c_char_p)
dbus.dbus_message_get_member.restype = ct.c_char_p
dbus.dbus_message_get_member.argtypes = (ct.c_void_p,)
dbus.dbus_message_has_member.restype = DBUS.bool_t
dbus.dbus_message_has_member.argtypes = (ct.c_void_p, ct.c_char_p)
dbus.dbus_message_set_error_name.restype = DBUS.bool_t
dbus.dbus_message_set_error_name.argtypes = (ct.c_void_p, ct.c_char_p)
dbus.dbus_message_get_error_name.restype = ct.c_char_p
dbus.dbus_message_get_error_name.argtypes = (ct.c_void_p,)
dbus.dbus_message_set_destination.restype = DBUS.bool_t
dbus.dbus_message_set_destination.argtypes = (ct.c_void_p, ct.c_char_p)
dbus.dbus_message_get_destination.restype = ct.c_char_p
dbus.dbus_message_get_destination.argtypes = (ct.c_void_p,)
dbus.dbus_message_set_sender.restype = DBUS.bool_t
dbus.dbus_message_set_sender.argtypes = (ct.c_void_p, ct.c_char_p)
dbus.dbus_message_get_sender.restype = ct.c_char_p
dbus.dbus_message_get_sender.argtypes = (ct.c_void_p,)
dbus.dbus_message_get_signature.restype = ct.c_char_p
dbus.dbus_message_get_signature.argtypes = (ct.c_void_p,)
dbus.dbus_message_set_no_reply.restype = None
dbus.dbus_message_set_no_reply.argtypes = (ct.c_void_p, DBUS.bool_t)
dbus.dbus_message_get_no_reply.restype = DBUS.bool_t
dbus.dbus_message_get_no_reply.argtypes = (ct.c_void_p,)
dbus.dbus_message_is_method_call.restype = DBUS.bool_t
dbus.dbus_message_is_method_call.argtypes = (ct.c_void_p, ct.c_char_p, ct.c_char_p)
dbus.dbus_message_is_signal.restype = DBUS.bool_t
dbus.dbus_message_is_signal.argtypes = (ct.c_void_p, ct.c_char_p, ct.c_char_p)
dbus.dbus_message_is_error.restype = DBUS.bool_t
dbus.dbus_message_is_error.argtypes = (ct.c_void_p, ct.c_char_p)
dbus.dbus_message_has_destination.restype = DBUS.bool_t
dbus.dbus_message_has_destination.argtypes = (ct.c_void_p, ct.c_char_p)
dbus.dbus_message_has_sender.restype = DBUS.bool_t
dbus.dbus_message_has_sender.argtypes = (ct.c_void_p, ct.c_char_p)
dbus.dbus_message_has_signature.restype = DBUS.bool_t
dbus.dbus_message_has_signature.argtypes = (ct.c_void_p, ct.c_char_p)
dbus.dbus_message_get_serial.restype = ct.c_uint
dbus.dbus_message_get_serial.argtypes = (ct.c_void_p,)
dbus.dbus_message_set_serial.restype = None
dbus.dbus_message_set_serial.argtypes = (ct.c_void_p, ct.c_uint)
dbus.dbus_message_set_reply_serial.restype = DBUS.bool_t
dbus.dbus_message_set_reply_serial.argtypes = (ct.c_void_p, ct.c_uint)
dbus.dbus_message_get_reply_serial.restype = ct.c_uint
dbus.dbus_message_get_reply_serial.argtypes = (ct.c_void_p,)
dbus.dbus_message_set_auto_start.restype = None
dbus.dbus_message_set_auto_start.argtypes = (ct.c_void_p, DBUS.bool_t)
dbus.dbus_message_get_auto_start.restype = DBUS.bool_t
dbus.dbus_message_get_auto_start.argtypes = (ct.c_void_p,)
dbus.dbus_message_get_path_decomposed.restype = DBUS.bool_t
dbus.dbus_message_get_path_decomposed.argtypes = (ct.c_void_p, ct.c_void_p)
dbus.dbus_message_append_args.restype = DBUS.bool_t
dbus.dbus_message_append_args.argtypes = (ct.c_void_p, ct.c_int, ct.c_void_p, ct.c_int)
  # note I can’t handle varargs
# probably cannot make use of dbus.dbus_message_append_args_valist
dbus.dbus_message_get_args.restype = DBUS.bool_t
dbus.dbus_message_get_args.argtypes = (ct.c_void_p, DBUS.ErrorPtr, ct.c_int, ct.c_void_p, ct.c_int)
  # note I can’t handle varargs
# probably cannot make use of dbus.dbus_message_get_args_valist
dbus.dbus_message_contains_unix_fds.restype = DBUS.bool_t
dbus.dbus_message_contains_unix_fds.argtypes = (ct.c_void_p,)
dbus.dbus_message_iter_init.restype = DBUS.bool_t
dbus.dbus_message_iter_init.argtypes = (ct.c_void_p, DBUS.MessageIterPtr)
dbus.dbus_message_iter_has_next.restype = DBUS.bool_t
dbus.dbus_message_iter_has_next.argtypes = (DBUS.MessageIterPtr,)
dbus.dbus_message_iter_next.restype = DBUS.bool_t
dbus.dbus_message_iter_next.argtypes = (DBUS.MessageIterPtr,)
dbus.dbus_message_iter_get_signature.restype = ct.c_void_p
dbus.dbus_message_iter_next.argtypes = (DBUS.MessageIterPtr,)
dbus.dbus_message_iter_get_signature.restype = ct.c_void_p
dbus.dbus_message_iter_get_signature.argtypes = (DBUS.MessageIterPtr,)
dbus.dbus_message_iter_get_arg_type.restype = ct.c_int
dbus.dbus_message_iter_get_arg_type.argtypes = (DBUS.MessageIterPtr,)
dbus.dbus_message_iter_get_element_type.restype = ct.c_int
dbus.dbus_message_iter_get_element_type.argtypes = (DBUS.MessageIterPtr,)
dbus.dbus_message_iter_recurse.restype = None
dbus.dbus_message_iter_recurse.argtypes = (DBUS.MessageIterPtr, DBUS.MessageIterPtr)
dbus.dbus_message_iter_get_basic.restype = None
dbus.dbus_message_iter_get_basic.argtypes = (DBUS.MessageIterPtr, ct.c_void_p)
dbus.dbus_message_iter_get_element_count.restype = ct.c_int
dbus.dbus_message_iter_get_element_count.argtypes = (DBUS.MessageIterPtr,)
# dbus_message_iter_get_array_len deprecated
dbus.dbus_message_iter_get_fixed_array.restype = None
dbus.dbus_message_iter_get_fixed_array.argtypes = (DBUS.MessageIterPtr, ct.c_void_p, ct.POINTER(ct.c_int))
dbus.dbus_message_iter_init_append.restype = None
dbus.dbus_message_iter_init_append.argtypes = (ct.c_void_p, DBUS.MessageIterPtr)
dbus.dbus_message_iter_append_basic.restype = DBUS.bool_t
dbus.dbus_message_iter_append_basic.argtypes = (DBUS.MessageIterPtr, ct.c_int, ct.c_void_p)
dbus.dbus_message_iter_append_fixed_array.restype = DBUS.bool_t
dbus.dbus_message_iter_append_fixed_array.argtypes = (DBUS.MessageIterPtr, ct.c_int, ct.c_void_p, ct.c_int)
dbus.dbus_message_iter_open_container.restype = DBUS.bool_t
dbus.dbus_message_iter_open_container.argtypes = (DBUS.MessageIterPtr, ct.c_int, ct.c_char_p, DBUS.MessageIterPtr)
dbus.dbus_message_iter_close_container.restype = DBUS.bool_t
dbus.dbus_message_iter_close_container.argtypes = (DBUS.MessageIterPtr, DBUS.MessageIterPtr)
dbus.dbus_message_iter_abandon_container.restype = None
dbus.dbus_message_iter_abandon_container.argtypes = (DBUS.MessageIterPtr, DBUS.MessageIterPtr)
dbus.dbus_message_lock.restype = None
dbus.dbus_message_lock.argtypes = (DBUS.MessageIterPtr,)
dbus.dbus_set_error_from_message.restype = DBUS.bool_t
dbus.dbus_set_error_from_message.argtypes = (ct.c_void_p, ct.c_void_p)
dbus.dbus_message_allocate_data_slot.restype = DBUS.bool_t
dbus.dbus_message_allocate_data_slot.argtypes = (ct.POINTER(ct.c_int),)
dbus.dbus_message_free_data_slot.restype = None
dbus.dbus_message_free_data_slot.argtypes = (ct.POINTER(ct.c_int),)
dbus.dbus_message_set_data.restype = DBUS.bool_t
dbus.dbus_message_set_data.argtypes = (ct.c_void_p, ct.c_int, ct.c_void_p, ct.c_void_p)
dbus.dbus_message_get_data.restype = ct.c_void_p
dbus.dbus_message_get_data.argtypes = (ct.c_void_p, ct.c_int)
dbus.dbus_message_type_from_string.restype = ct.c_int
dbus.dbus_message_type_from_string.argtypes = (ct.c_char_p,)
dbus.dbus_message_type_to_string.restype = ct.c_char_p
dbus.dbus_message_type_to_string.argtypes = (ct.c_int,)
dbus.dbus_message_marshal.restype = DBUS.bool_t
dbus.dbus_message_marshal.argtypes = (ct.c_void_p, ct.c_void_p, ct.POINTER(ct.c_int))
dbus.dbus_message_demarshal.restype = ct.c_void_p
dbus.dbus_message_demarshal.argtypes = (ct.c_void_p, ct.c_int, DBUS.ErrorPtr)
dbus.dbus_message_demarshal_bytes_needed.restype = ct.c_int
dbus.dbus_message_demarshal_bytes_needed.argtypes = (ct.c_void_p, ct.c_int)
dbus.dbus_message_set_allow_interactive_authorization.restype = None
dbus.dbus_message_set_allow_interactive_authorization.argtypes = (ct.c_void_p, DBUS.bool_t)
dbus.dbus_message_get_allow_interactive_authorization.restype = DBUS.bool_t
dbus.dbus_message_get_allow_interactive_authorization.argtypes = (ct.c_void_p,)

# from dbus-memory.h:
dbus.dbus_malloc.restype = ct.c_void_p
dbus.dbus_malloc.argtypes = (ct.c_size_t,)
dbus.dbus_malloc0.restype = ct.c_void_p
dbus.dbus_malloc0.argtypes = (ct.c_size_t,)
dbus.dbus_realloc.restype = ct.c_void_p
dbus.dbus_realloc.argtypes = (ct.c_void_p, ct.c_size_t)
dbus.dbus_free.restype = None
dbus.dbus_free.argtypes = (ct.c_void_p,)
dbus.dbus_free_string_array.restype = None
dbus.dbus_free_string_array.argtypes = (ct.c_void_p,)

# from dbus-misc.h:
dbus.dbus_get_local_machine_id.restype = ct.c_void_p
dbus.dbus_get_local_machine_id.argtypes = ()
dbus.dbus_get_version.restype = None
dbus.dbus_get_version.argtypes = (ct.POINTER(ct.c_int), ct.POINTER(ct.c_int), ct.POINTER(ct.c_int))
dbus.dbus_setenv.restype = DBUS.bool_t
dbus.dbus_setenv.argtypes = (ct.c_char_p, ct.c_char_p)

# from dbus-address.h:
dbus.dbus_parse_address.restype = DBUS.bool_t
dbus.dbus_parse_address.argtypes = (ct.c_char_p, ct.c_void_p, ct.POINTER(ct.c_int), DBUS.ErrorPtr)
dbus.dbus_address_entry_get_value.restype = ct.c_char_p
dbus.dbus_address_entry_get_value.argtypes = (ct.c_void_p, ct.c_char_p)
dbus.dbus_address_entry_get_method.restype = ct.c_char_p
dbus.dbus_address_entry_get_method.argtypes = (ct.c_void_p,)
dbus.dbus_address_entries_free.restype = None
dbus.dbus_address_entries_free.argtypes = (ct.c_void_p,)
dbus.dbus_address_escape_value.restype = ct.c_void_p
dbus.dbus_address_escape_value.argtypes = (ct.c_char_p,)
dbus.dbus_address_unescape_value.restype = ct.c_void_p
dbus.dbus_address_unescape_value.argtypes = (ct.c_char_p, DBUS.ErrorPtr)

# from dbus-signature.h:
dbus.dbus_signature_iter_init.restype = None
dbus.dbus_signature_iter_init.argtypes = (DBUS.SignatureIterPtr, ct.c_char_p)
dbus.dbus_signature_iter_get_current_type.restype = ct.c_int
dbus.dbus_signature_iter_get_current_type.argtypes = (DBUS.SignatureIterPtr,)
dbus.dbus_signature_iter_get_signature.restype = ct.c_void_p
dbus.dbus_signature_iter_get_signature.argtypes = (DBUS.SignatureIterPtr,)
dbus.dbus_signature_iter_get_element_type.restype = ct.c_int
dbus.dbus_signature_iter_get_element_type.argtypes = (DBUS.SignatureIterPtr,)
dbus.dbus_signature_iter_next.restype = DBUS.bool_t
dbus.dbus_signature_iter_next.argtypes = (DBUS.SignatureIterPtr,)
dbus.dbus_signature_iter_recurse.restype = None
dbus.dbus_signature_iter_recurse.argtypes = (DBUS.SignatureIterPtr, DBUS.SignatureIterPtr)
dbus.dbus_signature_validate.restype = DBUS.bool_t
dbus.dbus_signature_validate.argtypes = (ct.c_char_p, DBUS.ErrorPtr)
dbus.dbus_signature_validate_single.restype = DBUS.bool_t
dbus.dbus_signature_validate_single.argtypes = (ct.c_char_p, DBUS.ErrorPtr)
dbus.dbus_type_is_valid.restype = DBUS.bool_t
dbus.dbus_type_is_valid.argtypes = (ct.c_int,)
dbus.dbus_type_is_basic.restype = DBUS.bool_t
dbus.dbus_type_is_basic.argtypes = (ct.c_int,)
dbus.dbus_type_is_container.restype = DBUS.bool_t
dbus.dbus_type_is_container.argtypes = (ct.c_int,)
dbus.dbus_type_is_fixed.restype = DBUS.bool_t
dbus.dbus_type_is_fixed.argtypes = (ct.c_int,)

# from dbus-syntax.h:
dbus.dbus_validate_path.restype = DBUS.bool_t
dbus.dbus_validate_path.argtypes = (ct.c_char_p, DBUS.ErrorPtr)
dbus.dbus_validate_interface.restype = DBUS.bool_t
dbus.dbus_validate_interface.argtypes = (ct.c_char_p, DBUS.ErrorPtr)
dbus.dbus_validate_member.restype = DBUS.bool_t
dbus.dbus_validate_member.argtypes = (ct.c_char_p, DBUS.ErrorPtr)
dbus.dbus_validate_error_name.restype = DBUS.bool_t
dbus.dbus_validate_error_name.argtypes = (ct.c_char_p, DBUS.ErrorPtr)
dbus.dbus_validate_bus_name.restype = DBUS.bool_t
dbus.dbus_validate_bus_name.argtypes = (ct.c_char_p, DBUS.ErrorPtr)
dbus.dbus_validate_utf8.restype = DBUS.bool_t
dbus.dbus_validate_utf8.argtypes = (ct.c_char_p, DBUS.ErrorPtr)

# from dbus-server.h:
dbus.dbus_server_listen.restype = ct.c_void_p
dbus.dbus_server_listen.argtypes = (ct.c_char_p, DBUS.ErrorPtr)
dbus.dbus_server_ref.restype = ct.c_void_p
dbus.dbus_server_ref.argtypes = (ct.c_void_p,)
dbus.dbus_server_unref.restype = ct.c_void_p
dbus.dbus_server_unref.argtypes = (ct.c_void_p,)
dbus.dbus_server_disconnect.restype = None
dbus.dbus_server_disconnect.argtypes = (ct.c_void_p,)
dbus.dbus_server_get_is_connected.restype = DBUS.bool_t
dbus.dbus_server_get_is_connected.argtypes = (ct.c_void_p,)
dbus.dbus_server_get_address.restype = ct.c_void_p
dbus.dbus_server_get_address.argtypes = (ct.c_void_p,)
dbus.dbus_server_get_id.restype = ct.c_void_p
dbus.dbus_server_get_id.argtypes = (ct.c_void_p,)
dbus.dbus_server_set_new_connection_function.restype = None
dbus.dbus_server_set_new_connection_function.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p)
dbus.dbus_server_set_watch_functions.restype = DBUS.bool_t
dbus.dbus_server_set_watch_functions.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p)
dbus.dbus_server_set_timeout_functions.restype = DBUS.bool_t
dbus.dbus_server_set_timeout_functions.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p)
dbus.dbus_server_set_auth_mechanisms.restype = DBUS.bool_t
dbus.dbus_server_set_auth_mechanisms.argtypes = (ct.c_void_p, ct.c_void_p)
dbus.dbus_server_allocate_data_slot.restype = DBUS.bool_t
dbus.dbus_server_allocate_data_slot.argtypes = (ct.POINTER(ct.c_int),)
dbus.dbus_server_free_data_slot.restype = DBUS.bool_t
dbus.dbus_server_free_data_slot.argtypes = (ct.POINTER(ct.c_int),)
dbus.dbus_server_set_data.restype = DBUS.bool_t
dbus.dbus_server_set_data.argtypes = (ct.c_void_p, ct.c_int, ct.c_void_p, ct.c_void_p)
dbus.dbus_server_set_data.restype = ct.c_void_p
dbus.dbus_server_set_data.argtypes = (ct.c_void_p, ct.c_int)

# TODO: dbus-threads.h <https://dbus.freedesktop.org/doc/api/html/group__DBusThreads.html>

#+
# High-level stuff follows
#-

class DBusError(Exception) :
    "for raising an exception that reports a D-Bus error name and accompanying message."

    def __init__(self, name, message) :
        self.args = ("%s -- %s" % (name, message),)
    #end __init__

#end DBusError

class DBusFailure(DBusError) :
    "used internally for reporting general libdbus call failures."

    def __init__(self, message) :
        super().__init__(DBUS.ERROR_FAILED, message)
    #end __init__

#end DBusFailure

# Misc: <https://dbus.freedesktop.org/doc/api/html/group__DBusMisc.html>

def get_local_machine_id() :
    "Returns a systemwide unique ID that is supposed to remain constant at least" \
    " until the next reboot. Two processes seeing the same value for this can assume" \
    " they are on the same machine."
    c_result = dbus.dbus_get_local_machine_id()
    if c_result == None :
        raise DBusFailure("dbus_get_local_machine_id failed")
    #end if
    result = ct.cast(c_result, ct.c_char_p).value.decode()
    dbus.dbus_free(c_result)
    return \
        result
#end get_local_machine_id

def get_version() :
    "returns the libdbus library version as a tuple of integers (major, minor, micro)."
    major = ct.c_int()
    minor = ct.c_int()
    micro = ct.c_int()
    dbus.dbus_get_version(ct.byref(major), ct.byref(minor), ct.byref(micro))
    return \
        (major.value, minor.value, micro.value)
#end get_version

def setenv(key, value) :
    key = key.encode()
    if value != None :
        value = value.encode()
    #end if
    if not dbus.dbus_setenv(key, value) :
        raise DBusFailure("dbus_setenv failed")
    #end if
#end setenv

def unsetenv(key) :
    setenv(key, None)
#end unsetenv

class Watch :
    "wrapper around a DBusWatch object. Do not instantiate directly; they" \
    " are created and destroyed by libdbus.\n" \
    "\n" \
    "A Watch is the basic mechanism for plugging libdbus-created file descriptors" \
    " into your event loop. When created, they are passed to your add-watch callback" \
    " to manage; and conversely, when deleted, your remove-watch callback is notified." \
    " (These callbacks are ones you attach to Server and Connection objects.)\n" \
    "\n" \
    "Check the enabled property to decide if you need to pay attention to this Watch, and" \
    " look at the flags to see if you need to check for pending reads, or writes, or both." \
    " Call the handle() method with the appropriate flags when you see that reads or writes" \
    " are pending."
    # <https://dbus.freedesktop.org/doc/api/html/group__DBusWatch.html>

    __slots__ = ("__weakref__", "_dbobj",) # to forestall typos

    _instances = WeakValueDictionary()

    def __new__(celf, _dbobj) :
        self = celf._instances.get(_dbobj)
        if self == None :
            self = super().__new__(celf)
            self._dbobj = _dbobj
            celf._instances[_dbobj] = self
        #end if
        return \
            self
    #end __new__

    # no __del__ method -- no underlying dispose API call

    @property
    def unix_fd(self) :
        "the underlying file descriptor for this Watch."
        return \
            dbus.dbus_watch_get_unix_fd(self._dbobj)
    #end unix_fd

    def fileno(self) :
        "for use with Python’s “select” functions."
        return \
            self.unix_fd
    #end fileno

    @property
    def socket(self) :
        return \
            dbus.dbus_watch_get_socket(self._dbobj)
    #end socket

    @property
    def flags(self) :
        "returns WATCH_READABLE and/or WATCH_WRITABLE, indicating what to watch for."
        return \
            dbus.dbus_watch_get_flags(self._dbobj)
    #end flags

    # TODO: get/set data

    def handle(self, flags) :
        "tells libdbus that there is something to be read or written." \
        " flags are a combination of WATCH_xxx values."
        return \
            dbus.dbus_watch_handle(self._dbobj, flags) != 0
    #end handle

    @property
    def enabled(self) :
        "does libdbus want you to actually watch this Watch."
        return \
            dbus.dbus_watch_get_enabled(self._dbobj) != 0
    #end enabled

#end Watch

class Timeout :
    "wrapper around a DBusTimeout object. Do not instantiate directly; they" \
    " are created and destroyed by libdbus.\n" \
    "\n" \
    " A Timeout is the basic mechanism for plugging libdbus-created timeouts" \
    " into your event loop. When created, they are passed to your add-timeout" \
    " callback to manage; and conversely, when deleted, your remove-timeout" \
    " callback is notified. (These callbacks are ones you attach to Server and" \
    " Connection objects.)\n" \
    "\n" \
    "Check the enabled property to decide if you need to pay attention to this" \
    " Timeout. Call the handle() method when the timeout becomes due, as measured" \
    " from when it was initially created or most recently enabled, whichever" \
    " happened last."
    # <https://dbus.freedesktop.org/doc/api/html/group__DBusTimeout.html>

    __slots__ = ("__weakref__", "_dbobj",) # to forestall typos

    _instances = WeakValueDictionary()

    def __new__(celf, _dbobj) :
        self = celf._instances.get(_dbobj)
        if self == None :
            self = super().__new__(celf)
            self._dbobj = _dbobj
            celf._instances[_dbobj] = self
        #end if
        return \
            self
    #end __new__

    # no __del__ method -- no underlying dispose API call

    @property
    def interval(self) :
        "how long in float seconds until the timeout should fire."
        return \
            dbus.dbus_timeout_get_interval(self._dbobj) / 1000
    #end interval

    # TODO: get/set data

    def handle(self) :
        "tells libdbus the timeout has fired."
        return \
            dbus.dbus_timeout_handle(self._dbobj)
    #end handle

    @property
    def enabled(self) :
        "does libdbus want you to actually schedule this Timeout."
        return \
            dbus.dbus_timeout_get_enabled(self._dbobj) != 0
    #end enabled

#end Timeout

class ObjectPathVTable :
    "wrapper around an ObjectPathVTable struct. You can instantiate directly, or call" \
    " the init method. An additional feature beyond the underlying libdbus capabilities" \
    " is the option to specify an asyncio event loop. If the message handler returns" \
    " a coroutine, then an asyncio task is created to run it, and a result of" \
    " DBUS.HANDLER_RESULT_HANDLED is returned on behalf of the message handler;" \
    " that way, the message function can do the minimum beyond some initial filtering of" \
    " the message, leaving the time-consuming part of the work to the coroutine."

    __slots__ = \
      (
        "_dbobj",
        "loop",
        # need to keep references to ctypes-wrapped functions
        # so they don't disappear prematurely:
        "_wrap_unregister_func",
        "_wrap_message_func",
      ) # to forestall typos

    def __init__(self, *, loop = None, unregister = None, message = None) :
        self._dbobj = DBUS.ObjectPathVTable()
        self.loop = loop
        self._wrap_unregister_func = None
        self._wrap_message_func = None
        if unregister != None :
            self.set_unregister(unregister)
        #end if
        if message != None :
            self.set_message(message)
        #end if
    #end __init__

    @classmethod
    def init(celf, *, loop = None, unregister = None, message = None) :
        "for consistency with other classes that don’t want caller to instantiate directly."
        return \
            celf \
              (
                loop = loop,
                unregister = unregister,
                message = message,
              )
    #end init

    def set_unregister(self, unregister) :

        def wrap_unregister(c_conn, c_user_data) :
            conn = Connection(dbus.dbus_connection_ref(c_conn))
            unregister(conn, conn._user_data.get(c_user_data))
        #end wrap_unregister

    #begin set_unregister
        if unregister != None :
            self._wrap_unregister_func = DBUS.ObjectPathUnregisterFunction(wrap_unregister)
        else :
            self._wrap_unregister_func = None
        #end if
        self._dbobj.unregister_function = self._wrap_unregister_func
        return \
            self
    #end set_unregister

    def set_message(self, message) :

        def wrap_message(c_conn, c_message, c_user_data) :
            conn = Connection(dbus.dbus_connection_ref(c_conn))
            msg = Message(dbus.dbus_message_ref(c_message))
            user_data = conn._user_data.get(c_user_data)
            result = message(conn, msg, user_data)
            if isinstance(result, types.CoroutineType) :
                assert self.loop != None, "no event loop to attach coroutine to"
                self.loop.create_task(result)
                result = DBUS.HANDLER_RESULT_HANDLED
            #end if
            return \
                result
        #end wrap_message

    #begin set_message
        if message != None :
            self._wrap_message_func = DBUS.ObjectPathMessageFunction(wrap_message)
        else :
            self._wrap_message_func = None
        #end if
        self._dbobj.message_function = self._wrap_message_func
        return \
            self
    #end set_message

#end ObjectPathVTable

class _DummyError :
    # like an Error, but is never set and so will never raise.

    @property
    def is_set(self) :
        return \
            False
    #end is_set

    def raise_if_set(self) :
        pass
    #end raise_if_set

#end _DummyError

def _get_error(error) :
    # Common routine which processes an optional user-supplied Error
    # argument, and returns 2 Error-like objects: the first a real
    # Error object to be passed to the libdbus call, the second is
    # either the same Error object or a separate _DummyError object
    # on which to call raise_if_set() afterwards. The procedure for
    # using this is
    #
    #     error, my_error = _get_error(error)
    #     ... call libdbus routine, passing error._dbobj ...
    #     my_error.raise_if_set()
    #
    # If the user passes None for error, then an internal Error object
    # is created, and returned as both results. That way, if it is
    # filled in by the libdbus call, calling raise_if_set() will
    # automatically raise the exception.
    # But if the user passed their own Error object, then it is
    # returned as the first result, and a _DummyError as the second
    # result. This means the raise_if_set() call becomes a noop, and
    # it is up to the caller to check if their Error object was filled
    # in or not.
    if error != None and not isinstance(error, Error) :
        raise TypeError("error must be an Error")
    #end if
    if error != None :
        my_error = _DummyError()
    else :
        my_error = Error()
        error = my_error
    #end if
    return \
        error, my_error
#end _get_error

def _get_timeout(timeout) :
    if not isinstance(timeout, int) or timeout not in (DBUS.TIMEOUT_INFINITE, DBUS.TIMEOUT_USE_DEFAULT) :
        timeout = round(timeout * 1000)
    #end if
    return \
        timeout
#end _get_timeout

def _loop_attach(self, loop, dispatch) :
    # attaches a Server or Connection object to a given asyncio event loop.
    # If loop is None, then the default asyncio loop is used. The actual loop
    # value is returned as the function result for saving as an object attribute.

    if loop == None :
        loop = asyncio.get_event_loop()
    #end if

    watches = [] # do I need to keep track of Watch objects?
    timeouts = []

    def call_dispatch() :
        status = dispatch()
        if status == DBUS.DISPATCH_NEED_MEMORY :
            raise DBusFailure("not enough memory for connection dispatch")
        #end if
        if status == DBUS.DISPATCH_DATA_REMAINS :
            loop.call_soon(call_dispatch)
        #end if
    #end call_dispatch

    def add_remove_watch(watch, add) :

        def handle_watch_event(flags) :
            watch.handle(flags)
            if dispatch != None :
                call_dispatch()
            #end if
        #end handle_watch_event

    #end add_remove_watch
        if DBUS.WATCH_READABLE & watch.flags != 0 :
            if add :
                loop.add_reader(watch, handle_watch_event, DBUS.WATCH_READABLE)
            else :
                loop.remove_reader(watch)
            #end if
        #end if
        if DBUS.WATCH_WRITABLE & watch.flags != 0 :
            if add :
                loop.add_writer(watch, handle_watch_event, DBUS.WATCH_WRITABLE)
            else :
                loop.remove_writer(watch)
            #end if
        #end if
    #end add_remove_watch

    def handle_add_watch(watch, data) :
        if watch not in watches :
            watches.append(watch)
            add_remove_watch(watch, True)
        #end if
        return \
            True
    #end handle_add_watch

    def handle_watch_toggled(watch, data) :
        add_remove_watch(watch, watch.enabled)
    #end handle_watch_toggled

    def handle_remove_watch(watch, data) :
        try :
            pos = watches.index(watch)
        except ValueError :
            pos = None
        #end try
        if pos != None :
            watches[pos : pos + 1] = []
            add_remove_watch(watch, False)
        #end if
    #end handle_remove_watch

    def handle_timeout(timeout) :
        if timeout["due"] != None and timeout["due"] <= loop.time() and timeout["timeout"].enabled :
            timeout["timeout"].handle()
        #end if
    #end handle_timeout

    def handle_add_timeout(timeout, data) :
        if not any(timeout == t["timeout"] for t in timeouts) :
            entry = \
                {
                    "timeout" : timeout,
                    "due" : (lambda : None, lambda : loop.time() + timeout.interval)[timeout.enabled](),
                }
            timeouts.append(entry)
            if timeout.enabled :
                loop.call_later(timeout.interval, handle_timeout, entry)
            #end if
        #end if
        return \
            True
    #end handle_add_timeout

    def handle_timeout_toggled(timeout, data) :
        # not sure what to do if a Timeout gets toggled from enabled to disabled
        # and then to enabled again; effectively I update the due time from
        # the time of re-enabling.
        search = iter(timeouts)
        while True :
            entry = next(search, None)
            if entry == None :
                break
            #end if
            if entry["timeout"] == timeout :
                if timeout.enabled :
                    entry["due"] = loop.time() + timeout.enterval
                    loop.call_later(timeout.interval, handle_timeout, entry)
                else :
                    entry["due"] = None
                #end if
                break
            #end if
        #end while
    #end handle_timeout_toggled

    def handle_remove_timeout(timeout, data) :
        new_timeouts = []
        for entry in timeouts :
            if entry["timeout"] == timeout :
                entry["due"] = None # in case already queued, avoid segfault in handle_timeout
            else :
                new_timeouts.append(entry)
            #end if
        #end for
        timeouts[:] = new_timeouts
    #end handle_remove_timeout

#begin _loop_attach
    self.set_watch_functions \
      (
        add_function = handle_add_watch,
        remove_function = handle_remove_watch,
        toggled_function = handle_watch_toggled,
        data = None
      )
    self.set_timeout_functions \
      (
        add_function = handle_add_timeout,
        remove_function = handle_remove_timeout,
        toggled_function = handle_timeout_toggled,
        data = None
      )
    self = None # avoid circularity
    return \
        loop
#end _loop_attach

class Connection :
    "wrapper around a DBusConnection object. Do not instantiate directly; use the open" \
    " or bus_get methods."
    # <https://dbus.freedesktop.org/doc/api/html/group__DBusConnection.html>

    __slots__ = \
      (
        "__weakref__",
        "_dbobj",
        "_filters",
        "loop",
        "_user_data",
        # need to keep references to ctypes-wrapped functions
        # so they don't disappear prematurely:
        "_object_paths",
        "_add_watch_function",
        "_remove_watch_function",
        "_toggled_watch_function",
        "_free_watch_data",
        "_add_timeout_function",
        "_remove_timeout_function",
        "_toggled_timeout_function",
        "_free_timeout_data",
        "_wakeup_main",
        "_free_wakeup_main_data",
        "_dispatch_status",
        "_free_dispatch_status_data",
        "_allow_unix_user",
        "_free_unix_user_data",
      ) # to forestall typos

    _instances = WeakValueDictionary()

    def __new__(celf, _dbobj) :
        self = celf._instances.get(_dbobj)
        if self == None :
            self = super().__new__(celf)
            self._dbobj = _dbobj
            self._user_data = {}
            self._filters = {}
            self.loop = None
            self._object_paths = {}
            celf._instances[_dbobj] = self
        else :
            dbus.dbus_connection_unref(self._dbobj)
              # lose extra reference created by caller
        #end if
        return \
            self
    #end __new__

    def __del__(self) :
        if self._dbobj != None :
            dbus.dbus_connection_unref(self._dbobj)
            self._dbobj = None
        #end if
    #end __del__

    @classmethod
    def open(celf, address, private, error = None) :
        error, my_error = _get_error(error)
        result = (dbus.dbus_connection_open, dbus.dbus_connection_open_private)[private](address.encode(), error._dbobj)
        my_error.raise_if_set()
        if result != None :
            result = celf(result)
        #end if
        return \
            result
    #end open

    def close(self) :
        dbus.dbus_connection_close(self._dbobj)
    #end close

    @property
    def is_connected(self) :
        return \
            dbus.dbus_connection_get_is_connected(self._dbobj) != 0
    #end is_connected

    @property
    def is_authenticated(self) :
        return \
            dbus.dbus_connection_get_is_authenticated(self._dbobj) != 0
    #end is_authenticated

    @property
    def is_anonymous(self) :
        return \
            dbus.dbus_connection_get_is_anonymous(self._dbobj) != 0
    #end is_anonymous

    @property
    def server_id(self) :
        c_result = dbus.dbus_connection_get_server_id(self._dbobj)
        result = ct.cast(c_result, ct.c_char_p).value.decode()
        dbus.dbus_free(c_result)
        return \
            result
    #end server_id

    def can_send_type(self, type_code) :
        return \
            dbus.dbus_connection_can_send_type(self._dbobj, type_code) != 0
    #end can_send_type

    def set_exit_on_disconnect(self, exit_on_disconnect) :
        dbus.dbus_connection_set_exit_on_disconnect(self._dbobj, exit_on_disconnect)
    #end set_exit_on_disconnect

    def preallocate_send(self) :
        result = dbus.dbus_connection_preallocate_send(self._dbobj)
        if result == None :
            raise DBusFailure("dbus_connection_preallocate_send failed")
        #end if
        return \
            PreallocatedSend(result, self)
    #end preallocate_send

    def send_preallocated(self, preallocated, message) :
        if not isinstance(preallocated, PreallocatedSend) or not isinstance(message, Message) :
            raise TypeError("preallocated must be a PreallocatedSend and message must be a Message")
        #end if
        assert not preallocated._sent, "preallocated has already been sent"
        serial = ct.c_uint()
        dbus.dbus_connection_send_preallocated(self._dbobj, preallocated._dbobj, message._dbobj, ct.byref(serial))
        preallocated._sent = True
        return \
            serial.value
    #end send_preallocated

    def send(self, message) :
        if not isinstance(message, Message) :
            raise TypeError("message must be a Message")
        #end if
        serial = ct.c_uint()
        if not dbus.dbus_connection_send(self._dbobj, message._dbobj, ct.byref(serial)) :
            raise DBusFailure("dbus_connection_send failed")
        #end if
        return \
            serial.value
    #end send

    def send_with_reply(self, message, timeout) :
        if not isinstance(message, Message) :
            raise TypeError("message must be a Message")
        #end if
        pending_call = ct.c_void_p()
        if not dbus.dbus_connection_send_with_reply(self._dbobj, message._dbobj, ct.byref(pending_call), _get_timeout(timeout)) :
            raise DBusFailure("dbus_connection_send_with_reply failed")
        #end if
        if pending_call.value != None :
            result = PendingCall(pending_call.value)
        else :
            result = None
        #end if
        return \
            result
    #end send_with_reply

    def send_with_reply_and_block(self, message, timeout, error = None) :
        if not isinstance(message, Message) :
            raise TypeError("message must be a Message")
        #end if
        error, my_error = _get_error(error)
        reply = dbus.dbus_connection_send_with_reply_and_block(self._dbobj, message._dbobj, _get_timeout(timeout), error._dbobj)
        my_error.raise_if_set()
        if reply != None :
            result = Message(reply)
        else :
            result = None
        #end if
        return \
            result
    #end send_with_reply_and_block

    async def send_await_reply(self, message, timeout) :
        if not isinstance(message, Message) :
            raise TypeError("message must be a Message")
        #end if
        pending_call = ct.c_void_p()
        if not dbus.dbus_connection_send_with_reply(self._dbobj, message._dbobj, ct.byref(pending_call), _get_timeout(timeout)) :
            raise DBusFailure("dbus_connection_send_with_reply failed")
        #end if
        if pending_call.value != None :
            pending = PendingCall(pending_call.value)
        else :
            pending = None
        #end if
        reply = None # to begin with
        if pending != None :
            done = self.loop.create_future()

            def pending_done(pending, _) :
                done.set_result(pending.steal_reply())
            #end pending_done

            pending.set_notify(pending_done, None)
            reply = await done
        #end if
        return \
            reply
    #end send_await_reply

    def flush(self) :
        dbus.dbus_connection_flush(self._dbobj)
    #end flush

    def read_write_dispatch(self, timeout) :
        return \
            dbus.dbus_connection_read_write_dispatch(self._dbobj, _get_timeout(timeout)) != 0
    #end read_write_dispatch

    def read_write(self, timeout) :
        return \
            dbus.dbus_connection_read_write(self._dbobj, _get_timeout(timeout)) != 0
    #end read_write

    def borrow_message(self) :
        msg = dbus.dbus_connection_borrow_message(self._dbobj)
        if msg != None :
            msg = Message(msg)
            msg._conn = self
            msg._borrowed = True
        #end if
        return \
            msg
    #end borrow_message

    # returning/stealing borrowed messages done with
    # Message.return_borrowed and Message.steal_borrowed

    def pop_message(self) :
        message = dbus.dbus_connection_pop_message(self._dbobj)
        if message != None :
            message = Message(message)
        #end if
        return \
            message
    #end pop_message

    @property
    def dispatch_status(self) :
        "returns a DISPATCH_XXX code."
        return \
            dbus.dbus_connection_get_dispatch_status(self._dbobj)
    #end dispatch_status

    def dispatch(self) :
        "returns a DISPATCH_XXX code."
        return \
            dbus.dbus_connection_dispatch(self._dbobj)
    #end dispatch

    def set_watch_functions(self, add_function, remove_function, toggled_function, data, free_data = None) :

        def wrap_add_function(c_watch, _data) :
            return \
                add_function(Watch(c_watch), data)
        #end wrap_add_function

        def wrap_remove_function(c_watch, _data) :
            return \
                remove_function(Watch(c_watch), data)
        #end wrap_remove_function

        def wrap_toggled_function(c_watch, _data) :
            return \
                toggled_function(Watch(c_watch), data)
        #end wrap_toggled_function

        def wrap_free_data(_data) :
            free_data(data)
        #end wrap_free_data

    #begin set_watch_functions
        self._add_watch_function = DBUS.AddWatchFunction(wrap_add_function)
        self._remove_watch_function = DBUS.RemoveWatchFunction(wrap_remove_function)
        if toggled_function != None :
            self._toggled_watch_function = DBUS.WatchToggledFunction(wrap_toggled_function)
        else :
            self._toggled_watch_function = None
        #end if
        if free_data != None :
            self._free_watch_data = DBUS.FreeFunction(wrap_free_data)
        else :
            self._free_watch_data = None
        #end if
        if not dbus.dbus_connection_set_watch_functions(self._dbobj, self._add_watch_function, self._remove_watch_function, self._toggled_watch_function, None, self._free_watch_data) :
            raise DBusFailure("dbus_connection_set_watch_functions failed")
        #end if
    #end set_watch_functions

    def set_timeout_functions(self, add_function, remove_function, toggled_function, data, free_data = None) :

        def wrap_add_function(c_timeout, _data) :
            return \
                add_function(Timeout(c_timeout), data)
        #end wrap_add_function

        def wrap_remove_function(c_timeout, _data) :
            return \
                remove_function(Timeout(c_timeout), data)
        #end wrap_remove_function

        def wrap_toggled_function(c_timeout, _data) :
            return \
                toggled_function(Timeout(c_timeout), data)
        #end wrap_toggled_function

        def wrap_free_data(_data) :
            free_data(data)
        #end wrap_free_data

    #begin set_timeout_functions
        self._add_timeout_function = DBUS.AddTimeoutFunction(wrap_add_function)
        self._remove_timeout_function = DBUS.RemoveTimeoutFunction(wrap_remove_function)
        if toggled_function != None :
            self._toggled_timeout_function = DBUS.TimeoutToggledFunction(wrap_toggled_function)
        else :
            self._toggled_timeout_function = None
        #end if
        if free_data != None :
            self._free_timeout_data = DBUS.FreeFunction(wrap_free_data)
        else :
            self._free_timeout_data = None
        #end if
        if not dbus.dbus_connection_set_timeout_functions(self._dbobj, self._add_timeout_function, self._remove_timeout_function, self._toggled_timeout_function, None, self._free_timeout_data) :
            raise DBusFailure("dbus_connection_set_timeout_functions failed")
        #end if
    #end set_timeout_functions

    def set_wakeup_main_function(self, wakeup_main, data, free_data = None) :

        def wrap_wakeup_main(_data) :
            wakeup_main(data)
        #end wrap_wakeup_main

        def wrap_free_data(_data) :
            free_data(data)
        #end wrap_free_data

    #begin set_wakeup_main_function
        if wakeup_main != None :
            self._wakeup_main = DBUS.WakeupMainFunction(wrap_wakeup_main)
        else :
            self._wakeup_main = None
        #end if
        if free_data != None :
            self._free_wakeup_main_data = DBUS.FreeFunction(wrap_free_data)
        else :
            self._free_wakeup_main_data = None
        #end if
        dbus.dbus_connection_set_wakeup_main_function(self._dbobj, self._wakeup_main, None, self._free_wakeup_main_data)
    #end set_wakeup_main_function

    def set_dispatch_status_function(self, function, data, free_data = None) :

        def wrap_dispatch_status(_conn, status, _data) :
            function(self, status, data)
        #end wrap_dispatch_status

        def wrap_free_data(_data) :
            free_data(data)
        #end wrap_free_data

    #begin set_dispatch_status_function
        self._dispatch_status = DBUS.DispatchStatusFunction(wrap_dispatch_status)
        if free_data != None :
            self._free_wakeup_main_data = DBUS.FreeFunction(wrap_free_data)
        else :
            self._free_wakeup_main_data = None
        #end if
        dbus.dbus_connection_set_dispatch_status_function(self._dbobj, self._dispatch_status, None, self._free_wakeup_main_data)
    #end set_dispatch_status_function

    @property
    def unix_fd(self) :
        c_fd = ct.c_int()
        if dbus.dbus_connection_get_unix_fd(self._dbobj, ct.byref(c_fd)) :
            result = c_fd.value
        else :
            result = None
        #end if
        return \
            result
    #end unix_fd

    def fileno(self) :
        "for use with Python’s “select” functions."
        return \
            self.unix_fd
    #end fileno

    @property
    def socket(self) :
        c_fd = ct.c_int()
        if dbus.dbus_connection_get_socket(self._dbobj, ct.byref(c_fd)) :
            result = c_fd.value
        else :
            result = None
        #end if
        return \
            result
    #end socket

    @property
    def unix_process_id(self) :
        c_pid = ct.c_ulong()
        if dbus.dbus_connection_get_unix_process_id(self._dbobj, ct.byref(c_pid)) :
            result = c_pid.value
        else :
            result = None
        #end if
        return \
            result
    #end unix_process_id

    @property
    def unix_user(self) :
        c_uid = ct.c_ulong()
        if dbus.dbus_connection_get_unix_user(self._dbobj, ct.byref(c_uid)) :
            result = c_uid.value
        else :
            result = None
        #end if
        return \
            result
    #end unix_user

    # TODO: get_adt

    def set_unix_user_function(self, allow_unix_user, data, free_data = None) :

        def wrap_allow_unix_user(c_conn, uid, c_data) :
            return \
                allow_unix_user(self, uid, data)
        #end wrap_allow_unix_user

        def wrap_free_data(_data) :
            free_data(data)
        #end wrap_free_data

    #begin set_unix_user_function
        if allow_unix_user != None :
            self._allow_unix_user = DBUS.AllowUnixUserFunction(wrap_allow_unix_user)
        else :
            self._allow_unix_user = None
        #end if
        if free_data != None :
            self._free_unix_user_data = DBUS.FreeFunction(wrap_free_data)
        else :
            self._free_unix_user_data = None
        #end if
        dbus.dbus_connection_set_unix_user_function(self._dbobj, self._allow_unix_user, None, self._free_unix_user_data)
    #end set_unix_user_function

    def set_allow_anonymous(self, allow) :
        dbus.dbus_connection_set_allow_anonymous(self._dbobj, allow)
    #end set_allow_anonymous

    def set_route_peer_messages(self, enable) :
        dbus.dbus_connection_set_route_peer_messages(self._dbobj, enable)
    #end set_route_peer_messages

    def add_filter(self, function, user_data, free_data = None) :

        def wrap_function(c_conn, message, _data) :
            result = function(self, Message(dbus.dbus_message_ref(message)), user_data)
            if isinstance(result, types.CoroutineType) :
                assert self.loop != None, "no event loop to attach coroutine to"
                self.loop.create_task(result)
                result = DBUS.HANDLER_RESULT_HANDLED
            #end if
            return \
                result
        #end wrap_function

        def wrap_free_data(_data) :
            free_data(data)
        #end wrap_free_data

    #begin add_filter
        filter_key = (function, id(user_data))
          # use id to allow non-hashable user_data
        filter_value = \
            {
                "function" : DBUS.HandleMessageFunction(wrap_function),
                "free_data" : (lambda : None, lambda : DBUS.FreeFunction(wrap_free_data))[free_data != None](),
            }
        # pass user_data id because libdbus identifies filter entry by both function address and user data address
        if not dbus.dbus_connection_add_filter(self._dbobj, filter_value["function"], filter_key[1], filter_value["free_data"]) :
            raise DBusFailure("dbus_connection_add_filter failed")
        #end if
        self._filters[filter_key] = filter_value
          # need to ensure wrapped functions don’t disappear prematurely
    #end add_filter

    def remove_filter(self, function, user_data) :
        filter_key = (function, id(user_data))
          # use id to allow non-hashable user_data
        if filter_key not in self._filters :
            raise KeyError("removing nonexistent Connection filter")
        #end if
        filter_value = self._filters[filter_key]
        # pass user_data id because libdbus identifies filter entry by both function address and user data address
        dbus.dbus_connection_remove_filter(self._dbobj, filter_value["function"], filter_key[1])
        del self._filters[filter_key]
    #end remove_filter

    def register_object_path(self, path, vtable, user_data, error = None) :
        if not isinstance(vtable, ObjectPathVTable) :
            raise TypeError("vtable must be an ObjectPathVTable")
        #end if
        self._object_paths[path] = {"vtable" : vtable, "user_data" : user_data} # ensure it doesn’t disappear prematurely
        error, my_error = _get_error(error)
        if user_data != None :
            c_user_data = id(user_data)
            self._user_data[c_user_data] = user_data
        else :
            c_user_data = None
        #end if
        dbus.dbus_connection_try_register_object_path(self._dbobj, path.encode(), vtable._dbobj, c_user_data, error._dbobj)
        my_error.raise_if_set()
    #end register_object_path

    def register_fallback(self, path, vtable, user_data, error = None) :
        if not isinstance(vtable, ObjectPathVTable) :
            raise TypeError("vtable must be an ObjectPathVTable")
        #end if
        self._object_paths[path] = {"vtable" : vtable, "user_data" : user_data} # ensure it doesn’t disappear prematurely
        error, my_error = _get_error(error)
        if user_data != None :
            c_user_data = id(user_data)
            self._user_data[c_user_data] = user_data
        else :
            c_user_data = None
        #end if
        dbus.dbus_connection_try_register_fallback(self._dbobj, path.encode(), vtable._dbobj, c_user_data, error._dbobj)
        my_error.raise_if_set()
    #end register_fallback

    def unregister_object_path(self, path) :
        if path not in self._object_paths :
            raise KeyError("unregistering unregistered path")
        #end if
        if not dbus.dbus_connection_unregister_object_path(self._dbobj, path.encode()) :
            raise DBusFailure("dbus_connection_unregister_object_path failed")
        #end if
        user_data = self._object_paths[path]["user_data"]
        c_user_data = id(user_data)
        nr_remaining_refs = sum(int(self._object_paths[p]["user_data"] == user_data) for p in self._object_paths if p != path)
        if nr_remaining_refs == 0 :
            try :
                del self._user_data[c_user_data]
            except KeyError :
                pass
            #end try
        #end if
        del self._object_paths[path]
    #end unregister_object_path

    def get_object_path_data(self, path) :
        c_data_p = ct.c_void_p()
        if not dbus.dbus_connection_get_object_path_data(self._dbobj, path.encode(), ct.byref(c_data_p)) :
            raise DBusFailure("dbus_connection_get_object_path_data failed")
        #end if
        return \
            self._user_data.get(c_data_p.value)
    #end get_object_path_data

    def list_registered(self, parent_path) :
        child_entries = ct.POINTER(ct.c_char_p)()
        if not dbus.dbus_connection_list_registered(self._dbobj, parent_path.encode(), ct.byref(child_entries)) :
            raise DBusFailure("dbus_connection_list_registered failed")
        #end if
        result = []
        i = 0
        while True :
            entry = child_entries[i]
            if entry == None :
                break
            result.append(entry.decode())
            i += 1
        #end while
        dbus.dbus_free_string_array(child_entries)
        return \
            result
    #end list_registered

    # TODO: allocate/free data slot -- staticmethods
    # TODO: get/set data

    def set_change_sigpipe(self, will_modify_sigpipe) :
        dbus.dbus_connection_set_change_sigpipe(self._dbobj, will_modify_sigpipe)
    #end set_change_sigpipe

    @property
    def max_message_size(self) :
        return \
            dbus.dbus_connection_get_max_message_size(self._dbobj)
    #end max_message_size

    @max_message_size.setter
    def max_message_size(self, size) :
        dbus.dbus_connection_set_max_message_size(self._dbobj, size)
    #end max_message_size

    @property
    def max_received_size(self) :
        return \
            dbus.dbus_connection_get_max_received_size(self._dbobj)
    #end max_received_size

    @max_received_size.setter
    def max_received_size(self, size) :
        dbus.dbus_connection_set_max_received_size(self._dbobj, size)
    #end max_received_size

    @property
    def max_message_unix_fds(self) :
        return \
            dbus.dbus_connection_get_max_message_unix_fds(self._dbobj)
    #end max_message_unix_fds

    @max_message_unix_fds.setter
    def max_message_unix_fds(self, size) :
        dbus.dbus_connection_set_max_message_unix_fds(self._dbobj, size)
    #end max_message_unix_fds

    @property
    def max_received_unix_fds(self) :
        return \
            dbus.dbus_connection_get_max_received_unix_fds(self._dbobj)
    #end max_received_unix_fds

    @max_received_unix_fds.setter
    def max_received_unix_fds(self, size) :
        dbus.dbus_connection_set_max_received_unix_fds(self._dbobj, size)
    #end max_received_unix_fds

    @property
    def outgoing_size(self) :
        return \
            dbus.dbus_connection_get_outgoing_size(self._dbobj)
    #end outgoing_size

    @property
    def outgoing_unix_fds(self) :
        return \
            dbus.dbus_connection_get_outgoing_unix_fds(self._dbobj)
    #end outgoing_unix_fds

    @property
    def has_messages_to_send(self) :
        return \
            dbus.dbus_connection_has_messages_to_send(self._dbobj) != 0
    #end has_messages_to_send

    # message bus APIs
    # <https://dbus.freedesktop.org/doc/api/html/group__DBusBus.html>

    @classmethod
    def bus_get(celf, type, private, error = None) :
        "type is a BUS_xxx value."
        error, my_error = _get_error(error)
        result = (dbus.dbus_bus_get, dbus.dbus_bus_get_private)[private](type, error._dbobj)
        my_error.raise_if_set()
        if result != None :
            result = celf(result)
        #end if
        return \
            result
    #end bus_get

    def bus_register(self, error = None) :
        error, my_error = _get_error(error)
        dbus.dbus_bus_register(self._dbobj, error._dbobj)
        my_error.raise_if_set()
    #end bus_register

    @property
    def bus_unique_name(self) :
        return \
            dbus.dbus_bus_get_unique_name(self._dbobj).decode()
    #end bus_unique_name

    @bus_unique_name.setter
    def bus_unique_name(self, unique_name) :
        if not dbus.dbus_bus_set_unique_name(self._dbobj, unique_name.encode()) :
            raise DBusFailure("D-Bus set-unique-name failed")
        #end if
    #end bus_unique_name

    def bus_get_unix_user(self, name, error = None) :
        error, my_error = _get_error(error)
        result = dbus.dbus_bus_get_unix_user(self._dbobj, name.encode(), error._dbobj)
        my_error.raise_if_set()
        return \
            result
    #end bus_get_unix_user

    @property
    def bus_id(self) :
        my_error = Error()
        c_result = dbus.dbus_bus_get_id(self._dbobj, my_error._dbobj)
        my_error.raise_if_set()
        result = ct.cast(c_result, ct.c_char_p).value.decode()
        dbus.dbus_free(c_result)
        return \
            result
    #end bus_id

    def bus_request_name(self, name, flags, error = None) :
        "flags is a combination of NAME_FLAG_xxx bits. Result will be" \
        " a REQUEST_NAME_REPLY_xxx value or -1 on error."
        error, my_error = _get_error(error)
        result = dbus.dbus_bus_request_name(self._dbobj, name.encode(), flags, error._dbobj)
        my_error.raise_if_set()
        return \
            result
    #end bus_request_name

    def bus_release_name(self, name, error = None) :
        error, my_error = _get_error(error)
        result = dbus.dbus_bus_release_name(self._dbobj, name.encode(), error._dbobj)
        my_error.raise_if_set()
        return \
            result
    #end bus_release_name

    def bus_name_has_owner(self, name, error = None) :
        error, my_error = _get_error(error)
        result = dbus.dbus_bus_name_has_owner(self._dbobj, name.encode(), error._dbobj)
        my_error.raise_if_set()
        return \
            result
    #end bus_name_has_owner

    def bus_start_service_by_name(self, name, flags = 0, error = None) :
        error, my_error = _get_error(error)
        outflags = ct.c_uint()
        success = dbus.dbus_bus_start_service_by_name(self._dbobj, name.encode(), flags, ct.byref(outflags), error._dbobj)
        my_error.raise_if_set()
        return \
            outflags.value
    #end bus_start_service_by_name

    def bus_add_match(self, rule, error = None) :
        error, my_error = _get_error(error)
        dbus.dbus_bus_add_match(self._dbobj, rule.encode(), error._dbobj)
        my_error.raise_if_set()
    #end bus_add_match

    def bus_remove_match(self, rule, error = None) :
        error, my_error = _get_error(error)
        dbus.dbus_bus_remove_match(self._dbobj, rule.encode(), error._dbobj)
        my_error.raise_if_set()
    #end bus_remove_match

    def attach_asyncio(self, loop = None) :
        "attaches this Connection object to an asyncio event loop. If none is" \
        " specified, the default event loop (as returned from asyncio.get_event_loop()" \
        " is used."
        assert self.loop == None, "already attached to an event loop"
        self.loop = _loop_attach(self, loop, self.dispatch)
    #end attach_asyncio

#end Connection

class Server :
    "wrapper around a DBusServer object. Do not instantiate directly; use" \
    " the listen method."
    # <https://dbus.freedesktop.org/doc/api/html/group__DBusServer.html>

    __slots__ = \
      (
        "__weakref__",
        "_dbobj",
        "loop",
        # need to keep references to ctypes-wrapped functions
        # so they don't disappear prematurely:
        "_new_connection_function",
        "_free_new_connection_data",
        "_add_watch_function",
        "_remove_watch_function",
        "_toggled_watch_function",
        "_free_watch_data",
        "_add_timeout_function",
        "_remove_timeout_function",
        "_toggled_timeout_function",
        "_free_timeout_data",
      ) # to forestall typos

    _instances = WeakValueDictionary()

    def __new__(celf, _dbobj) :
        self = celf._instances.get(_dbobj)
        if self == None :
            self = super().__new__(celf)
            self._dbobj = _dbobj
            self.loop = None
            self._new_connection_function = None
            self._free_new_connection_data = None
            self._add_watch_function = None
            self._remove_watch_function = None
            self._toggled_watch_function = None
            self._free_watch_data = None
            self._add_timeout_function = None
            self._remove_timeout_function = None
            self._toggled_timeout_function = None
            self._free_timeout_data = None
            celf._instances[_dbobj] = self
        else :
            dbus.dbus_server_unref(self._dbobj)
              # lose extra reference created by caller
        #end if
        return \
            self
    #end __new__

    def __del__(self) :
        if self._dbobj != None :
            dbus.dbus_server_unref(self._dbobj)
            self._dbobj = None
        #end if
    #end __del__

    @classmethod
    def listen(celf, address, error = None) :
        error, my_error = _get_error(error)
        result = dbus.dbus_server_listen(address.encode(), error._dbobj)
        my_error.raise_if_set()
        if result != None :
            result = celf(result)
        #end if
        return \
            result
    #end listen

    def disconnect(self) :
        dbus.dbus_server_disconnect(self._dbobj)
    #end disconnect

    @property
    def is_connected(self) :
        return \
            dbus.dbus_server_get_is_connected(self._dbobj) != 0
    #end is_connected

    @property
    def address(self) :
        c_result = dbus.dbus_server_get_address(self._dbobj)
        if c_result == None :
            raise DBusFailure("dbus_server_get_address failed")
        #end if
        result = ct.cast(c_result, ct.c_char_p).value.decode()
        dbus.dbus_free(c_result)
        return \
            result
    #end address

    @property
    def id(self) :
        c_result = dbus.dbus_server_get_id(self._dbobj)
        if c_result == None :
            raise DBusFailure("dbus_server_get_id failed")
        #end if
        result = ct.cast(c_result, ct.c_char_p).value.decode()
        dbus.dbus_free(c_result)
        return \
            result
    #end id

    def set_new_connection_function(self, function, data, free_data = None) :

        def wrap_function(self, conn, _data) :
            function(self, Connection(dbus.dbus_connection_ref(conn)), data)
              # even though this is a new connection, I still have to reference it
        #end wrap_function

        def wrap_free_data(_data) :
            free_data(data)
        #end wrap_free_data

    #begin set_new_connection_function
        self._new_connection_function = DBUS.NewConnectionFunction(wrap_function)
        if free_data != None :
            self._free_new_connection_data = DBUS.FreeFunction(wrap_free_data)
        else :
            self._free_new_connection_data = None
        #end if
        dbus.dbus_server_set_new_connection_function(self._dbobj, self._new_connection_function, None, self._free_new_connection_data)
    #end set_new_connection_function

    def set_watch_functions(self, add_function, remove_function, toggled_function, data, free_data = None) :

        def wrap_add_function(c_watch, _data) :
            return \
                add_function(Watch(c_watch), data)
        #end wrap_add_function

        def wrap_remove_function(c_watch, _data) :
            return \
                remove_function(Watch(c_watch), data)
        #end wrap_remove_function

        def wrap_toggled_function(c_watch, _data) :
            return \
                toggled_function(Watch(c_watch), data)
        #end wrap_toggled_function

        def wrap_free_data(_data) :
            free_data(data)
        #end wrap_free_data

    #begin set_watch_functions
        self._add_watch_function = DBUS.AddWatchFunction(wrap_add_function)
        self._remove_watch_function = DBUS.RemoveWatchFunction(wrap_remove_function)
        if toggled_function != None :
            self._toggled_watch_function = DBUS.WatchToggledFunction(wrap_toggled_function)
        else :
            self._toggled_watch_function = None
        #end if
        if free_data != None :
            self._free_watch_data = DBUS.FreeFunction(wrap_free_data)
        else :
            self._free_watch_data = None
        #end if
        if not dbus.dbus_server_set_watch_functions(self._dbobj, self._add_watch_function, self._remove_watch_function, self._toggled_watch_function, None, self._free_watch_data) :
            raise DBusFailure("dbus_server_set_watch_functions failed")
        #end if
    #end set_watch_functions

    def set_timeout_functions(self, add_function, remove_function, toggled_function, data, free_data = None) :

        def wrap_add_function(c_timeout, _data) :
            return \
                add_function(Timeout(c_timeout), data)
        #end wrap_add_function

        def wrap_remove_function(c_timeout, _data) :
            return \
                remove_function(Timeout(c_timeout), data)
        #end wrap_remove_function

        def wrap_toggled_function(c_timeout, _data) :
            return \
                toggled_function(Timeout(c_timeout), data)
        #end wrap_toggled_function

        def wrap_free_data(_data) :
            free_data(data)
        #end wrap_free_data

    #begin set_timeout_functions
        self._add_timeout_function = DBUS.AddTimeoutFunction(wrap_add_function)
        self._remove_timeout_function = DBUS.RemoveTimeoutFunction(wrap_remove_function)
        if toggled_function != None :
            self._toggled_timeout_function = DBUS.TimeoutToggledFunction(wrap_toggled_function)
        else :
            self._toggled_timeout_function = None
        #end if
        if free_data != None :
            self._free_timeout_data = DBUS.FreeFunction(wrap_free_data)
        else :
            self._free_timeout_data = None
        #end if
        if not dbus.dbus_server_set_timeout_functions(self._dbobj, self._add_timeout_function, self._remove_timeout_function, self._toggled_timeout_function, None, self._free_timeout_data) :
            raise DBusFailure("dbus_server_set_timeout_functions failed")
        #end if
    #end set_timeout_functions

    def set_auth_mechanisms(self, mechanisms) :
        nr_mechanisms = len(mechanisms)
        c_mechanisms = (ct.c_char_p * (nr_mechanisms + 1))()
        for i in range(nr_mechanisms) :
            c_mechanisms[i] = mechanisms[i].encode()
        #end if
        c_mechanisms[nr_mechanisms] = None # marks end of array
        if not dbus.dbus_server_set_auth_mechanisms(self._dbobj, c_mechanisms) :
            raise DBusFailure("dbus_server_set_auth_mechanisms failed")
        #end if
    #end set_auth_mechanisms

    # TODO: allocate/free slot (static methods)
    # TODO: get/set/data

    def attach_asyncio(self, loop = None) :
        "attaches this Server object to an asyncio event loop. If none is" \
        " specified, the default event loop (as returned from asyncio.get_event_loop()" \
        " is used.\n" \
        "\n" \
        "Note that you still need to attach a new_connection callback. This can call" \
        " Connection.attach_asyncio() to handle events for the connection as well."
        assert self.loop == None, "already attached to an event loop"
        self.loop = _loop_attach(self, loop, None)
    #end attach_asyncio

#end Server

class PreallocatedSend :
    "wrapper around a DBusPreallocatedSend object. Do not instantiate directly;" \
    " get from Connection.preallocate_send method."
    # <https://dbus.freedesktop.org/doc/api/html/group__DBusConnection.html>

    __slots__ = ("__weakref__", "_dbobj", "_parent", "_sent") # to forestall typos

    _instances = WeakValueDictionary()

    def __new__(celf, _dbobj, _parent) :
        self = celf._instances.get(_dbobj)
        if self == None :
            self = super().__new__(celf)
            self._dbobj = _dbobj
            self._parent = _parent
            self._sent = False
            celf._instances[_dbobj] = self
        else :
            assert self._parent == _parent
        #end if
        return \
            self
    #end __new__

    def __del__(self) :
        if self._dbobj != None :
            if not self._sent :
                dbus.dbus_connection_free_preallocated_send(self._parent._dbobj, self._dbobj)
            #end if
            self._dbobj = None
        #end if
    #end __del__

    def send(self, message) :
        "alternative to Connection.send_preallocated."
        if not isinstance(message, Message) :
            raise TypeError("message must be a Message")
        #end if
        assert not self._sent, "preallocated has already been sent"
        serial = ct.c_uint()
        dbus.dbus_connection_send_preallocated(self._parent._dbobj, self._dbobj, message._dbobj, ct.byref(serial))
        self._sent = True
        return \
            serial.value
    #end send

#end PreallocatedSend

class Message :
    "wrapper around a DBusMessage object. Do not instantiate directly; use one of the" \
    " new_xxx or copy methods, or Connection.pop_message or Connection.borrow_message."
    # <https://dbus.freedesktop.org/doc/api/html/group__DBusMessage.html>

    __slots__ = ("__weakref__", "_dbobj", "_conn", "_borrowed") # to forestall typos

    _instances = WeakValueDictionary()

    def __new__(celf, _dbobj) :
        self = celf._instances.get(_dbobj)
        if self == None :
            self = super().__new__(celf)
            self._dbobj = _dbobj
            self._conn = None
            self._borrowed = False
            celf._instances[_dbobj] = self
        else :
            dbus.dbus_message_unref(self._dbobj)
              # lose extra reference created by caller
        #end if
        return \
            self
    #end __new__

    def __del__(self) :
        if self._dbobj != None :
            assert not self._borrowed, "trying to dispose of borrowed message"
            dbus.dbus_message_unref(self._dbobj)
            self._dbobj = None
        #end if
    #end __del__

    @classmethod
    def new(celf, type) :
        "type is one of the MESSAGE_TYPE_xxx codes."
        result = dbus.dbus_message_new(type)
        if result == None :
            raise DBusFailure("dbus_message_new failed")
        #end if
        return \
            celf(result)
    #end new

    def new_error(self, name, message) :
        result = dbus.dbus_message_new_error(self._dbobj, name.encode(), (lambda : None, lambda : message.encode())[message != None]())
        if result == None :
            raise DBusFailure("dbus_message_new_error failed")
        #end if
        return \
            type(self)(result)
    #end new_error

    # probably not much point trying to use new_error_printf

    @classmethod
    def new_method_call(celf, destination, path, iface, method) :
        result = dbus.dbus_message_new_method_call \
          (
            (lambda : None, lambda : destination.encode())[destination != None](),
            (lambda : None, lambda : path.encode())[path != None](),
            (lambda : None, lambda : iface.encode())[iface != None](),
            (lambda : None, lambda : method.encode())[method != None](),
          )
        if result == None :
            raise DBusFailure("dbus_message_new_method_call failed")
        #end if
        return \
            celf(result)
    #end new_method_call

    def new_method_return(self) :
        result = dbus.dbus_message_new_method_return(self._dbobj)
        if result == None :
            raise DBusFailure("dbus_message_new_method_return failed")
        #end if
        return \
            type(self)(result)
    #end new_method_return

    @classmethod
    def new_signal(celf, path, iface, name) :
        result = dbus.dbus_message_new_signal(path.encode(), iface.encode(), name.encode())
        if result == None :
            raise DBusFailure("dbus_message_new_signal failed")
        #end if
        return \
            celf(result)
    #end new_signal

    def copy(self) :
        result = dbus.dbus_message_copy(self._dbobj)
        if result == None :
            raise DBusFailure("dbus_message_copy failed")
        #end if
        return \
            type(self)(result)
    #end copy

    @property
    def type(self) :
        return \
            dbus.dbus_message_get_type(self._dbobj)
    #end type

    # NYI append_args, get_args -- probably not useful, use my
    # objects and append_objects convenience methods (below) instead

    class Iter :
        "for iterating over the arguments in a Message, whether for reading or appending." \
        " Do not instantiate directly; get from Message.iter_init, Message.Iter.recurse," \
        " Message.iter_init_append or Message.Iter.open_container.\n" \
        "\n" \
        "When reading, you can use this as a Python iterator, in a for-loop, passing" \
        " it to the next() built-in function etc. Do not mix such usage with calls to" \
        " the has_next() and next() methods."

        __slots__ = ("_dbobj", "_parent", "_nulliter", "_writing", "_startiter") # to forestall typos

        def __init__(self, _parent, _writing) :
            self._dbobj = DBUS.MessageIter()
            self._parent = _parent
            self._nulliter = False
            self._writing = _writing
            self._startiter = True
        #end __init__

        @property
        def has_next(self) :
            assert not self._writing, "cannot read from write iterator"
            return \
                dbus.dbus_message_iter_has_next(self._dbobj)
        #end has_next

        def next(self) :
            assert not self._writing, "cannot read from write iterator"
            if self._nulliter or not dbus.dbus_message_iter_next(self._dbobj) :
                raise StopIteration("end of message iterator")
            #end if
            self._startiter = False
            return \
                self
        #end next

        def __iter__(self) :
            assert not self._writing, "cannot read from write iterator"
            return \
                self
        #end __iter__

        def __next__(self) :
            assert not self._writing, "cannot read from write iterator"
            if self._nulliter :
                raise StopIteration("empty message iterator")
            else :
                if self._startiter :
                    self._startiter = False
                else :
                    self.next()
                #end if
            #end if
            return \
                self
        #end __next__

        @property
        def arg_type(self) :
            assert not self._writing, "cannot read from write iterator"
            return \
                dbus.dbus_message_iter_get_arg_type(self._dbobj)
        #end arg_type

        @property
        def element_type(self) :
            assert not self._writing, "cannot read from write iterator"
            return \
                dbus.dbus_message_iter_get_element_type(self._dbobj)
        #end element_type

        def recurse(self) :
            assert not self._writing, "cannot read from write iterator"
            subiter = type(self)(self, False)
            dbus.dbus_message_iter_recurse(self._dbobj, subiter._dbobj)
            return \
                subiter
        #end recurse

        @property
        def signature(self) :
            assert not self._writing, "cannot read from write iterator"
            c_result = dbus.dbus_message_iter_get_signature(self._dbobj)
            if c_result == None :
                raise DBusFailure("dbus_message_iter_get_signature failure")
            #end if
            result = ct.cast(c_result, ct.c_char_p).value.decode()
            dbus.dbus_free(c_result)
            return \
                result
        #end signature

        @property
        def basic(self) :
            assert not self._writing, "cannot read from write iterator"
            argtype = self.arg_type
            c_result_type = DBUS.basic_to_ctypes[argtype]
            c_result = c_result_type()
            dbus.dbus_message_iter_get_basic(self._dbobj, ct.byref(c_result))
            if c_result_type == ct.c_char_p :
                result = c_result.value.decode()
            else :
                result = c_result.value
            #end if
            if argtype in DBUS.basic_subclasses :
                result = DBUS.basic_subclasses[argtype](result)
            #end if
            return \
                result
        #end basic

        @property
        def object(self) :
            "returns the current iterator item as a Python object. Will recursively" \
            " process container objects."
            assert not self._writing, "cannot read from write iterator"
            argtype = self.arg_type
            if argtype in DBUS.basic_to_ctypes :
                result = self.basic
            elif argtype == DBUS.TYPE_ARRAY :
                if self.element_type == DBUS.TYPE_DICT_ENTRY :
                    result = {}
                    subiter = self.recurse()
                    while True :
                        entry = next(subiter, None)
                        if entry == None :
                            break
                        assert entry.arg_type == DBUS.TYPE_DICT_ENTRY
                        key, value = tuple(x.object for x in entry.recurse())
                        result[key] = value
                    #end while
                else :
                    result = list(x.object for x in self.recurse())
                #end if
            elif argtype == DBUS.TYPE_STRUCT :
                result = list(x.object for x in self.recurse())
            elif argtype == DBUS.TYPE_VARIANT :
                subiter = self.recurse()
                result = next(subiter, None).object
            else :
                raise RuntimeError("unrecognized argtype %d" % argtype)
            #end if
            return \
                result
        #end object

        @property
        def element_count(self) :
            assert not self._writing, "cannot read from write iterator"
            return \
                dbus.dbus_message_iter_get_element_count(self._dbobj)
        #end element_count

        @property
        def fixed_array(self) :
            assert not self._writing, "cannot read from write iterator"
            c_element_type = DBUS.basic_to_ctypes[self.element_type]
            c_result = ct.POINTER(c_element_type)()
            c_nr_elts = ct.c_int()
            dbus.dbus_message_iter_get_fixed_array(self._dbobj, ct.byref(c_result), ct.byref(c_nr_elts))
            result = []
            for i in range(c_nr_elts.value) :
                elt = c_result[i]
                if c_element_type == ct.c_char_p :
                    elt = elt.value.decode()
                else :
                    elt = elt.value
                #end if
                result.append(elt)
            #end for
            return \
                result
        #end fixed_array

        def append_basic(self, type, value) :
            assert self._writing, "cannot write to read iterator"
            if type in DBUS.int_convert :
                value = DBUS.int_convert[type](value)
            #end if
            c_type = DBUS.basic_to_ctypes[type]
            if c_type == ct.c_char_p :
                value = value.encode()
            #end if
            c_value = c_type(value)
            if not dbus.dbus_message_iter_append_basic(self._dbobj, type, ct.byref(c_value)) :
                raise DBusFailure("dbus_message_iter_append_basic failed")
            #end if
            return \
                self
        #end append_basic

        def append_fixed_array(self, element_type, values) :
            assert self._writing, "cannot write to read iterator"
            c_elt_type = DBUS.basic_to_ctypes[element_type]
            nr_elts = len(values)
            c_arr = (nr_elts * c_elt_type)()
            for i in range(nr_elts) :
                if c_elt_type == ct.c_char_p :
                    c_arr[i] = values[i].encode()
                else :
                    c_arr[i] = values[i]
                #end if
            #end for
            c_arr_ptr = ct.pointer(c_arr)
            if not dbus.dbus_message_iter_append_fixed_array(self._dbobj, element_type, ct.byref(c_arr_ptr), nr_elts) :
                raise DBusFailure("dbus_message_iter_append_fixed_array failed")
            #end if
            return \
                self
        #end append_fixed_array

        def open_container(self, type, contained_signature) :
            assert self._writing, "cannot write to read iterator"
            if contained_signature != None :
                c_sig = contained_signature.encode()
            else :
                c_sig = None
            #end if
            subiter = __builtins__["type"](self)(self, True)
            if not dbus.dbus_message_iter_open_container(self._dbobj, type, c_sig, subiter._dbobj) :
                raise DBusFailure("dbus_message_iter_open_container failed")
            #end if
            return \
                subiter
        #end open_container

        def close(self) :
            assert self._writing, "cannot write to read iterator"
            assert self._parent != None, "cannot close top-level iterator"
            if not dbus.dbus_message_iter_close_container(self._parent._dbobj, self._dbobj) :
                raise DBusFailure("dbus_message_iter_close_container failed")
            #end if
            return \
                self._parent
        #end close

        def abandon(self) :
            assert self._writing, "cannot write to read iterator"
            assert self._parent != None, "cannot abandon top-level iterator"
            dbus.dbus_message_iter_abandon_container(self._parent._dbobj, self._dbobj)
            return \
                self._parent
        #end abandon

    #end Iter

    def iter_init(self) :
        iter = self.Iter(None, False)
        if dbus.dbus_message_iter_init(self._dbobj, iter._dbobj) == 0 :
            iter._nulliter = True
        #end if
        return \
             iter
    #end iter_init

    @property
    def objects(self) :
        for iter in self.iter_init() :
            yield iter.object
        #end for
    #end objects

    def iter_init_append(self) :
        iter = self.Iter(None, True)
        dbus.dbus_message_iter_init_append(self._dbobj, iter._dbobj)
        return \
            iter
    #end iter_init_append

    def append_objects(self, signature, val) :
        "interprets Python value val (which should be a sequence of objects) according" \
        " to signature and appends converted items to the message args."

        def append_sub(val, sigiter, appenditer) :
            index = 0
            for sigelt in sigiter :
                elttype = sigelt.current_type
                elt = val[index]
                if elttype in DBUS.basic_to_ctypes :
                    appenditer.append_basic(elttype, elt)
                elif elttype == DBUS.TYPE_ARRAY :
                    if sigiter.element_type == DBUS.TYPE_DICT_ENTRY :
                        if not isinstance(elt, dict) :
                            raise TypeError("dict expected for array of dict entry")
                        #end if
                        subsig = sigiter.recurse()
                        subiter = appenditer.open_container(elttype, subsig.signature)
                        for key in sorted(elt) : # might as well insert in some kind of predictable order
                            value = elt[key]
                            subsubiter = subiter.open_container(DBUS.TYPE_DICT_ENTRY, None)
                            subsubsig = subsig.recurse()
                            assert subsubsig.current_type in DBUS.basic_to_ctypes, "dict key type must be basic type"
                            append_sub([key, value], subsubsig, subsubiter)
                            subsubiter.close()
                        #end for
                        subiter.close()
                    else :
                        # append 0 or more elements matching sigiter.element_type
                        subiter = appenditer.open_container(elttype, sigiter.recurse().signature)
                        if not isinstance(elt, (tuple, list)) :
                            raise TypeError("expecting sequence of values for array")
                        #end if
                        for subval in elt :
                            subsig = sigiter.recurse()
                            append_sub([subval], subsig, subiter)
                        #end for
                        subiter.close()
                    #end if
                elif elttype == DBUS.TYPE_STRUCT :
                    subiter = appenditer.open_container(elttype, None)
                    append_sub(elt, sigiter.recurse(), subiter)
                    subiter.close()
                elif elttype == DBUS.TYPE_VARIANT :
                    if not isinstance(elt, (list, tuple)) or len(elt) != 2 :
                        raise TypeError("sequence of 2 elements expected for variant")
                    #end if
                    subiter = appenditer.open_container(elttype, elt[0])
                    append_sub([elt[1]], SignatureIter.init(elt[0]), subiter)
                    subiter.close()
                else :
                    raise RuntimeError("unrecognized type %s" % bytes((elttype,)))
                #end if
                index += 1
            #end for
            assert index == len(val), "leftover unappended objects"
        #end append_sub

    #begin append_objects
        if not isinstance(val, (tuple, list)) :
            val = [val]
        #end if
        append_sub(val, SignatureIter.init(signature), self.iter_init_append())
    #end append_objects

    @property
    def no_reply(self) :
        return \
            dbus.dbus_message_get_no_reply(self._dbobj) != 0
    #end no_reply

    @no_reply.setter
    def no_reply(self, no_reply) :
        dbus.dbus_message_set_no_reply(self._dbobj, no_reply)
    #end no_reply

    @property
    def auto_start(self) :
        return \
            dbus.dbus_message_get_auto_start(self._dbobj) != 0
    #end auto_start

    @auto_start.setter
    def auto_start(self, auto_start) :
        dbus.dbus_message_set_auto_start(self._dbobj, auto_start)
    #end auto_start

    @property
    def path(self) :
        result = dbus.dbus_message_get_path(self._dbobj)
        if result != None :
            result = result.decode()
        #end if
        return \
            result
    #end path

    @path.setter
    def path(self, object_path) :
        if not dbus.dbus_message_set_path(self._dbobj, (lambda : None, lambda : object_path.encode())[object_path != None]()) :
            raise DBusFailure("dbus_message_set_path failed")
        #end if
    #end path

    @property
    def path_decomposed(self) :
        path = ct.POINTER(ct.c_char_p)()
        if not dbus.dbus_message_get_path_decomposed(self._dbobj, ct.byref(path)) :
            raise DBusFailure("dbus_message_get_path_decomposed failed")
        #end if
        if bool(path) :
            result = []
            i = 0
            while True :
                entry = path[i]
                if entry == None :
                    break
                result.append(entry.decode())
                i += 1
            #end while
            dbus.dbus_free_string_array(path)
        else :
            result = None
        #end if
        return \
            result
    #end path_decomposed

    @property
    def interface(self) :
        result = dbus.dbus_message_get_interface(self._dbobj)
        if result != None :
            result = result.decode()
        #end if
        return \
            result
    #end interface

    @interface.setter
    def interface(self, iface) :
        if not dbus.dbus_message_set_interface(self._dbobj, (lambda : None, lambda : iface.encode())[iface != None]()) :
            raise DBusFailure("dbus_message_set_interface failed")
        #end if
    #end interface

    def has_interface(self, iface) :
        return \
            dbus.dbus_message_has_interface(self._dbobj, iface.encode()) != 0
    #end has_interface

    @property
    def member(self) :
        result = dbus.dbus_message_get_member(self._dbobj)
        if result != None :
            result = result.decode()
        #end if
        return \
            result
    #end member

    @member.setter
    def member(self, member) :
        if not dbus.dbus_message_set_member(self._dbobj, (lambda : None, lambda : member.encode())[member != None]()) :
            raise DBusFailure("dbus_message_set_member failed")
        #end if
    #end member

    def has_member(self, member) :
        return \
            dbus.dbus_message_has_member(self._dbobj, member.encode()) != 0
    #end has_member

    @property
    def error_name(self) :
        result = dbus.dbus_message_get_error_name(self._dbobj)
        if result != None :
            result = result.decode()
        #end if
        return \
            result
    #end error_name

    @error_name.setter
    def error_name(self, error_name) :
        if not dbus.dbus_message_set_error_name(self._dbobj, (lambda : None, lambda : error_name.encode())[error_name != None]()) :
            raise DBusFailure("dbus_message_set_error_name failed")
        #end if
    #end error_name

    @property
    def destination(self) :
        result = dbus.dbus_message_get_destination(self._dbobj)
        if result != None :
            result = result.decode()
        #end if
        return \
            result
    #end destination

    @destination.setter
    def destination(self, destination) :
        if not dbus.dbus_message_set_destination(self._dbobj, (lambda : None, lambda : destination.encode())[destination != None]()) :
            raise DBusFailure("dbus_message_set_destination failed")
        #end if
    #end destination

    @property
    def sender(self) :
        result = dbus.dbus_message_get_sender(self._dbobj)
        if result != None :
            result = result.decode()
        #end if
        return \
            result
    #end sender

    @sender.setter
    def sender(self, sender) :
        if not dbus.dbus_message_set_sender(self._dbobj, (lambda : None, lambda : sender.encode())[sender != None]()) :
            raise DBusFailure("dbus_message_set_sender failed")
        #end if
    #end sender

    @property
    def signature(self) :
        result = dbus.dbus_message_get_signature(self._dbobj)
        if result != None :
            result = result.decode()
        #end if
        return \
            result
    #end signature

    def is_method_call(self, iface, method) :
        return \
            dbus.dbus_message_is_method_call(self._dbobj, iface.encode(), method.encode()) != 0
    #end is_method_call

    def is_signal(self, iface, signal_name) :
        return \
            dbus.dbus_message_is_signal(self._dbobj, iface.encode(), signal_name.encode()) != 0
    #end is_signal

    def is_error(self, iface, error_name) :
        return \
            dbus.dbus_message_is_error(self._dbobj, error_name.encode()) != 0
    #end is_error

    def has_destination(self, iface, destination) :
        return \
            dbus.dbus_message_has_destination(self._dbobj, destination.encode()) != 0
    #end has_destination

    def has_sender(self, iface, sender) :
        return \
            dbus.dbus_message_has_sender(self._dbobj, sender.encode()) != 0
    #end has_sender

    def has_signature(self, iface, signature) :
        return \
            dbus.dbus_message_has_signature(self._dbobj, signature.encode()) != 0
    #end has_signature

    def set_error(self, error) :
        "fills in error if this is an error message, else does nothing. Returns" \
        " whether it was an error message or not."
        if not isinstance(error, Error) :
            raise TypeError("error must be an Error")
        #end if
        return \
            dbus.dbus_set_error_from_message(error._dbobj, self._dbobj) != 0
    #end set_error

    @property
    def contains_unix_fds(self) :
        return \
            dbus.dbus_message_contains_unix_fds(self._dbobj) != 0
    #end contains_unix_fds

    @property
    def serial(self) :
        return \
            dbus.dbus_message_get_serial(self._dbobj)
    #end serial

    @serial.setter
    def serial(self, serial) :
        dbus.dbus_message_set_serial(self._dbobj, serial)
    #end serial

    @property
    def reply_serial(self) :
        return \
            dbus.dbus_message_get_reply_serial(self._dbobj)
    #end reply_serial

    @reply_serial.setter
    def reply_serial(self, serial) :
        if not dbus.dbus_message_set_reply_serial(self._dbobj, serial) :
            raise DBusFailure("dbus_message_set_reply_serial failed")
        #end if
    #end serial

    def lock(self) :
        dbus.dbus_message_lock(self._dbobj)
    #end lock

    def return_borrowed(self) :
        assert self._borrowed and self._conn != None
        dbus.dbus_connection_return_message(self._conn._dbobj, self._dbobj)
        self._borrowed = False
    #end return_borrowed

    def steal_borrowed(self) :
        assert self._borrowed and self._conn != None
        dbus.dbus_connection_steal_borrowed_message(self._conn._dbobj, self._dbobj)
        self._borrowed = False
        return \
            self
    #end steal_borrowed

    # TODO: allocate/free data slot -- static methods
    #    (freeing slot can set passed-in var to -1 on actual free; do I care?)
    # TODO: set/get data

    @staticmethod
    def type_from_string(type_str) :
        "returns a MESSAGE_TYPE_xxx value."
        return \
            dbus.dbus_message_type_from_string(type_str.encode())
    #end type_from_string

    @staticmethod
    def type_to_string(type) :
        "type is a MESSAGE_TYPE_xxx value."
        return \
            dbus.dbus_message_type_to_string(type).decode()
    #end type_to_string

    def marshal(self) :
        buf = ct.POINTER(ct.c_ubyte)()
        nr_bytes = ct.c_int()
        if not dbus.dbus_message_marshal(self._dbobj, ct.byref(buf), ct.byref(nr_bytes)) :
            raise DBusFailure("dbus_message_marshal failed")
        #end if
        result = bytearray(nr_bytes.value)
        ct.memmove \
          (
            ct.addressof((ct.c_ubyte * nr_bytes.value).from_buffer(result)),
            buf,
            nr_bytes.value
          )
        dbus.dbus_free(buf)
        return \
            result
    #end marshal

    @classmethod
    def demarshal(celf, buf, error = None) :
        error, my_error = _get_error(error)
        if isinstance(buf, bytes) :
            baseadr = ct.cast(buf, ct.c_void_p).value
        elif isinstance(buf, bytearray) :
            baseadr = ct.addressof((ct.c_ubyte * len(buf)).from_buffer(buf))
        elif isinstance(buf, array.array) and buf.typecode == "B" :
            baseadr = buf.buffer_info()[0]
        else :
            raise TypeError("buf is not bytes, bytearray or array.array of bytes")
        #end if
        msg = dbus.dbus_message_demarshal(baseadr, len(buf), error._dbobj)
        my_error.raise_if_set()
        if msg != None :
            msg = celf(msg)
        #end if
        return \
            msg
    #end demarshal

    @classmethod
    def demarshal_bytes_needed(celf, buf) :
        if isinstance(buf, bytes) :
            baseadr = ct.cast(buf, ct.c_void_p).value
        elif isinstance(buf, bytearray) :
            baseadr = ct.addressof((ct.c_ubyte * len(buf)).from_buffer(buf))
        elif isinstance(buf, array.array) and buf.typecode == "B" :
            baseadr = buf.buffer_info()[0]
        else :
            raise TypeError("buf is not bytes, bytearray or array.array of bytes")
        #end if
        return \
            dbus.dbus_message_demarshal_bytes_needed(baseadr, len(buf))
    #end demarshal_bytes_needed

    @property
    def interactive_authorization(self) :
        return \
            dbus.dbus_message_get_interactive_authorization(self._dbobj)
    #end interactive_authorization

    @interactive_authorization.setter
    def interactive_authorization(self, allow) :
        dbus.dbus_message_set_interactive_authorization(self._dbobj, allow)
    #end interactive_authorization

#end Message

class PendingCall :
    "wrapper around a DBusPendingCall object."
    # <https://dbus.freedesktop.org/doc/api/html/group__DBusPendingCall.html>

    __slots__ = ("__weakref__", "_dbobj", "_wrap_notify", "_wrap_free") # to forestall typos

    _instances = WeakValueDictionary()

    def __new__(celf, _dbobj) :
        self = celf._instances.get(_dbobj)
        if self == None :
            self = super().__new__(celf)
            self._dbobj = _dbobj
            self._wrap_notify = None
            self._wrap_free = None
            celf._instances[_dbobj] = self
        else :
            dbus.dbus_pending_call_unref(self._dbobj)
              # lose extra reference created by caller
        #end if
        return \
            self
    #end __new__

    def __del__(self) :
        if self._dbobj != None :
            dbus.dbus_pending_call_unref(self._dbobj)
            self._dbobj = None
        #end if
    #end __del__

    def set_notify(self, function, user_data, free_user_data = None) :

        def _wrap_notify(c_pending, c_user_data) :
            function(self, user_data)
        #end _wrap_notify

        def _wrap_free(c_user_data) :
            free_user_data(user_data)
        #end _wrap_free

    #begin set_notify
        if function != None :
            self._wrap_notify = DBUS.PendingCallNotifyFunction(_wrap_notify)
        else :
            self._wrap_notify = None
        #end if
        if free_user_data != None :
            self._wrap_free = DBUS.FreeFunction(_wrap_free)
        else :
            self._wrap_free = None
        #end if
        if not dbus.dbus_pending_call_set_notify(self._dbobj, self._wrap_notify, None, self._wrap_free) :
            raise DBusFailure("dbus_pending_call_set_notify failed")
        #end if
    #end set_notify

    def cancel(self) :
        dbus.dbus_pending_call_cancel(self._dbobj)
    #end cancel

    @property
    def completed(self) :
        return \
            dbus.dbus_pending_call_get_completed(self._dbobj) != 0
    #end completed

    def steal_reply(self) :
        result = dbus.dbus_pending_call_steal_reply(self._dbobj)
        if result != None :
            result = Message(result)
        #end if
        return \
            result
    #end steal_reply

    def block(self) :
        dbus.dbus_pending_call_block(self._dbobj)
    #end block

    # TODO: data slots (static methods), get/set data

#end PendingCall

class Error :
    "wrapper around a DBusError object. You can create one by calling the init method."
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

    @classmethod
    def init(celf) :
        "for consistency with other classes that don’t want caller to instantiate directly."
        return \
            celf()
    #end init

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

    def raise_if_set(self) :
        if self.is_set :
            raise DBusError(self.name, self.message)
        #end if
    #end raise_if_set

    def set_from_message(self, message) :
        "fills in this Error object from message if it is an error message." \
        " Returns whether it was or not."
        if not isinstance(message, Message) :
            raise TypeError("message must be a Message")
        #end if
        return \
            dbus.dbus_set_error_from_message(self._dbobj, message._dbobj) != 0
    #end set_from_message

#end Error

class AddressEntries :
    "wrapper for arrays of DBusAddressEntry values. Do not instantiate directly;" \
    " get from parse. This object behaves like an array; you can obtain the number" \
    " of elements with len(), and use array subscripting to access the elements."
    # <https://dbus.freedesktop.org/doc/api/html/group__DBusAddress.html>

    __slots__ = ("__weakref__", "_dbobj", "_nrelts") # to forestall typos

    def __init__(self, _dbobj, _nrelts) :
        self._dbobj = _dbobj
        self._nrelts = _nrelts
    #end __init__

    def __del__(self) :
        if self._dbobj != None :
            dbus.dbus_address_entries_free(self._dbobj)
            self._dbobj = None
        #end if
    #end __del__

    class Entry :
        "a single AddressEntry. Do not instantiate directly; get from AddressEntries[]." \
        " This object behaves like a dictionary in that you can use keys to get values;" \
        " however, there is no libdbus API to check what keys are present; unrecognized" \
        " keys return a value of None."

        __slots__ = ("_dbobj", "_parent", "_index") # to forestall typos

        def __init__(self, _parent, _index) :
            self._dbobj = _parent._dbobj
            self._parent = weak_ref(_parent)
            self._index = _index
        #end __init__

        @property
        def method(self) :
            assert self._parent() != None, "AddressEntries object has gone"
            result = dbus.dbus_address_entry_get_method(self._dbobj[self._index])
            if result != None :
                result = result.decode()
            #end if
            return \
                result
        #end method

        def get_value(self, key) :
            assert self._parent() != None, "AddressEntries object has gone"
            c_result = dbus.dbus_address_entry_get_value(self._dbobj[self._index], key.encode())
            if c_result != None :
                result = c_result.decode()
            else :
                result = None
            #end if
            return \
                result
        #end get_value
        __getitem__ = get_value

    #end Entry

    @classmethod
    def parse(celf, address, error = None) :
        error, my_error = _get_error(error)
        c_result = ct.POINTER(ct.c_void_p)()
        nr_elts = ct.c_int()
        if not dbus.dbus_parse_address(address.encode(), ct.byref(c_result), ct.byref(nr_elts), error._dbobj) :
            c_result.contents = None
            nr_elts.value = 0
        #end if
        my_error.raise_if_set()
        if c_result.contents != None :
            result = celf(c_result, nr_elts.value)
        else :
            result = None
        #end if
        return \
            result
    #end parse

    def __len__(self) :
        return \
            self._nrelts
    #end __len__

    def __getitem__(self, index) :
        if not isinstance(index, int) or index < 0 or index >= self._nrelts :
            raise IndexError("AddressEntries[%d] out of range" % index)
        #end if
        return \
            type(self).Entry(self, index)
    #end __getitem__

#end AddressEntries

def address_escape_value(value) :
    c_result = dbus.dbus_address_escape_value(value.encode())
    if c_result == None :
        raise DBusFailure("dbus_address_escape_value failed")
    #end if
    result = ct.cast(c_result, ct.c_char_p).value.decode()
    dbus.dbus_free(c_result)
    return \
        result
#end address_escape_value

def address_unescape_value(value, error = None) :
    error, my_error = _get_error(error)
    c_result = dbus.dbus_address_unescape_value(value.encode(), error._dbobj)
    my_error.raise_if_set()
    if c_result != None :
        result = ct.cast(c_result, ct.c_char_p).value.decode()
        dbus.dbus_free(c_result)
    elif not error.is_set :
        raise DBusFailure("dbus_address_unescape_value failed")
    else :
        result = None
    #end if
    return \
        result
#end address_unescape_value

class SignatureIter :
    "wraps a DBusSignatureIter object. Do not instantiate directly; use the init" \
    " and recurse methods."
    # <https://dbus.freedesktop.org/doc/api/html/group__DBusSignature.html>

    __slots__ = ("_dbobj", "_signature", "_startiter") # to forestall typos

    @classmethod
    def init(celf, signature) :
        self = celf()
        self._signature = ct.c_char_p(signature.encode()) # need to ensure storage stays valid
        dbus.dbus_signature_iter_init(self._dbobj, self._signature)
        return \
            self
    #end init

    def __init__(self) :
        self._dbobj = DBUS.SignatureIter()
        self._signature = None # caller will set as necessary
        self._startiter = True
    #end __init__

    def __iter__(self) :
        return \
            self
    #end __iter__

    def __next__(self) :
        if self._startiter :
            self._startiter = False
        else :
            self.next()
        #end if
        return \
            self
    #end __next__

    def next(self) :
        if dbus.dbus_signature_iter_next(self._dbobj) == 0 :
            raise StopIteration("end of signature iterator")
        #end if
        self._startiter = False
        return \
            self
    #end next

    def recurse(self) :
        subiter = type(self)()
        dbus.dbus_signature_iter_recurse(self._dbobj, subiter._dbobj)
        return \
            subiter
    #end recurse

    @property
    def current_type(self) :
        return \
            dbus.dbus_signature_iter_get_current_type(self._dbobj)
    #end current_type

    @property
    def signature(self) :
        c_result = dbus.dbus_signature_iter_get_signature(self._dbobj)
        result = ct.cast(c_result, ct.c_char_p).value.decode()
        dbus.dbus_free(c_result)
        return \
            result
    #end signature

    @property
    def element_type(self) :
        return \
            dbus.dbus_signature_iter_get_element_type(self._dbobj)
    #end element_type

#end SignatureIter

def signature_validate(signature, error = None) :
    "is signature a valid sequence of zero or more complete types."
    error, my_error = _get_error(error)
    result = dbus.dbus_signature_validate(signature.encode(), error._dbobj) != 0
    my_error.raise_if_set()
    return \
        result
#end signature_validate

def signature_validate_single(signature, error = None) :
    "is signature a single valid type."
    error, my_error = _get_error(error)
    result = dbus.dbus_signature_validate_single(signature.encode(), error._dbobj) != 0
    my_error.raise_if_set()
    return \
        result
#end signature_validate_single

def type_is_valid(typecode) :
    return \
        dbus.dbus_type_is_valid(typecode) != 0
#end type_is_valid

def type_is_basic(typecode) :
    return \
        dbus.dbus_type_is_basic(typecode) != 0
#end type_is_basic

def type_is_container(typecode) :
    return \
        dbus.dbus_type_is_container(typecode) != 0
#end type_is_container

def type_is_fixed(typecode) :
    return \
        dbus.dbus_type_is_fixed(typecode) != 0
#end type_is_fixed

# syntax validation <https://dbus.freedesktop.org/doc/api/html/group__DBusSyntax.html>

def validate_path(path, error = None) :
    error, my_error = _get_error(error)
    result = dbus.dbus_validate_path(path.encode(), error._dbobj) != 0
    my_error.raise_if_set()
    return \
        result
#end validate_path

def validate_interface(name, error = None) :
    error, my_error = _get_error(error)
    result = dbus.dbus_validate_interface(name.encode(), error._dbobj) != 0
    my_error.raise_if_set()
    return \
        result
#end validate_interface

def validate_member(name, error = None) :
    error, my_error = _get_error(error)
    result = dbus.dbus_validate_member(name.encode(), error._dbobj) != 0
    my_error.raise_if_set()
    return \
        result
#end validate_member

def validate_error_name(name, error = None) :
    error, my_error = _get_error(error)
    result = dbus.dbus_validate_error_name(name.encode(), error._dbobj) != 0
    my_error.raise_if_set()
    return \
        result
#end validate_error_name

def validate_bus_name(name, error = None) :
    error, my_error = _get_error(error)
    result = dbus.dbus_validate_bus_name(name.encode(), error._dbobj) != 0
    my_error.raise_if_set()
    return \
        result
#end validate_bus_name

def validate_utf8(alleged_utf8, error = None) :
    "alleged_utf8 must be null-terminated bytes."
    error, my_error = _get_error(error)
    result = dbus.dbus_validate_utf8(alleged_utf8, error._dbobj) != 0
    my_error.raise_if_set()
    return \
        result
#end validate_utf8

#+
# Cleanup
#-

def _atexit() :
    # disable all __del__ methods at process termination to avoid segfaults
    for cls in Connection, Server, PreallocatedSend, Message, PendingCall, Error, AddressEntries :
        delattr(cls, "__del__")
    #end for
#end _atexit
atexit.register(_atexit)
del _atexit
