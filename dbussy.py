#+
# Pure-Python binding for parts of D-Bus <https://www.freedesktop.org/wiki/Software/dbus/>,
# built around libdbus.
#
# libdbus API: <https://dbus.freedesktop.org/doc/api/html/index.html>.
#-

import ctypes as ct
from weakref import \
    WeakValueDictionary
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

#end DBUS

#+
# Library prototypes
#-

# from dbus-connection.h
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
dbus.dbus_connection_send_with_reply_and_block.argtypes = (ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_int, DBUS.ErrorPtr)
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
dbus.dbus_connection_set_watch_functions.argtypes = (ct.c_void_p, DBUS.AddWatchFunction, DBUS.RemoveWatchFunction, DBUS.WatchToggledFunction, ct.c_void_p, DBUS.FreeFunction)
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
dbus.dbus_watch_get_enabled.argtypes = (ct.c_void_p, ct.c_uint)

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
dbus.dbus_message_demarshal.argtypes = (ct.c_char_p, ct.c_int, DBUS.ErrorPtr)
dbus.dbus_message_demarshal_bytes_needed.restype = ct.c_int
dbus.dbus_message_demarshal_bytes_needed.argtypes = (ct.c_char_p, ct.c_int)
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

#+
# High-level stuff follows
#-

class ObjectPathVTable :

    __slots__ = \
      (
        "_dbobj",
        # need to keep references to ctypes-wrapped functions
        # so they don't disappear prematurely:
        "_wrap_unregister_func",
        "_wrap_message_func",
      ) # to forestall typos

    def __init__(self, *, unregister = None, message = None) :
        self._dbobj = DBUS.ObjectPathVTable()
        self._wrap_unregister_func = None
        self._wrap_message_func = None
        if unregister != None :
            self.set_unregister(unregister)
        #end if
        if message != None :
            self.set_message(message)
        #end if
    #end __init__

    def set_unregister(self, unregister = None) :

        def wrap_unregister(c_conn, user_data) :
            unregister(Connection(dbus.dbus_connection_ref(c_conn)), user_data)
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

    def set_message(self, message = None) :

        def wrap_message(c_conn, c_message, user_data) :
            return \
                message(Connection(dbus.dbus_connection_ref(c_conn)), Message(c_message), user_data)
        #end wrap_message

    #begin set_message
        if message != None :
            self._wrap_message_func = DBUS.ObjectPathMessageFunction(wrap_message)
        else :
            self._wrap_message_func = None
        #end if
        self._dbobj.message = self._wrap_message_func
        return \
            self
    #end set_message

#end ObjectPathVTable

class _DummyError :

    def raise_if_set(self) :
        pass
    #end raise_if_set

#end _DummyError

def _get_error(error) :
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

class Connection :
    "wrapper around a DBusConnection object. Do not instantiate directly; use the open" \
    " or bus_get methods."
    # <https://dbus.freedesktop.org/doc/api/html/group__DBusConnection.html>

    __slots__ = ("__weakref__", "_dbobj",) # to forestall typos

    _instances = WeakValueDictionary()

    def __new__(celf, _dbobj) :
        self = celf._instances.get(_dbobj)
        if self == None :
            self = super().__new__(celf)
            self._dbobj = _dbobj
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
        result = (dbus.dbus_connection_open, dbus.dbus_connection_open_private)[private](address, error._dbobj)
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
            raise RuntimeError("dbus_connection_preallocate_send failed")
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
            raise RuntimeError("dbus_connection_send failed")
        #end if
        return \
            serial.value
    #end send

    def send_with_reply(self, message, timeout) :
        if not isinstance(message, Message) :
            raise TypeError("message must be a Message")
        #end if
        pending_call = ct.c_void_p()
        if not dbus.dbus_connection_send_with_reply(self._dbobj, message._dbobj, ct.byref(pending_call), timeout) :
            raise RuntimeError("dbus_connection_send_with_reply failed")
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
        reply = dbus.dbus_connection_send_with_reply_and_block(self._dbobj, message._dbobj, timeout, error._dbobj)
        my_error.raise_if_set()
        if reply != None :
            result = Message(reply)
        else :
            result = None
        #end if
        return \
            result
    #end send_with_reply_and_block

    def flush(self) :
        dbus.dbus_connection_flush(self._dbobj)
    #end flush

    def read_write_dispatch(self, timeout) :
        return \
            dbus.dbus_connection_read_write_dispatch(self._dbobj, timeout) != 0
    #end read_write_dispatch

    def read_write(self, timeout) :
        return \
            dbus.dbus_connection_read_write(self._dbobj, timeout) != 0
    #end read_write

    # TODO: borrowed messages

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

    # TODO: set watch/timeout/wakeup_main/dispatch_status functions

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

    # TODO: get_adt, set_unix_user_function

    def set_allow_anonymous(self, allow) :
        dbus.dbus_connection_set_allow_anonymous(self._dbobj, allow)
    #end set_allow_anonymous

    def set_route_peer_messages(self, enable) :
        dbus.dbus_connection_set_route_peer_messages(self._dbobj, enable)
    #end set_route_peer_messages

    # TODO: add/remove filter
    # TODO: register/unregister object_path/fallback

    def list_registered(self, parent_path) :
        child_entries = ct.POINTER(ct.c_char_p)()
        if not dbus.dbus_connection_list_registered(self._dbobj, parent_path.encode(), ct.byref(child_entries)) :
            raise RuntimeError("dbus_connection_list_registered failed")
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
    # TODO: set_change_sigpipe
    # TODO: get/set max message/received size/fds outgoing

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
            raise RuntimeError("D-Bus set-unique-name failed")
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

#end Connection

class PreallocatedSend :
    "wrapper around a DBusPreallocatedSend object. Do not instantiate directly;" \
    " get from Connection.preallocate_send method."
    # <https://dbus.freedesktop.org/doc/api/html/group__DBusConnection.html>

    __slots__ = ("_dbobj", "_parent", "_sent") # to forestall typos

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
    " new methods."
    # <https://dbus.freedesktop.org/doc/api/html/group__DBusMessage.html>

    __slots__ = ("_dbobj") # to forestall typos

    def __new__(celf, _dbobj) :
        self = celf._instances.get(_dbobj)
        if self == None :
            self = super().__new__(celf)
            self._dbobj = _dbobj
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
            dbus.dbus_message_unref(self._dbobj)
            self._dbobj = None
        #end if
    #end __del__

    @classmethod
    def new(celf, type) :
        "type is one of the MESSAGE_TYPE_xxx codes."
        result = dbus.dbus_message_new(type)
        if result == None :
            raise RuntimeError("dbus_message_new failed")
        #end if
        return \
            celf(result)
    #end new

    @classmethod
    def new_error(celf, name, message) :
        result = dbus.dbus_message_new_error(name.encode(), message.encode())
        if result == None :
            raise RuntimeError("dbus_message_new_error failed")
        #end if
        return \
            celf(result)
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
            raise RuntimeError("dbus_message_new_method_call failed")
        #end if
        return \
            celf(result)
    #end new_method_call

    def new_method_return(self) :
        result = dbus.dbus_message_new_method_return(self._dbobj)
        if result == None :
            raise RuntimeError("dbus_message_new_method_return failed")
        #end if
        return \
            type(self)(result)
    #end new_method_return

    @classmethod
    def new_signal(celf, path, iface, name) :
        result = dbus.dbus_message_new_signal(path.encode(), iface.encode(), name.encode())
        if result == None :
            raise RuntimeError("dbus_message_new_signal failed")
        #end if
        return \
            celf(result)
    #end new_signal

    def copy(self) :
        result = dbus.dbus_message_copy(self._dbobj)
        if result == None :
            raise RuntimeError("dbus_message_copy failed")
        #end if
        return \
            type(self)(result)
    #end copy

    @property
    def type(self) :
        return \
            dbus.dbus_message_get_type(self._dbobj)
    #end type

    # TODO: append_args, get_args

    class Iter :
        "for iterating over the arguments in a Message, whether for reading or appending." \
        " Do not instantiate directly; get from Message.iter_init, Message.Iter.recurse," \
        " Message.iter_init_append or Message.Iter.open_container."

        __slots__ = ("_dbobj", "_parent", "_writing") # to forestall typos

        def __init__(self, _parent, _writing) :
            self._MessageIter = DBUS.MessageIter()
            self._parent = _parent
            self._writing = writing
        #end __init__

        @property
        def has_next(self) :
            assert not self._writing, "cannot read from write iterator"
            return \
                dbus.dbus_message_iter_has_next(self._dbobj)
        #end has_next

        def next(self) :
            assert not self._writing, "cannot read from write iterator"
            if not dbus.dbus_message_iter_next(self._dbobj) :
                raise StopIteration("end of message iterator")
            #end if
        #end next

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
                raise RuntimeError("dbus_message_iter_get_signature failure")
            #end if
            result = ct.cast(c_result, ct.c_char_p).value.decode()
            dbus.dbus_free(c_result)
            return \
                result
        #end signature

        @property
        def basic(self) :
            assert not self._writing, "cannot read from write iterator"
            c_result_type = DBUS.basic_to_ctypes[self.arg_type]
            c_result = c_result_type()
            dbus.dbus_message_iter_get_basic(self._dbobj, ct.byref(c_result))
            if c_result_type == ct.c_char_p :
                result = c_result.value.decode()
            else :
                result = c_result.value
            #end if
            return \
                result
        #end basic

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
            c_type = DBUS.basic_to_ctypes[type]
            if c_type == ct.c_char_p :
                value = value.encode()
            #end if
            c_value = c_type(value)
            if not dbus.dbus_message_iter_append_basic(self._dbobj, ct.byref(c_value)) :
                raise RuntimeError("dbus_message_iter_append_basic failed")
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
            if not dbus.dbus_message_iter_append_fixed_array(self._dbobj, ct.byref(c_arr)) :
                raise RuntimeError("dbus_message_iter_append_fixed_array failed")
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
            subiter = type(self)(self, True)
            if not dbus.dbus_message_iter_open_container(self._dbobj, type, c_sig, subiter._dbobj) :
                raise RuntimeError("dbus_message_iter_open_container failed")
            #end if
            return \
                subiter
        #end open_container

        def close(self) :
            assert self._writing, "cannot write to read iterator"
            assert self._parent != None, "cannot close top-level iterator"
            if not dbus.dbus_message_iter_close_container(self._parent._dbobj, self._dbobj) :
                raise RuntimeError("dbus_message_iter_close_container failed")
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
            iter = None
        #end if
        return \
             iter
    #end iter_init

    def init_append(self) :
        iter = self.Iter(None, True)
        dbus.dbus_message_iter_init_append(self._dbobj, iter._dbobj)
        return \
            iter
    #end init_append

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
    def auto_start(self, y) :
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
            raise RuntimeError("dbus_message_set_path failed")
        #end if
    #end path

    @property
    def path_decomposed(self) :
        path = ct.POINTER(ct.c_char_p)()
        if not dbus.dbus_message_get_path_decomposed(self._dbobj, ct.byref(path)) :
            raise RuntimeError("dbus_message_get_path_decomposed failed")
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
            raise RuntimeError("dbus_message_set_interface failed")
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
            raise RuntimeError("dbus_message_set_member failed")
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
            raise RuntimeError("dbus_message_set_error_name failed")
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
            raise RuntimeError("dbus_message_set_destination failed")
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
            raise RuntimeError("dbus_message_set_sender failed")
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

    def lock(self) :
        dbus.dbus_message_lock(self._dbobj)
    #end lock

    # TODO: allocate/free data slot (freeing slot can set passed-in var to -1 on actual free; do I care?)
    # TODO: set/get data
    # TODO: type from/to string
    # TODO: marshal/demarshal

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
    pass # TBD
#end PendingCall

class Error :
    "wrapper around a DBusError object."
    # <https://dbus.freedesktop.org/doc/api/html/group__DBusErrors.html>

    __slots__ = ("_dbobj") # to forestall typos

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

    def raise_if_set(self) :
        if self.is_set :
            raise RuntimeError("D-Bus error %s: %s" % (self.name, self.message))
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

# more TBD

def _atexit() :
    # disable all __del__ methods at process termination to avoid segfaults
    for cls in Connection, PreallocatedSend, Message, Error :
        delattr(cls, "__del__")
    #end for
#end _atexit
# atexit.register(_atexit) # TBD enable later
del _atexit
