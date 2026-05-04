from ctypes import *

# opaque C types


class call(Structure):
    pass


class provider_t(Structure):
    pass


provider_ptr = POINTER(provider_t)


call_ptr = POINTER(call)


class call_info(Structure):
    _fields_ = [
        ("call_id", c_char * 256),
        ("body", c_char * 8192),
        ("content_type", c_char * 256),
        ("from_addr", c_char * 256),
        ("to_addr", c_char * 256),
        ("from_tag", c_char * 256),
        ("to_tag", c_char * 256),
        ("call", call_ptr),
    ]


call_info_ptr = POINTER(call_info)
