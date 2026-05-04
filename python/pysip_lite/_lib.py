from ctypes import *
from ._types import *
import os

lib: CDLL = CDLL(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "belle-wrap.so")
)
assert lib


# primary lib init
lib.bsw_init.argtypes = []
lib.bsw_init.restype = c_bool

# set up logging callback
lib.bsw_set_logger.argtypes = [c_int, c_int]
lib.bsw_set_logger.restype = None

# receive one log message
lib.bsw_get_log.argtypes = [c_char_p, c_size_t]
lib.bsw_get_log.restype = c_bool

# create a provider
lib.bsw_provider.argtypes = [c_char_p, c_int, c_char_p]
lib.bsw_provider.restype = provider_ptr

# register a UA
lib.bsw_register.argtypes = [provider_ptr, c_int, c_char_p, c_char_p, c_int]
lib.bsw_register.restype = None

# listen for incoming calls
lib.bsw_listen.argtypes = [provider_ptr, c_int, c_char_p]
lib.bsw_listen.restype = None

# wait for one incoming call
lib.bsw_receive.argtypes = [provider_ptr, c_char_p, call_info_ptr]
lib.bsw_receive.restype = c_bool

# destroy a call object
lib.bsw_call_destroy.argtypes = [call_ptr]
lib.bsw_call_destroy.restype = None

# answer one incoming call
lib.bsw_call_answer.argtypes = [call_ptr, c_int, c_char_p]
lib.bsw_call_answer.restype = bool

# wait for end of call
lib.bsw_call_finished.argtypes = [call_ptr, c_int]
lib.bsw_call_finished.restype = bool

# close a running call
lib.bsw_call_terminate.argtypes = [call_ptr]
lib.bsw_call_terminate.restype = bool

# initiate an outgoing call
lib.bsw_call_create.argtypes = [provider_ptr, call_info_ptr, c_int]
lib.bsw_call_create.restype = call_ptr

# return state of outgoing call answer
lib.bsw_call_wait.argtypes = [call_ptr, call_info_ptr]
lib.bsw_call_wait.restype = c_int


if not lib.bsw_init():
    raise RuntimeError("lib init failed")
