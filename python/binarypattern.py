from ctypes import *
from os import path
import platform

if platform.system() == 'Windows':
    _binarypattern_name = 'binja-pattern.dll'
elif platform.system() == 'Linux':
    _binarypattern_name = 'libbinja-pattern.so'
elif platform.system() == 'Darwin':
    _binarypattern_name = "libbinja-pattern.dylib"
else:
    raise Exception('OS not supported')

_binarypattern_dll = CDLL(path.join(path.dirname(path.realpath(__file__)), _binarypattern_name))

class _BinaryPattern(Structure):
    pass

_BinaryPattern_Parse = _binarypattern_dll['BinaryPattern_Parse']
_BinaryPattern_Parse.argtypes = [POINTER(c_char)]
_BinaryPattern_Parse.restype = POINTER(_BinaryPattern)

_BinaryPattern_Free = _binarypattern_dll['BinaryPattern_Free']
_BinaryPattern_Free.argtypes = [POINTER(_BinaryPattern)]
_BinaryPattern_Free.restype = None

_BinaryPattern_Scan = _binarypattern_dll['BinaryPattern_Scan']
_BinaryPattern_Scan.argtypes = [POINTER(_BinaryPattern), POINTER(c_ubyte), c_size_t, POINTER(c_size_t), c_size_t]
_BinaryPattern_Scan.restype = c_size_t

class BinaryPattern:
    def __init__(self, pattern):
        self.handle = _BinaryPattern_Parse(create_string_buffer(pattern.encode('ascii')))

    def __del__(self):
        _BinaryPattern_Free(self.handle)

    def find(self, data):
        result = c_size_t()

        if _BinaryPattern_Scan(self.handle, cast(data, POINTER(c_ubyte)), c_size_t(len(data)), cast(addressof(result), POINTER(c_size_t)), c_size_t(1)):
            return result.value
        else:
            return None
