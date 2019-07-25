from ctypes import *
from os import path

_binarypattern_dll = CDLL(path.join(path.dirname(path.realpath(__file__)), 'binja-pattern'))

class _BinaryPattern(Structure):
    pass

_BinaryPattern_Parse = _binarypattern_dll['BinaryPattern_Parse']
_BinaryPattern_Parse.argtypes = [POINTER(c_char)]
_BinaryPattern_Parse.restype = POINTER(_BinaryPattern)

_BinaryPattern_Free = _binarypattern_dll['BinaryPattern_Free']
_BinaryPattern_Free.argtypes = [POINTER(_BinaryPattern)]
_BinaryPattern_Free.restype = None

_BinjaPattern_Scan = _binarypattern_dll['BinjaPattern_Scan']
_BinjaPattern_Scan.argtypes = [POINTER(_BinaryPattern), POINTER(c_ubyte), c_size_t, POINTER(c_size_t), c_size_t]
_BinjaPattern_Scan.restype = c_size_t

class BinaryPattern:
    def __init__(self, pattern: str):
        self.handle = _BinaryPattern_Parse(create_string_buffer(pattern.encode('ascii')))

    def __del__(self):
        _BinaryPattern_Free(self.handle)

    def find(self, data: bytes):
        result = c_size_t()

        if _BinjaPattern_Scan(self.handle, cast(data, POINTER(c_ubyte)), c_size_t(len(data)), cast(addressof(result), POINTER(c_size_t)), c_size_t(1)):
            return result.value
        else:
            return None
