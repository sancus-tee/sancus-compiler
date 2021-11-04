#!/usr/bin/env python3

import os
import ctypes

from . import config
from . import paths

KEY_SIZE = config.SECURITY

_lib = ctypes.cdll.LoadLibrary(paths.get_data_path() + '/libsancus-crypto.so')

def wrap(key, ad, body):
    # NOTE ctypes only understands bytes, not bytearrays
    cipher = bytes(len(body))
    tag = bytes(int(KEY_SIZE / 8))
    ok = _lib.sancus_wrap(bytes(key), bytes(ad), ctypes.c_ulonglong(len(ad)),
                          bytes(body), ctypes.c_ulonglong(len(body)),
                          cipher, tag)
    return (cipher, tag) if ok else None


def unwrap(key, ad, cipher, tag):
    body = bytes(len(cipher))
    ok = _lib.sancus_unwrap(bytes(key), bytes(ad), ctypes.c_ulonglong(len(ad)),
                            bytes(cipher), ctypes.c_ulonglong(len(cipher)),
                            bytes(tag), bytes(body))
    return body if ok else None


def mac(key, msg):
    ret = bytes(int(KEY_SIZE / 8))
    _lib.sancus_mac(bytes(key), bytes(msg), ctypes.c_ulonglong(len(msg)), ret)
    return ret


