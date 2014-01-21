# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import threading

from cryptography.hazmat.bindings.utils import build_ffi


_OSX_PRE_INCLUDE = """
#ifdef __APPLE__
#include <AvailabilityMacros.h>
#define __ORIG_DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER \
    DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#undef DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#define DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#endif
"""

_OSX_POST_INCLUDE = """
#ifdef __APPLE__
#undef DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#define DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER \
    __ORIG_DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#endif
"""


class Binding(object):
    """
    OpenSSL API wrapper.
    """
    _module_prefix = "cryptography.hazmat.bindings.openssl."
    _modules = [
        "asn1",
        "bignum",
        "bio",
        "conf",
        "crypto",
        "dh",
        "dsa",
        "ec",
        "engine",
        "err",
        "evp",
        "hmac",
        "nid",
        "objects",
        "opensslv",
        "pem",
        "pkcs7",
        "pkcs12",
        "rand",
        "rsa",
        "ssl",
        "x509",
        "x509name",
        "x509v3",
    ]

    _locks = None
    _lock_cb_handle = None
    _lock_init_lock = threading.Lock()

    ffi = None
    lib = None

    def __init__(self):
        self._ensure_ffi_initialized()

    @classmethod
    def _ensure_ffi_initialized(cls):
        if cls.ffi is not None and cls.lib is not None:
            return

        cls.ffi, cls.lib = build_ffi(cls._module_prefix, cls._modules,
                                     _OSX_PRE_INCLUDE, _OSX_POST_INCLUDE,
                                     ["crypto", "ssl"])

    @classmethod
    def is_available(cls):
        # OpenSSL is the only binding so for now it must always be available
        return True

    def init_static_locks(self):
        with Binding._lock_init_lock:
            # use Python's implementation if available
            __import__("_ssl")

            if self.lib.CRYPTO_get_locking_callback() != self.ffi.NULL:
                return

            # otherwise setup our version
            num_locks = self.lib.CRYPTO_num_locks()
            Binding._locks = [threading.Lock()
                              for n in range(num_locks)]

            self._lock_cb_handle = self.ffi.callback(
                "void(int, int, const char *, int)",
                self._lock_cb
            )
            self.lib.CRYPTO_set_locking_callback(self._lock_cb_handle)

    def _lock_cb(self, mode, n, file, line):
        lock = Binding._locks[n]

        if mode & self.lib.CRYPTO_LOCK:
            lock.acquire()
        elif mode & self.lib.CRYPTO_UNLOCK:
            lock.release()
        else:
            raise RuntimeError("Unknown lock mode {0}".format(mode))
