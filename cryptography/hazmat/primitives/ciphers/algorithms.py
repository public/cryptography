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

from cryptography import utils
from cryptography.hazmat.primitives import interfaces


def _valid_key_size(algorithm, key_size):
    if key_size not in algorithm.key_sizes:
        raise ValueError("Invalid key size ({0}) for {1}".format(
            key_size, algorithm.name
        ))


def _init_algorithm(algorithm, key, key_size):
    """
    Ciphers may have eith key, key_size or both specified on __init__.

    len(key) * 8 must be equal to key_size if both are set.

    Both must be contained in algorithm.key_sizes
    """
    if key_size is None and key is None:
        raise TypeError(
            "__init__ takes at least one of key and key_size"
        )

    if key_size is not None:
        _valid_key_size(algorithm, key_size)
        algorithm._key_size = key_size

    if key is not None:
        key_bits = len(key) * 8

        if key_size is not None and key_bits != key_size:
            raise ValueError("Key size {0} does not match {1}".format(
                key_bits, key_size
            ))
        else:
            _valid_key_size(algorithm, key_bits)
            algorithm._key_size = key_bits
        algorithm._key = key


@utils.register_interface(interfaces.BlockCipherAlgorithm)
@utils.register_interface(interfaces.CipherAlgorithm)
class AES(object):
    name = "AES"
    block_size = 128
    key_sizes = frozenset([128, 192, 256])

    def __init__(self, key=None, key_size=None):
        _init_algorithm(self, key, key_size)

    @property
    def key(self):
        return self._key

    @property
    def key_size(self):
        return self._key_size


@utils.register_interface(interfaces.BlockCipherAlgorithm)
@utils.register_interface(interfaces.CipherAlgorithm)
class Camellia(object):
    name = "camellia"
    block_size = 128
    key_sizes = frozenset([128, 192, 256])

    def __init__(self, key=None, key_size=None):
        _init_algorithm(self, key, key_size)

    @property
    def key(self):
        return self._key

    @property
    def key_size(self):
        return self._key_size


@utils.register_interface(interfaces.BlockCipherAlgorithm)
@utils.register_interface(interfaces.CipherAlgorithm)
class TripleDES(object):
    name = "3DES"
    block_size = 64
    key_sizes = frozenset([64, 128, 192])

    def __init__(self, key=None, key_size=None):
        if key is not None:
            if len(key) == 8:
                key += key + key
            elif len(key) == 16:
                key += key[:8]

        _init_algorithm(self, key, key_size)

    @property
    def key(self):
        return self._key

    @property
    def key_size(self):
        return self._key_size


@utils.register_interface(interfaces.BlockCipherAlgorithm)
@utils.register_interface(interfaces.CipherAlgorithm)
class Blowfish(object):
    name = "Blowfish"
    block_size = 64
    key_sizes = frozenset(range(32, 449, 8))

    def __init__(self, key=None, key_size=None):
        _init_algorithm(self, key, key_size)

    @property
    def key(self):
        return self._key

    @property
    def key_size(self):
        return self._key_size


@utils.register_interface(interfaces.CipherAlgorithm)
class ARC4(object):
    name = "RC4"
    key_sizes = frozenset([40, 56, 64, 80, 128, 192, 256])

    def __init__(self, key=None, key_size=None):
        _init_algorithm(self, key, key_size)

    @property
    def key(self):
        return self._key

    @property
    def key_size(self):
        return self._key_size
