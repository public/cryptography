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

import threading

from cryptography.hazmat.bindings.openssl.binding import Binding


class TestOpenSSL(object):
    def test_binding_loads(self):
        binding = Binding()
        assert binding
        assert binding.lib
        assert binding.ffi

    def test_is_available(self):
        assert Binding.is_available() is True

    def test_thread_init(self):
        b = Binding()
        b.init_static_locks()
        lock_cb = b.lib.CRYPTO_get_locking_callback()
        assert lock_cb != b.ffi.NULL

    def test_threads(self):
        b = Binding()
        b.init_static_locks()

        def randloop():
            s = b.ffi.new("char[]", 256)
            sb = b.ffi.buffer(s)
            sb[:] = b"\0" * 256

            for i in range(100000):
                b.lib.RAND_seed(s, 256)

        threads = []
        for x in range(3):
            t = threading.Thread(target=randloop)
            t.daemon = True
            t.start()

            threads.append(t)

        while threads:
            for t in threads:
                t.join(0.1)
                if not t.isAlive():
                    threads.remove(t)
