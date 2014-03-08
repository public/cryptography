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

import pytest

import random

from cryptography.hazmat.primitives.asymmetric import dsa


class TestDSA(object):
    def test_invalid_parameters_argument_types(self):
        with pytest.raises(TypeError):
            dsa.DSAParameters(None, None, None)

    def test_invalid_private_key_argument_types(self):
        with pytest.raises(TypeError):
            dsa.DSAPrivateKey(None, None, None, None, None)

    def test_invalid_public_key_argument_types(self):
        with pytest.raises(TypeError):
            dsa.DSAPublicKey(None, None, None, None)

    def test_invalid_parameters_argument_values(self):
        # Test a modulus < 1024 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=random.getrandbits(1020),
                subgroup_order=random.getrandbits(160),
                generator=random.getrandbits(300)
            )

        # Test a modulus < 2048 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=random.getrandbits(2040),
                subgroup_order=random.getrandbits(256),
                generator=random.getrandbits(300)
            )

        # Test a modulus < 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=random.getrandbits(3070),
                subgroup_order=random.getrandbits(256),
                generator=random.getrandbits(300)
            )

        # Test a modulus > 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=random.getrandbits(3100),
                subgroup_order=random.getrandbits(256),
                generator=random.getrandbits(300)
            )

        # Test a subgroup_order < 160 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=random.getrandbits(1024),
                subgroup_order=random.getrandbits(150),
                generator=random.getrandbits(300)
            )

        # Test a subgroup_order < 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=random.getrandbits(2048),
                subgroup_order=random.getrandbits(250),
                generator=random.getrandbits(300)
            )

        # Test a subgroup_order > 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=random.getrandbits(2048),
                subgroup_order=random.getrandbits(260),
                generator=random.getrandbits(300)
            )

        # Test a modulus, subgroup_order pair of (1024, 256) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=random.getrandbits(1024),
                subgroup_order=random.getrandbits(256),
                generator=random.getrandbits(300)
            )

        # Test a modulus, subgroup_order pair of (2048, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=random.getrandbits(2048),
                subgroup_order=random.getrandbits(160),
                generator=random.getrandbits(300)
            )

        # Test a modulus, subgroup_order pair of (3072, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=random.getrandbits(3072),
                subgroup_order=random.getrandbits(160),
                generator=random.getrandbits(300)
            )

        # Test a generator < 1
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=random.getrandbits(1024),
                subgroup_order=random.getrandbits(160),
                generator=0
            )

        # Test a generator = 1
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=random.getrandbits(1024),
                subgroup_order=random.getrandbits(160),
                generator=1
            )

        # Test a generator > modulus
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=random.getrandbits(1024),
                subgroup_order=random.getrandbits(160),
                generator=random.getrandbits(2000)
            )
