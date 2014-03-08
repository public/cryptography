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

    def test_invalid_parameters_values(self):
        # Test a modulus < 1024 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 1000,
                subgroup_order=2 ** 159,
                generator=2 ** 300
            )

        # Test a modulus < 2048 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 2000,
                subgroup_order=2 ** 255,
                generator=2 ** 300
            )

        # Test a modulus < 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 3000,
                subgroup_order=2 ** 255,
                generator=2 ** 300
            )

        # Test a modulus > 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 3100,
                subgroup_order=2 ** 256,
                generator=2 ** 300
            )

        # Test a subgroup_order < 160 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 1023,
                subgroup_order=2 ** 150,
                generator=2 ** 300
            )

        # Test a subgroup_order < 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 2047,
                subgroup_order=2 ** 250,
                generator=2 ** 300
            )

        # Test a subgroup_order > 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 2047,
                subgroup_order=2 ** 260,
                generator=2 ** 300
            )

        # Test a modulus, subgroup_order pair of (1024, 256) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 1023,
                subgroup_order=2 ** 255,
                generator=2 ** 300
            )

        # Test a modulus, subgroup_order pair of (2048, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 2047,
                subgroup_order=2 ** 159,
                generator=2 ** 300
            )

        # Test a modulus, subgroup_order pair of (3072, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 3071,
                subgroup_order=2 ** 159,
                generator=2 ** 300
            )

        # Test a generator < 1
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 1023,
                subgroup_order=2 ** 159,
                generator=0
            )

        # Test a generator = 1
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 1023,
                subgroup_order=2 ** 159,
                generator=1
            )

        # Test a generator > modulus
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 1023,
                subgroup_order=2 ** 159,
                generator=2 ** 1200
            )

    def test_invalid_private_key_argument_values(self):
        # Test a modulus < 1024 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 1000,
                subgroup_order=2 ** 159,
                generator=2 ** 300,
                x=2 ** 100,
                y=((2 ** 300) ** (2 ** 100)) % (2 ** 1000)
            )

        # Test a modulus < 2048 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 2000,
                subgroup_order=2 ** 255,
                generator=2 ** 300,
                x=2 ** 100,
                y=((2 ** 300) ** (2 ** 100)) % (2 ** 2000)
            )

        # Test a modulus < 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 3000,
                subgroup_order=2 ** 255,
                generator=2 ** 300,
                x=2 ** 100,
                y=((2 ** 300) ** (2 ** 100)) % (2 ** 3000)
            )

        # Test a modulus > 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 3100,
                subgroup_order=2 ** 256,
                generator=2 ** 300,
                x=2 ** 100,
                y=((2 ** 300) ** (2 ** 100)) % (2 ** 3100)
            )

        # Test a subgroup_order < 160 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 1023,
                subgroup_order=2 ** 150,
                generator=2 ** 300,
                x=2 ** 100,
                y=((2 ** 300) ** (2 ** 100)) % (2 ** 1023)
            )

        # Test a subgroup_order < 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 2047,
                subgroup_order=2 ** 250,
                generator=2 ** 300,
                x=2 ** 100,
                y=((2 ** 300) ** (2 ** 100)) % (2 ** 2047)
            )

        # Test a subgroup_order > 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 2047,
                subgroup_order=2 ** 260,
                generator=2 ** 300,
                x=2 ** 100,
                y=((2 ** 300) ** (2 ** 100)) % (2 ** 2047)
            )

        # Test a modulus, subgroup_order pair of (1024, 256) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 1023,
                subgroup_order=2 ** 255,
                generator=2 ** 300,
                x=2 ** 100,
                y=((2 ** 300) ** (2 ** 100)) % (2 ** 1023)
            )

        # Test a modulus, subgroup_order pair of (2048, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 2047,
                subgroup_order=2 ** 159,
                generator=2 ** 300,
                x=2 ** 100,
                y=((2 ** 300) ** (2 ** 100)) % (2 ** 2047)
            )

        # Test a modulus, subgroup_order pair of (3072, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 3071,
                subgroup_order=2 ** 159,
                generator=2 ** 300,
                x=2 ** 100,
                y=((2 ** 300) ** (2 ** 100)) % (2 ** 3071)
            )

        # Test a generator < 1
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 1023,
                subgroup_order=2 ** 159,
                generator=0,
                x=2 ** 100,
                y=0
            )

        # Test a generator = 1
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 1023,
                subgroup_order=2 ** 159,
                generator=1,
                x=2 ** 100,
                y=(1 ** (2 ** 100)) % (2 ** 1023)
            )

        # Test a generator > modulus
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 1023,
                subgroup_order=2 ** 159,
                generator=2 ** 1200,
                x=2 ** 100,
                y=((2 ** 1200) ** (2 ** 100)) % (2 ** 1023)
            )

        # Test x < 0
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 1023,
                subgroup_order=2 ** 159,
                generator=2 ** 300,
                x=-2,
                y=((2 ** 300) ** (-2)) % (2 ** 1023)
            )

        # Test x = 0
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 1023,
                subgroup_order=2 ** 159,
                generator=2 ** 300,
                x=0,
                y=(1) % (2 ** 1023)
            )

        # Test x > subgroup_order
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 1023,
                subgroup_order=2 ** 159,
                generator=2 ** 300,
                x=2 ** 200,
                y=((2 ** 300) ** (2 ** 200)) % (2 ** 1023)
            )

        # Test y != (generator ** x) % modulus:
        with pytest.raises(ValueError):
            dsa.DSAPrivateKey(
                modulus=2 ** 1023,
                subgroup_order=2 ** 159,
                generator=2 ** 300,
                x=2 ** 100,
                y=2 ** 100
            )
