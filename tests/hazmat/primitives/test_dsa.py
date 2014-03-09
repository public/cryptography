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

import os

import pytest

from cryptography.hazmat.primitives.asymmetric import dsa

from ...utils import load_fips_dsa_vectors, load_vectors_from_file


class TestDSA(object):
    my_dict = load_vectors_from_file(
        os.path.join(
            "asymmetric", "DSA", "FIPS_186-3", "KeyPair.rsp",
        ),
        load_fips_dsa_vectors
    )
    _dict_1024, _dict_2048, _dict_3072 = my_dict

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
                subgroup_order=int(self._dict_1024['q'], 16),
                generator=int(self._dict_1024['g'], 16)
            )

        # Test a modulus < 2048 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 2000,
                subgroup_order=int(self._dict_2048['q'], 16),
                generator=int(self._dict_2048['g'], 16)
            )

        # Test a modulus < 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 3000,
                subgroup_order=int(self._dict_3072['q'], 16),
                generator=int(self._dict_3072['g'], 16)
            )

        # Test a modulus > 3072 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=2 ** 3100,
                subgroup_order=int(self._dict_3072['q'], 16),
                generator=int(self._dict_3072['g'], 16)
            )

        # Test a subgroup_order < 160 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=int(self._dict_1024['p'], 16),
                subgroup_order=2 ** 150,
                generator=int(self._dict_1024['g'], 16)
            )

        # Test a subgroup_order < 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=int(self._dict_2048['p'], 16),
                subgroup_order=2 ** 250,
                generator=int(self._dict_2048['g'], 16)
            )

        # Test a subgroup_order > 256 bits in length
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=int(self._dict_3072['p'], 16),
                subgroup_order=2 ** 260,
                generator=int(self._dict_3072['g'], 16)
            )

        # Test a modulus, subgroup_order pair of (1024, 256) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=int(self._dict_1024['p'], 16),
                subgroup_order=int(self._dict_2048['q'], 16),
                generator=int(self._dict_1024['g'], 16)
            )

        # Test a modulus, subgroup_order pair of (2048, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=int(self._dict_2048['p'], 16),
                subgroup_order=int(self._dict_1024['q'], 16),
                generator=int(self._dict_2048['g'], 16)
            )

        # Test a modulus, subgroup_order pair of (3072, 160) bit lengths
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=int(self._dict_3072['p'], 16),
                subgroup_order=int(self._dict_1024['q'], 16),
                generator=int(self._dict_3072['g'], 16)
            )

        # Test a generator < 1
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=int(self._dict_1024['p'], 16),
                subgroup_order=int(self._dict_1024['q'], 16),
                generator=0
            )

        # Test a generator = 1
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=int(self._dict_1024['p'], 16),
                subgroup_order=int(self._dict_1024['q'], 16),
                generator=1
            )

        # Test a generator > modulus
        with pytest.raises(ValueError):
            dsa.DSAParameters(
                modulus=int(self._dict_1024['p'], 16),
                subgroup_order=int(self._dict_1024['q'], 16),
                generator=2 ** 1200
            )
