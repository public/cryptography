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

INCLUDES = """
#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif

#include <openssl/obj_mac.h>
"""

TYPES = """
static const int Cryptography_HAS_EC;

typedef ... EC_KEY;
typedef ... EC_GROUP;
typedef ... EC_POINT;
typedef struct {
    int nid;
    const char *comment;
} EC_builtin_curve;
typedef enum { ... } point_conversion_form_t;
"""

FUNCTIONS = """
"""

MACROS = """


void EC_KEY_free(EC_KEY *);
size_t EC_get_builtin_curves(EC_builtin_curve *, size_t);

int EC_KEY_get_flags(const EC_KEY *);
void EC_KEY_set_flags(EC_KEY *, int);
void EC_KEY_clear_flags(EC_KEY *, int);
EC_KEY *EC_KEY_new_by_curve_name(int);
EC_KEY *EC_KEY_copy(EC_KEY *, const EC_KEY *);
EC_KEY *EC_KEY_dup(const EC_KEY *);
int EC_KEY_up_ref(EC_KEY *);
const EC_GROUP *EC_KEY_get0_group(const EC_KEY *);
int EC_KEY_set_group(EC_KEY *, const EC_GROUP *);
const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *);
int EC_KEY_set_private_key(EC_KEY *, const BIGNUM *);
const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *);
int EC_KEY_set_public_key(EC_KEY *, const EC_POINT *);
unsigned int EC_KEY_get_enc_flags(const EC_KEY *);
void EC_KEY_set_enc_flags(EC_KEY *eckey, unsigned int);
point_conversion_form_t EC_KEY_get_conv_form(const EC_KEY *);
void EC_KEY_set_conv_form(EC_KEY *, point_conversion_form_t);
void *EC_KEY_get_key_method_data(
    EC_KEY *,
    void *(*)(void *),
    void (*)(void *),
    void (*)(void *)
);
void EC_KEY_insert_key_method_data(
    EC_KEY *,
    void *,
    void *(*)(void *),
    void (*)(void *),
    void (*)(void *)
);
void EC_KEY_set_asn1_flag(EC_KEY *, int);
int EC_KEY_precompute_mult(EC_KEY *, BN_CTX *);
int EC_KEY_generate_key(EC_KEY *);
int EC_KEY_check_key(const EC_KEY *);
int EC_KEY_set_public_key_affine_coordinates(EC_KEY *, BIGNUM *x, BIGNUM *y);
"""

CUSTOMIZATIONS = """
#ifdef OPENSSL_NO_EC
static const long Cryptography_HAS_EC = 0;
typedef void EC_KEY;
typedef struct {
    int nid;
    const char *comment;
} EC_builtin_curve;

void (*EC_KEY_free)(EC_KEY *) = NULL;
size_t (*EC_get_builtin_curves)(EC_builtin_curve *, size_t) = NULL;
int (*EC_KEY_get_flags)(const EC_KEY *) = NULL;
void (*EC_KEY_set_flags)(EC_KEY *, int) = NULL;
void (*EC_KEY_clear_flags)(EC_KEY *, int) = NULL;
EC_KEY *(*EC_KEY_new_by_curve_name)(int) = NULL;
EC_KEY *(*EC_KEY_copy)(EC_KEY *, const EC_KEY *) = NULL;
EC_KEY *(*EC_KEY_dup)(const EC_KEY *) = NULL;
int (*EC_KEY_up_ref)(EC_KEY *) = NULL;
const EC_GROUP *(*EC_KEY_get0_group)(const EC_KEY *) = NULL;
int (*EC_KEY_set_group)(EC_KEY *, const EC_GROUP *) = NULL;
const BIGNUM *(*EC_KEY_get0_private_key)(const EC_KEY *) = NULL;
int (*EC_KEY_set_private_key)(EC_KEY *, const BIGNUM *) = NULL;
const EC_POINT *(*EC_KEY_get0_public_key)(const EC_KEY *) = NULL;
int (*EC_KEY_set_public_key)(EC_KEY *, const EC_POINT *) = NULL;
unsigned int (*EC_KEY_get_enc_flags)(const EC_KEY *) = NULL;
void (*EC_KEY_set_enc_flags)(EC_KEY *eckey, unsigned int) = NULL;
point_conversion_form_t (*EC_KEY_get_conv_form)(const EC_KEY *) = NULL;
void (*EC_KEY_set_conv_form)(EC_KEY *, point_conversion_form_t) = NULL;
void *(*EC_KEY_get_key_method_data)(
    EC_KEY *, void *(*)(void *), void (*)(void *), void (*)(void *)) = NULL;
void (*EC_KEY_insert_key_method_data)(
    EC_KEY *, void *,
    void *(*)(void *), void (*)(void *), void (*)(void *)) = NULL;
void (*EC_KEY_set_asn1_flag)(EC_KEY *, int) = NULL;
int (*EC_KEY_precompute_mult)(EC_KEY *, BN_CTX *) = NULL;
int (*EC_KEY_generate_key)(EC_KEY *) = NULL;
int (*EC_KEY_check_key)(const EC_KEY *) = NULL;
int (*EC_KEY_set_public_key_affine_coordinates)(
    EC_KEY *, BIGNUM *x, BIGNUM *y) = NULL;
#else
static const long Cryptography_HAS_EC = 1;
#endif
"""

CONDITIONAL_NAMES = {
    "Cryptography_HAS_EC": [
        "EC_KEY_free",
        "EC_get_builtin_curves",
        "EC_KEY_get_flags",
        "EC_KEY_set_flags",
        "EC_KEY_clear_flags",
        "EC_EC_KEY_new_by_curve_name",
        "EC_EC_KEY_copy",
        "EC_EC_KEY_dup",
        "EC_KEY_up_ref",
        "EC_KEY_set_group",
        "EC_KEY_get0_private_key",
        "EC_KEY_set_private_key",
        "EC_KEY_set_public_key",
        "EC_KEY_get_enc_flags",
        "EC_KEY_set_enc_flags",
        "EC_KEY_set_conv_form",
        "EC_KEY_get_key_method_data",
        "EC_KEY_insert_key_method_data",
        "EC_KEY_set_asn1_flag",
        "EC_KEY_precompute_mult",
        "EC_KEY_generate_key",
        "EC_KEY_check_key",
        "EC_KEY_set_public_key_affine_coordinates",
    ],
}
