.. hazmat::

OpenSSL Backend
===============

The `OpenSSL`_ C library.

.. data:: cryptography.hazmat.backends.openssl.backend

    This is the exposed API for the OpenSSL backend. It has no public attributes.    

Using your own OpenSSL on Linux
-------------------------------

Python links to OpenSSL for its own purposes and this can sometimes cause
problems when you wish to use a different version of OpenSSL with cryptography.
If you want to use cryptography with your own build of OpenSSL you will need to
make sure that the build is configured correctly so that your version of
OpenSSL doesn't conflict with Python's.

The options you need to add allow the linker to identify every symbol correctly
even when multiple versions of the library are linked into the same program. If
you are using your distribution's source packages these will probably be
patched in for you already, otherwise you'll need to use options something like
this when configuring OpenSSL::

    ./config -Wl,--version-script=openssl.ld -Wl,-Bsymbolic-functions -fPIC shared

You'll also need to generate your own ``openssl.ld`` file. For example::

    OPENSSL_1.0.1F_CUSTOM {
        global:
            *;
    };

You should replace the version string on the first line as appropriate for your
build.

If you are building a customised version of OpenSSL that has the same ELF
SONAME attribute (you can find this with ``readelf -d``) as the one used by
Python, you'll probably want to make sure that your build doesn't have the same
one. One way to do this is by modifying ``crypto/opensslv.h`` to use custom
version number. We recomended something like ``0.0.101`` instead of
incrementing any of the other versions. 

.. _`OpenSSL`: https://www.openssl.org/
