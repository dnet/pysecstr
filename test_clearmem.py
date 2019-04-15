import sys

import unittest

from SecureBytes import clearmem, scanmem, safemem, safemem_supported, scanmem_supported

class TestSecureBytes(unittest.TestCase):
    def test_clear_str(self):
        s = "12R34G"
        a = "12R"
        b = "34G"

        assert(s == (a+b))

        y = s
        clearmem(s)

        assert(s != (a+b))
        assert(y != (a+b))

        assert(a+b)

    def test_clear_int(self):
        i = 239872349827349587239857234985623497562387465284396528934658923465892436582436587243

        clearmem(i)

        print(i)

        assert(i+0 == 0);

    def test_scanmem(self):
        # todo, make linux vm area scanner 
        if not scanmem_supported:
            return

        a = b"zzX~X12R9s8fysd98hf"
        b = b"zzX~X34Gsdf909sdjff"
        s = a + b

        # adjacent a+b in memory
        assert(scanmem(a,b))

        # remove s
        clearmem(s)

        # adjacent a+b not in memory
        assert(not scanmem(a,b))

    @unittest.skipIf(not safemem_supported,"python2 no allocators")
    def test_safemem_context(self):

        a = b"zzX~X12R9s8fysd98h"
        b = b"zzX~X34Gsdf909sdjf"

        with safemem():
            s = a + b
            # adjacent a+b in memory
            if scanmem_supported:
                assert(scanmem(a,b))
            del s                       # freed refs are zeroed by pysafemem while in context

        # adjacent a+b not in memory
        if scanmem_supported:
            assert(not scanmem(a,b))

    @unittest.skipIf(not safemem_supported,"python2 no allocators")
    def test_safemem_install(self):
        a = b"zzX~X12R9s8fysd98h"
        b = b"zzX~X34Gsdf909sdjf"

        safemem.start()

        s = a + b
        # adjacent a+b in memory
        if scanmem_supported:
            assert(scanmem(a,b))
        del s                       # freed refs are zeroed by pysafemem while in context

        # adjacent a+b not in memory
        if scanmem_supported:
            assert(not scanmem(a,b))

        safemem.stop()

    def test_del_refs(self):
        a = b"zzX~X12R9s8fysd9"
        b = b"zzX~X34Gsdf909sd"

        # Warning: this test will NOT pass if secbytes is derived from bytes
        # python 3 handles derivation from primitives in a way that causes more than one copy

        class secbytes():
            def __init__(self, k):
                self.__k = k
            def __del__(self):
                clearmem(self.__k)
            def __len__(self):
                return len(self.__k)

        x = secbytes(a+b)
        y = x

        if scanmem_supported:
            assert(scanmem(a,b))

        del(x)

        # reference to y has material
        if scanmem_supported:
            assert(scanmem(a,b))

        del(y)
            
        if scanmem_supported:
            assert(not scanmem(a,b))
