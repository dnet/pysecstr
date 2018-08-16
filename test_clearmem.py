from unittest import TestCase

from SecureBytes import clearmem, scanmem

class TestSecureBytes(TestCase):
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

    def test_scanmem(self):
        a = b"zzX~X12R9s8fysd98hf"
        b = b"zzX~X34Gsdf909sdjff"
        s = a + b
        import sys
        if sys.platform == "win32":
            # adjacent a+b in memory
            assert(scanmem(a,b))
            # remove s
            clearmem(s)
            # adjacent a+b not in memory
            assert(not scanmem(a,b))

    def test_del_refs(self):
        a = b"zzX~X12R9s8fysd9"
        b = b"zzX~X34Gsdf909sd"

        # warning: this test will NOT pass if secbytes is derived from bytes
        # because python 3 handles derivation from primitives in a way that causes more than one copy

        class secbytes():
            def __init__(self, k):
                self.__k = k
            def __del__(self):
                clearmem(self.__k)
            def __len__(self):
                return len(self.__k)

        x = secbytes(a+b)
        y = x

        assert(scanmem(a,b))

        del(x)

        # reference to y has material
        assert(scanmem(a,b))

        del(y)
            
        assert(not scanmem(a,b))
