from unittest import TestCase

from SecureBytes import clearmem

from secbytes import secbytes

class TestSecureBytes(TestCase):
    def test_clear_mem(self):
        s = "12R34G"
        a = "12R"
        b = "34G"

        assert(s == (a+b))

        y = s
        clearmem(s)

        assert(s != (a+b))
        assert(y != (a+b))

        assert(a+b)

    def test_secbytes(self):
        s = secbytes(b"zzX~X12RzzX~X34G")

        a = b"zzX~X12R"
        b = b"zzX~X34G"

        assert(s == (a+b))

        # adjacent a+b in memory
        assert(scanmem(a,b))

        # remove s
        del(s)

        # adjacent a+b not in memory
        assert(!scanmem(a,b))

