from unittest import TestCase

from SecureBytes import clearmem, scanmem

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

