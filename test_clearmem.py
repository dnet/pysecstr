from unittest import TestCase

from SecureBytes import clearmem

class TestSecureBytes(TestCase):
    def test_clear_mem(self):
        s = "1234"
        a = "12"
        b = "34"

        y = s
        clearmem(s)

        assert(s != (a+b))
        assert(y != (a+b))
