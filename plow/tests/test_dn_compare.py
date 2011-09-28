import unittest

from plow.ldapadaptor import LdapAdaptor

class FakeLA(LdapAdaptor):
    def bind(self, *args):
        """ Nothing to see here move along """

    initialize = bind

class Test_Ldap_DN_Compare(unittest.TestCase):
    def setUp(self):
        self.ldap_case_i = FakeLA("uri", "base", case_insensitive_dn=True)
        self.ldap_case_s = FakeLA("uri", "base")

    def _do_compare(self, ref, other, res, case_sensitive=True):
        if case_sensitive:
            match = self.ldap_case_s.compare_dn(ref, other)
        else:
            match = self.ldap_case_i.compare_dn(ref, other)

        if res:
            self.assertTrue(
                match,
                "Expected '{0}' to match '{1}' (Case Sensitive: {2})".format(ref, other, case_sensitive),
                )
        else:
            self.assertFalse(
                match,
                "'{0}' and '{1}' should not match (Case Sensitive: {2})".format(ref, other, case_sensitive),
                )

    def test_basic(self):
        self._do_compare("CN=Test", "CN=test", False, case_sensitive=True)
        self._do_compare("CN=Test", "CN=test", True, case_sensitive=False)

    def test_spaces(self):
        self._do_compare("CN=Test, OU=Base", "CN=Test,OU=Base", True)
        self._do_compare(" CN = Test,OU  =  Base    ", "CN=Test,OU=Base", True)
        self._do_compare(" CN = Te   st   ", "CN=Te   st", True)

if __name__ == '__main__':
    unittest.main()
