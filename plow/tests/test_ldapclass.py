import unittest
from oaps4.libs.ldap.ldapclass import (
    LdapClass,
    CaseInsensitiveDict,
    )


class TestAttributeDict(unittest.TestCase):
    def test_getsetdel(self):
        d = CaseInsensitiveDict()
        d["aa"] = 5
        self.assertEquals(d["aa"], 5)
        self.assertEquals(d["AA"], 5)
        self.assertTrue("aA" in d)
        self.assertEquals(len(d), 1)

        d["AA"] = 4
        self.assertEquals(len(d), 1)
        self.assertEquals(d["aa"], 4)
        self.assertEquals(d["AA"], 4)
        self.assertEquals(d.keys(), ["aa"])

        del d["Aa"]
        self.assertEquals(len(d), 0)
        self.assertFalse("aa" in d)
        self.assertFalse("AA" in d)

    def test_update(self):
        d = CaseInsensitiveDict(A=1, C=1)
        d2 = CaseInsensitiveDict(a=2, b=2)

        d.update(d2)
        self.assertTrue("a" in d)
        self.assertTrue("b" in d)
        self.assertTrue("c" in d)
        self.assertEquals(d["a"], 2)


