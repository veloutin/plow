import unittest
from plow.ldapclass import LdapType, CaseInsensitiveDict
from .mocks import LdapAdaptor


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


    def test_copy(self):
        d = CaseInsensitiveDict(A=[1], B=2)
        e = d.copy()
        d['A'].append(2)

        self.assertEquals(e['a'], [1])


class TestLdapClass(unittest.TestCase):
    def test_attrs(self):
        la = LdapAdaptor("ldap://localhost", "dc=example,dc=com")
        User = LdapType.from_config("User", {
            "rdn" : "uid",
            "uid" : "uid",
            "objectClass" : "inetOrgPerson",
            "attributes" : {
                "name" : {
                    "attribute" : "givenName",
                },
                "sn" : {},
            },
        })

        u = User(la, "uid=test,dc=example,dc=com", uid="test", givenName="Hello")
        self.assertEquals(u.name, "Hello")
        self.assertEquals(u.sn, None)
        u.set_attr("sn", ["Bye"])
        self.assertEquals(u.sn, "Bye")
        u.name = "New Name"
        self.assertEquals(u.get_attr("givenName"), ["New Name"])
