import unittest
from plow.ldapclass import LdapType, CaseInsensitiveDict
from .mocks import LdapAdaptor, FakeLDAPSrv


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
    def setUp(self):
        self.la = LdapAdaptor("ldap://localhost", "dc=example,dc=com")
        self.srv = self.la._ldap

        self.User = LdapType.from_config("User", {
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

    def test_attrs(self):
        u = self.User(self.la, "uid=test,dc=example,dc=com",
                      uid="test", givenName="Hello")
        self.assertEquals(u.name, "Hello")
        self.assertEquals(u.sn, None)
        u.set_attr("sn", ["Bye"])
        self.assertEquals(u.sn, "Bye")
        u.name = "New Name"
        self.assertEquals(u.get_attr("givenName"), ["New Name"])

    def test_modify_uid(self):
        u = self.User(self.la, "uid=test,dc=example,dc=com",
                      uid="test", givenName="Hello")
        self.srv.data[u.dn] = u._attrs.copy()

        u.set_attr("uid", "test2")
        u.save()

        newdat = self.srv.data[u.dn]
        self.assertEquals(newdat["uid"], ["test2"])

    def test_modify_uid2(self):
        """Test modification of the uid attr when it is not part of the DN"""
        u = self.User(self.la, "cn=Test User,dc=example,dc=com",
                      uid="test", cn="Test User")
        self.srv.data[u.dn] = u._attrs.copy()

        u.set_attr("uid", "test2")
        u.save()

        newdat = self.srv.data[u.dn]
        # Currently we force the rdn
        self.assertEquals(u.dn, "uid=test2,dc=example,dc=com")
        self.assertEquals(newdat["uid"], ["test2"])
        self.assertEquals(newdat["cn"], ["Test User"])


    def test_modify_preserve(self):
        """Test preservation of rdn"""
        u = self.User(self.la, "cn=Test User,dc=example,dc=com",
                      uid="test", cn="Test User")
        self.srv.data[u.dn] = u._attrs.copy()

        dn = u.dn
        u.set_attr("uid", "test2")
        u.save(preserve_rdn=True)

        self.assertEquals(dn, u.dn, "DN should not change")

        newdat = self.srv.data[u.dn]
        self.assertEquals(newdat["uid"], ["test2"])


    def test_modify_preserve_partial(self):
        """Test preservation of multi-part rdn with uid in it"""
        u = self.User(self.la, "cn=Test User+uid=test,dc=example,dc=com",
                      uid="test", cn="Test User")
        self.srv.data[u.dn] = u._attrs.copy()

        u.set_attr("uid", "test2")
        u.save(preserve_rdn=True)

        self.assertEquals(u.dn, "cn=Test User+uid=test2,dc=example,dc=com")

        newdat = self.srv.data[u.dn]
        self.assertEquals(newdat["uid"], ["test2"])
        self.assertEquals(newdat["cn"], ["Test User"])
