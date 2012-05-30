from plow.ldapadaptor import LdapAdaptor as BaseAdaptor

class FakeLDAPSrv(object):
    def unbind(self):
        print "Unbound"

    def simple_bind_s(self, user, passwd):
        print "Bound as %s" % user


class LdapAdaptor(BaseAdaptor):
    def initialize(self, server):
        self._ldap = FakeLDAPSrv()
        self.is_connected = True

