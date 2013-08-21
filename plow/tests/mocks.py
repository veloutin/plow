import ldap
import logging
log = logging.getLogger("plow.tests.mocks")

def add(d, key, val):
    log.debug("++ add %s %s %s", d, key, val)
    d.setdefault(key, []).append(val)

def delete(d, key, val):
    log.debug("++ delete %s %s %s", d, key, val)
    try:
        if val is None:
            del d[key]

        else:
            d[key].remove(val)

    except (KeyError, ValueError):
        raise ldap.NO_SUCH_ATTRIBUTE(key)

def replace(d, key, val):
    log.debug("++ set %s %s %s", d, key, val)
    d[key] = val[:]

OPS = {
    ldap.MOD_ADD : add,
    ldap.MOD_DELETE : delete,
    ldap.MOD_REPLACE : replace,
}

from plow.ldapadaptor import LdapAdaptor as BaseAdaptor

class FakeLDAPSrv(object):
    def __init__(self):
        self._data = {}

    @property
    def data(self):
        log.debug("DB: %r",  self._data)
        return self._data

    def unbind(self):
        log.info("Unbound")

    def simple_bind_s(self, user, passwd):
        log.info("Bound as %s", user)
        return (ldap.RES_BIND, [])

    def rename_s(self, dn, newrdn, newsuperior=None, delold=1, *ctrls):
        log.info("rename: dn=%r newrdn=%r newsuperior=%r delold=%r",
                 dn, newrdn, newsuperior, delold)
        try:
            dat = self.data.pop(dn)
        except KeyError:
            raise ldap.NO_SUCH_OBJECT(dn)

        log.debug("Current data: %s", dat)
        newparts = ldap.dn.str2dn(newrdn)
        for key, val, _ in newparts[0]:
            attrval = dat.setdefault(key, [])
            if val not in attrval:
                log.debug("~~~ append %r %r %r", key, attrval, val)
                attrval.append(val)

        if delold:
            for key, val, _ in ldap.dn.str2dn(dn)[0]:
                log.debug("delold %s %s %s", dat, key, val)
                try:
                    log.debug('~~~ remove %r %r %r', dat, key, val)
                    dat[key].remove(val)
                except ValueError:
                    log.warn('missing value: %s %s', key, val)
                else:
                    if not dat[key]:
                        log.debug("clear empty: %s %s", dat, key)
                        del dat[key]


        dnparts = ldap.dn.str2dn(dn)
        dnparts[:1] = newparts
        if newsuperior:
            dnparts[1:] = ldap.dn.str2dn(newsuperior)

        newdn = ldap.dn.dn2str(dnparts)
        self.data[newdn] = dat
        log.debug("New data: %s", dat)

        return (ldap.RES_MODRDN, [])

    def modify_s(self, dn, modlist):
        log.info("modify: %s %r", dn, modlist)
        try:
            dat = self.data[dn]
        except KeyError:
            raise ldap.NO_SUCH_OBJECT(dn)
        else:
            orig = dict((k, v[:]) for k, v in dat.iteritems())

        for op, key, val in modlist:
            OPS[op](dat, key, val)

        for attr, val, _ in ldap.dn.str2dn(dn)[0]:
            if not val in dat.get(attr, []):
                self.data[dn] = orig
                raise ldap.NAMING_VIOLATION(dn, attr, val)

        return (ldap.RES_MODIFY, [])

class LdapAdaptor(BaseAdaptor):
    def initialize(self, server):
        self._ldap = FakeLDAPSrv()
        self.is_connected = True

