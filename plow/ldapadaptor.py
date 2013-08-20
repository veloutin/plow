""" the ldapadaptor module handles low-level LDAP operations """

from functools import wraps
import operator
import re
import logging
LOG = logging.getLogger(__name__)

import ldap
import ldap.filter
import ldap.dn

from ldap.controls import SimplePagedResultsControl as PagedCtrl

from plow.errors import LdapAdaptorError

try:
    ldap.CONTROL_PAGEDRESULTS
    make_page_control = PagedCtrl
    get_page_control = operator.attrgetter("size", "cookie")
except AttributeError:
    # seems like we are in < 2.4 version
    def PCtrlAdapter(criticality, size, cookie):
        return PagedCtrl(PagedCtrl.controlType, criticality, (size, cookie))

    make_page_control = PCtrlAdapter
    get_page_control = operator.attrgetter("controlValue")

RANGED_ATTR = re.compile("(?P<name>.*);range=(?P<start>\d+)-(?P<end>\*|\d+)$")

def get_new_ranges(attrs):
    """ Returns a list of attributes that need to be fetched to complete
    the attribute dict `attrs`. Those are all the attributes in the form
        attrname;range=start-end
    where end isn't *.
    The new list will be the following ranges in the format
        attrname;range=newstart-*
    """
    extra = [
        m.groupdict()
        for m in
            (RANGED_ATTR.match(attrname) for attrname in attrs)
        if m is not None
    ]

    return [
        "{name};range={start}-*".format(
            name = d["name"],
            start = int(d["end"]) + 1,
        )
        for d in extra
        if d["end"] != "*"
    ]


def check_connected(f):
    """ Utility decorator to retry connection on ldap.SERVER_DOWN """
    @wraps(f)
    def _newcall_(self, *args, **kwargs):
        if not self.is_connected:
            LOG.debug("check_connected -> not connected")
            self.initialize(self._server_url)
            self.bind(self._binduser, self._bindpw)
        try:
            return f(self, *args, **kwargs)
        except ldap.SERVER_DOWN, down:
            LOG.debug("check_connected -> server down")
            #Make a reconnect attempt
            self.is_connected = False
            self.initialize(self._server_url)
            self.bind(self._binduser, self._bindpw)
        return f(self, *args, **kwargs)
    return _newcall_

class LdapAdaptor(object):
    def __init__ (self,
                  server_uri,
                  base_dn,
                  bind_user=None,
                  bind_password=None,
                  certificate_validation=False,
                  referrals=None,
                  case_insensitive_dn=False,
                  dry_run=False,
                 ):
        """
        Creates the instance, initializing a connection and binding to the LDAP
        server.
        """
        self._connected = False
        self._bound = False
        self._ldap = None
        self._server_url = server_uri
        self._binduser, self._bindpw = bind_user, bind_password
        self._base_dn = base_dn
        self._cert_validation = certificate_validation
        self._case_insensitive_dn = case_insensitive_dn
        self._referrals = referrals

        # FIXME : Defer initialization until connection is needed
        self.initialize (self._server_url)
        self.bind(self._binduser, self._bindpw)
        self._dry_run = dry_run

    def is_dry_run(self):
        if hasattr(self._dry_run, "__call__"):
            return self._dry_run()
        else:
            return self._dry_run

    def _dry_run_msg(self):
        if self.is_dry_run():
            return "DRY-RUN "
        else:
            return ""

    def __del__(self):
        if self._ldap:
            self._ldap.unbind()

    def __str__(self):
        return "<LdapAdaptor: {0}>".format(self._server_url)
    
    def __repr__(self):
        return str(self)

    def initialize (self, server, p_version=ldap.VERSION3):
        """
        Initializes the LDAP system and returns an LDAPObject.
        
        Uses the initialize() function, which takes a simple LDAP URL (in the
        format protocol://host:port) as a parameter. A safe connection can be
        done using an ldaps:// protocol instead of ldap://.  Standard
        ldap.VERSION is 3, but can be changed passing the desired version
        as a parameter.
        """
        LOG.info("Initializing connection with server %s ..." % server)
        try:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            if self._referrals is None:
                ldap.set_option(ldap.OPT_REFERRALS, ldap.DEREF_NEVER)
            else:
                ldap.set_option(ldap.OPT_REFERRALS, self._referrals)

            #ldap.initialize will only raise an exception with a bad formed URL
            self._ldap = ldap.initialize (server)
            self.is_connected = True
        except ldap.LDAPError,  e:
            LOG.error("Caught ldap error: %s", str(e))
            raise
        self._ldap.protocol_version = p_version

    # FIXME: the client of the interface doesn't care to bind and unbind :
    # should be managed internaly If the client code tries to do a
    # client.add() call without a client.bind(), it will fail and it's bad.
    def bind (self, user_dn, user_passwd): 
        """
        Binds to the LDAP directory.
        
        Once we have an LDAPObject instance, we need to bind to the LDAP server. The
        python-ldap API supports both simple and SASL binding methods.
        """
        LOG.info("Binding to the server with user %s ..." % user_dn)

        if not self.is_connected:
            self.initialize(self._server_url)

        try:
            self._ldap.simple_bind_s (user_dn, user_passwd)
        except ldap.LDAPError, e:
            self.is_connected = False
            LOG.error("Caught ldap error: %s", str(e))
            raise

    def unbind (self):
        """
        Unbinds and closes the connection to the LDAP server.
        """
        LOG.info("Unbinding from the server")
        if not self.is_connected:
            LOG.debug("Not Connected")
            return

        try:
            self._ldap.unbind()
            self._ldap = None
        except ldap.SERVER_DOWN, e:
            LOG.warn("Caught SERVER_DOWN, ignoring")
        except ldap.LDAPError, e:
            LOG.error("Caught ldap error: %s", str(e))
            raise
        finally:
            # we can't rely on this being connected after an error
            # or a successful unbind
            self.is_connected = False

    @check_connected
    def add (self, dn, add_record):
        """
        Perform an add operation.

        add_record must be a list of tuples, where the first element of the tuple
        must be an attribute and the second element of the tuple must be the value
        of the attribute, which can be a list or a string.
        Hint: you may use ldap.modlist addModList() function to convert a data
        structure in the format of a dictionnary in the format used here by
        add_record.
        """
        LOG.debug("%(dry_run_msg)sAdding %(dn)s:  %(data)s..." %
            {"dry_run_msg": self._dry_run_msg(),
             "dn": dn, "data": repr(add_record)})
        if self.is_dry_run():
            return
        try:
            result_type, result_data = self._ldap.add_s(dn, add_record)
            if result_type != ldap.RES_ADD:
                raise LdapAdaptorError(
                    "add: unexpected result %(type)s : %(result)s" %
                    {"type": str(result_type), "result": result_data})
        except ldap.ALREADY_EXISTS, e:
            LOG.error("Record already exists")
            raise

    @check_connected
    def delete (self, dn):
        """
        Delete an ldap entry.
        """
        LOG.debug("{dryrunmsg}Deleting {dn}..."
                        .format(dryrunmsg = self._dry_run_msg(), dn = dn))
        if self.is_dry_run():
            return
        try:
            res = self._ldap.delete_s (dn)
            result_type, result_data = res[0], res[1]
            if result_type != ldap.RES_DELETE:
                raise LdapAdaptorError(
                    "delete : unexpected result %(type)s : %(result)s" %
                     {"type": str(result_type), "result": result_data})
        except ldap.LDAPError, e:
            LOG.error("Caught ldap error: %s", str(e))
            raise

    @check_connected
    def modify (self, dn, mod_attrs):
        """ Modify ldap attributes

        mod_attrs is a list of modification three-tuples
        (modification type, attribute name, value)

        The modification type can be one of the followings:
        - ldap.MOD_ADD : add the value to an attribute, if the schema allows
        - ldap.MOD_DELETE : remove the value from the attribute, if it exists
        - ldap.MOD_REPLACE : the value replaces old values of the attribute
        - ldap.MOD_INCREMENT (code 3).
        Hint: ldap.modlist's modifyModList() can be used to convert a data
        strucutre in the format of a dictionnary in the format used here by
        mod_attrs.
        """
        LOG.debug("%(dry_run_msg)sModifying %(dn)s: %(attrs)s" %
            {"dry_run_msg": self._dry_run_msg(),
             "dn": dn, "attrs": str(mod_attrs)})
        if self.is_dry_run():
            return
        try:
            res = self._ldap.modify_s (dn, mod_attrs)
            result_type, result_data = res[0], res[1]
            if result_type != ldap.RES_MODIFY:
                raise LdapAdaptorError(
                    "modify: unexpected result %(type)s : %(result)s" %
                    {"type": str(result_type), "result": result_data})
        except ldap.LDAPError, e:
            LOG.error("Caught ldap error: %s", str(e))
            raise

    @check_connected
    def rename (self, dn, new_dn, newparentdn=None, delold=1):
        """
        Perform a modify RDN operation.
        """
        LOG.debug(
            "%(dry_run)sModifying dn %(dn)s to %(new_dn)s%(newparentdn)s..." %
            {"dry_run": self._dry_run_msg(),
             "dn": dn, "new_dn": new_dn,
             "newparentdn": newparentdn and "," + newparentdn or "" })
        if self.is_dry_run():
            return [True, None]
        try:
            res = self._ldap.rename_s(dn,
                                      new_dn,
                                      newparentdn,
                                      delold)
            result_type, result_data = res[0], res[1]
            if result_type != ldap.RES_MODRDN:
                raise LdapAdaptorError(
                    "rename: unexpected result %(type)s : %(result)s" %
                    {"type": str(result_type), "result": result_data})
        except ldap.LDAPError, e:
            LOG.error("Caught ldap error: %s", str(e))
            raise

    @check_connected
    def search (self,
                base_dn=None,
                scope=ldap.SCOPE_SUBTREE,
                filterstr='(objectClass=*)',
                attrs=None,
                page_size=1000):
        """
        search([base_dn [, scope [, filterstr [, attrs [, page_size]]]]])
        Search for entries

        Scope can be one of the followings:
        - SCOPE_BASE (to search the object itself);
        - SCOPE_ONELEVEL (to search the object's immediate children);
        - SCOPE_SUBTREE (to search the object and all its descendants).
        Return list of results
        """
        base_dn = base_dn or self._base_dn
        LOG.debug(
            "Searching for %(filter)s (%(attrs)s) on %(dn)s ..." %
            {"filter": filterstr, "attrs": attrs, "dn": base_dn})

        all_res = []
        page_cookie = ''

        while True:

            # Use?
            #filterstr = ldap.filter.escape_filter_chars(filterstr)
            paging_ctrl = make_page_control(False, page_size, page_cookie)
            query_id = self._ldap.search_ext(base_dn,
                                             scope,
                                             filterstr,
                                             attrs,
                                             serverctrls=[paging_ctrl])
            x, res, y, ctrls = self._ldap.result3(query_id)

            for dn, obj_attrs in res:
                if dn is None:
                    continue

                # Pesky attributes might be ranges, we need to see about that
                new_ranges = get_new_ranges(obj_attrs)
                while new_ranges:
                    new_res = self._ldap.search_s(dn,
                                                  ldap.SCOPE_BASE,
                                                  attrlist=new_ranges)
                    if len(new_res) != 1 or new_res[0][0] is None:
                        LOG.warn("get extra attr failed for {0}".format(dn))
                        break

                    new_attrs = new_res[0][1]
                    obj_attrs.update(new_attrs)
                    new_ranges = get_new_ranges(new_attrs)

            all_res += res

            # extract cookie if supplied by server
            page_cookie = ''
            for ext in ctrls:
                if isinstance(ext, PagedCtrl):
                    x, page_cookie = get_page_control(ext)
            if not page_cookie:
                break #Paging not supported or end of paging

        return all_res

    @check_connected
    def compare (self, dn, attr_name, attr_value):
        """
        Return True if dn has attr_name with attr_value or False otherwise.
        
        Verify in the directory server if the given DN has an attribute with
        the given attribute name, and the given attribute value.
        """
        LOG.debug(
            "Verifying if %(dn)s has attribute %(attr_name)s=%(attr_val)s ..."
             % {"dn": dn, "attr_name": attr_name, "attr_val": attr_value}
        )
        try:
            return self._ldap.compare_s (dn, attr_name, attr_value)
        except ldap.LDAPError, e:
            LOG.error("Caught ldap error: %s", str(e))
            raise

    @check_connected
    def passwd(self, dn, newpass, oldpass=None):
        try:
            self._ldap.passwd_s(dn, oldpass, newpass)
        except ldap.LDAPError, e:
            LOG.error("Caught ldap error: %s", str(e))
            raise

    def get_error (self, e):
        """Try to identify error description from exception and return it."""
        raise DeprecationWarning("get_error is deprecated")

    def _set_verbose(self, v):
        pass
    def _get_verbose(self):
        return True
    verbose = property(fset=_set_verbose, fget=_get_verbose)
    def _get_base_dn(self):
        return self._base_dn
    base_dn = property(fget=_get_base_dn)
    def _get_connected(self):
        return self._connected
    def _set_connected(self, value):
        self._connected = value
    is_connected = property(fget=_get_connected, fset=_set_connected)


    @property
    def is_case_insensitive(self):
        return self._case_insensitive_dn

    def normalize_value(self, val):
        if self.is_case_insensitive:
            return val.lower()
        else:
            return val

    def normalize_dn(self, dn):
        attr = lambda name:name.lower()

        handle_parts = lambda l: [
            (attr(a), self.normalize_value(v), t) for a, v, t in l
        ]
        return ldap.dn.dn2str(
            handle_parts(part) for part in ldap.dn.str2dn(dn)
        )

    def compare_dn(self, dn, other):
        # Normalize dn's to standard
        return self.normalize_dn(dn) == self.normalize_dn(other)

