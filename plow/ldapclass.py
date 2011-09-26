import logging
LOG = logging.getLogger(__name__)
_ = lambda x: x

import ldap

from plow.errors import DNConflict
from plow.ldapadaptor import DEBUG2
from plow.utils import (
    smart_str_to_unicode,
    prepare_str_for_ldap,
    modify_modlist,
    dict_diff,
)


class LdapClassConfig(object):
    def __init__(self, attrs):
        self._attrs = attrs
        self.attributes = attrs.get("attributes", {})

    def __getattr__(self, attr):
        return self._attrs.get(attr)

    @property
    def objectClasses(self):
        return [self._attrs.get("objectClass", "top")] + self._attrs.get("extraClasses", [])

class StructuralObjectMixIn(object):
    def __contains__(self, other):
        other_dn = ldap.dn.str2dn(getattr(other, "dn", other))
        test_len = len(ldap.dn.str2dn(self.dn))
        if len(other_dn) <= test_len:
            # The other must have at least one more element, otherwise
            # it cannot be *in* this one
            return False

        else:
            return self._ldap.compare_dn(
                self.dn,
                ldap.dn.dn2str(other_dn[-test_len:])
                )

class MemberView(object):
    @classmethod
    def get_view_class(cls, name, attrdef):
        return type(
            "{0}MemberView".format(name.title()),
            (cls, ),
            {
                "_managed_attr":attrdef.get("attribute", name),
                "_remote_attr":attrdef.get("remote_attribute", "dn"),
                "_reverse_relation":attrdef.get("reverse_relation"),
                "_reverse_attr":attrdef.get("reverse_attribute", "dn"),
            }
        )

    @classmethod
    def get_property(cls):
        def getter(self):
            attr = "_{0}_view".format(cls._managed_attr)
            if hasattr(self, attr):
                return getattr(self, attr)
            
            view = cls(self)
            setattr(self, attr, view)
            return view

        def setter(self, member_list):
            attr = cls._managed_attr + "_view"
            self.set_attr(cls._managed_attr, member_list)
            setattr(self, attr, cls(self))


        return property(getter, setter)


    def __init__(self, ldapobject):
        self._obj = ldapobject
        self._map = dict(
            (self._normalize_attrvalue(value), value)
            for value in self._obj.get_attr(self._managed_attr, [])
        )

    def __iter__(self):
        return self._map.itervalues()

    def __len__(self):
        return len(self._map)

    @property
    def _normalize_attrvalue(self):
        if self._remote_attr == "dn":
            return self._obj._ldap.normalize_dn
        else:
            return self._obj._ldap.normalize_value

    @property
    def _normalize_rvalue(self):
        if self._reverse_attr == "dn":
            return self._obj._ldap.normalize_dn
        else:
            return self._obj._ldap.normalize_value

    def _get_attrvalue(self, obj):
        if isinstance(obj, LdapClass):
            if self._remote_attr == "dn":
                return obj.dn
            else:
                #XXX Unicode or no?
                return obj.get_attr(self._remote_attr)[0]
        else:
            return obj

    def _get_member_attr(self, obj):
        attr = self._get_attrvalue(obj)
        return attr, self._normalize_attrvalue(attr)

    def _get_reverse_attr(self):
        if self._reverse_attr == "dn":
            attr = self._obj.dn
        else:
            attr = self._obj.get_attr(self._reverse_attr)[0]

        return attr, self._normalize_rvalue(attr)

    def __contains__(self, member):
        dn, ndn = self._get_member_attr(member)
        return ndn in self._map

    def add(self, member):
        dn, ndn = self._get_member_attr(member)
        if ndn not in self._map:
            self._map[ndn] = dn
            members = self._obj.get_attr(self._managed_attr, [])
            self._obj.set_attr(self._managed_attr, members + [dn])

            # If we need to manually set a reverse relation, do it.
            if self._reverse_relation:
                attr = member.get_attr(self._reverse_relation, [])
                rval, nrval = self._get_reverse_attr()
                if nrval not in [self._normalize_rvalue(a) for a in attr]:
                    attr.append(rval)
                    member.set_attr(self._reverse_relation, attr)

    def clear(self):
        self._map = dict()
        self._obj.set_attr(self._managed_attr, [])

    def remove(self, member):
        dn, ndn = self._get_member_attr(member)
        if ndn in self._map:
            curdn = self._map.pop(ndn)
            members = self._obj.get_attr(self._managed_attr, [])
            members.remove(curdn)

            # If we need to manually unset a reverse relation, do it.
            if self._reverse_relation:
                attr = member.get_attr(self._reverse_relation, [])
                rval, nrval = self._get_reverse_attr()
                try:
                    attrs = [self._normalize_rvalue(a) for a in attr]
                    valpos = attrs.index(nrval)
                    attr.pop(valpos)
                    member.set_attr(self._reverse_relation, attr)
                except ValueError:
                    # Not in there
                    pass


class LdapType(type):

    @classmethod
    def from_config(typ, name, cfg):
        bases = (LdapClass, )
        attrs = {}
        cfg = LdapClassConfig(cfg)

        if getattr(cfg, "structural", False):
            bases = (StructuralObjectMixIn, ) + bases

        for aname, attrcfg in cfg.attributes.items():
            if attrcfg.get("relation") == "member":
                viewcls = MemberView.get_view_class(aname, attrcfg)
                attrs[aname] = viewcls.get_property()


        attrs["cfg"] = cfg
        return typ(name, bases, attrs)



def lower(key):
    try:
        return key.lower()
    except AttributeError:
        return key

class CaseInsensitiveDict(dict):
    """
    dict with case insensitive keys.
    """
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        self.keymapping = dict(
            (lower(key), key) for key in self
            )

    def __getitem__(self, key):
        key = self.keymapping.get(lower(key), key)
        return dict.__getitem__(self, key)

    def __setitem__(self, key, value):
        key = self.keymapping.setdefault(lower(key), key)
        dict.__setitem__(self, key, value)

    def __delitem__(self, key):
        key = self.keymapping.get(lower(key), key)
        dict.__delitem__(self, key)
        self.keymapping.pop(key, None)

    def __contains__(self, key):
        key = self.keymapping.get(lower(key), key)
        return dict.__contains__(self, key)

    def get(self, key, *args):
        key = self.keymapping.get(lower(key), key)
        return dict.get(self, key, *args)

    def pop(self, key, *args):
        key = self.keymapping.get(lower(key), key)
        return dict.pop(self, key, *args)


    def popitem(self):
        k, v = dict.popitem(self)
        self.pop(k, None)
        return (k, v)

    def update(self, E, **F):
        for key, val in CaseInsensitiveDict(E).iteritems():
            self[key] = val

        for key, val in CaseInsensitiveDict(**F).iteritems():
            self[key] = val

    def copy(self):
        return type(self)(self.iteritems())

class LdapClass(object):
    __metaclass__ = LdapType
    cfg = LdapClassConfig({})

    def __init__ (self, la, dn, attributes=None, **kwattrs):
        """Initialize instance."""
        self._ldap = la
        self._dn = dn
        self._attrs = CaseInsensitiveDict()

        range_attributes = []
        if attributes:
            for k, v in attributes.iteritems():
                if ";range=" in k:
                    range_attributes.append((k.split(";range=")[0], v))
                else:
                    self.set_attr(k, v)
        for k, v in kwattrs.iteritems():
            if ";range=" in k:
                range_attributes.append((k.split(";range=")[0], v))
            else:
                self.set_attr(k, v)
            self.set_attr(k, v)
        
        for k, v in range_attributes:
            self.set_attr(k, self.get_attr(k) + v)

        #print "__init__", dn, attributes
        
        for attrname in self._attrs:
            if isinstance(self._attrs[attrname], list): 
                self._attrs[attrname] = self._attrs[attrname][:]
        
        self._origattrs = self._attrs.copy()
        # Make sure to copy lists
        for key, val in self._origattrs.iteritems():
            if isinstance(val, list):
                self._origattrs[key] = val[:]


    @property
    def dn(self):
        return self._dn

    def _get_rdn(self, orig=True):
        if orig:
            return ldap.dn.dn2str(
                ldap.dn.str2dn(self.dn)[:1]
                )

        else:
            # Check if we have a rdn field
            rdn_field = self._get_rdn_field()
            return "{0}={1}".format(rdn_field, self.get_attr(rdn_field)[0])

    def _get_rdn_field(self):
        rdn_field = self.cfg.rdn or self.cfg.uid
        if not rdn_field:
            # Attempt to guess from dn
            rdn_field = ldap.dn.str2dn(self.dn)[0][0]

        return rdn_field

    rdn = property(fget=_get_rdn)

    @property
    def parentdn(self):
        if len(self.dn) == len(self._ldap.base_dn):
            return None

        #Strip the first component of the dn, return None if result is empty
        return ldap.dn.dn2str(ldap.dn.str2dn(self.dn)[1:]) or None

    @property
    def parentdnObj(self):
        if self.parentdn is None:
            return None
        return LdapClass.get(self.parentdn, la=self._ldap)

    @classmethod
    def get_base_dn(cls, la):
        # Get the base ou for this class if available, otherwise return the root DN only
        return la.base_dn

    @classmethod
    def get_objectClass_filter(cls):
        return "(&%s)" % ("".join(
            ["(objectClass=%s)" % c for c in cls.cfg.objectClasses ]
            ),
        )

    def get_attr(self, attr, default=None):
        """ Return an attribute list by key
        @param attr Attribute name to retrieve
        @param default Default value to return if the key does not exist

        @return tuple containing the values of the attribute for this key
        """
        return self._attrs.get(attr, default)

    def get_unicode_attr(self, attr, default=None):
        """ Call get_attr and convert the strings in the attr tuple to unicode, if possible. """
        attr = self.get_attr(attr, default)
        return [smart_str_to_unicode(a) for a in attr]
    
    def set_attr(self, key, value):
        """ Set an attribute by key, value
        @param key Attribute name to set
        @param value value to which the attribute will be set
        """
        #All attributes are stored as lists, so convert as necessary
        if isinstance(value, (list, tuple)):
            self._attrs[key] = [prepare_str_for_ldap(l) for l in value]
        else:
            self._attrs[key] =  [prepare_str_for_ldap(value),]

    def del_attr(self, key):
        del self._attrs[key]

    def has_attr(self, key):
        return self._attrs.has_key(key)

    def get_named_attr(self, attr, default=None):
        """ Return an attribute defined in the configuration file
        @param attr Configuration key for the attribute
        @param default Default value to pass to self.get_attr(attr, default)
        
        @return tuple containing the values of the attribute
        """
        return self.get_attr(self._ldap.get_option(attr), default)

    def set_named_attr(self, attr, value):
        """ Set an attribute defined in the configuration file
        @param attr Configuration key for the attribute
        @param value value to which the attribute will be set
        """
        return self.set_attr(self._ldap.get_option(attr), value)

    def _get_member_attr(self, key):
        """ Returns the target for attributes that act as Foreign Keys.
        For example, groups have the member attribute, which can refer to a
        cn, uid or dn depending on the schema. This will return this attribute.

        @param key The configuration key for the attribute
        @return (attribute name, foreign attribute name) or (None, None)
        """
        #Check if exists, first
        if self._ldap.has_option(key):
            prop = self._ldap.get_option(key)
            #Check that option is not empty
            if not prop:
                return None, None
            #Check which attribute must be used as a value
            if self._ldap.has_option(key + "_attr"):
                value = self._ldap.get_option(key + "_attr")
                if value:
                    return prop, value
            #No target attribute or empty attribute, default to 'dn'
            return prop, "dn"
        else:
            return None, None

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self._dn)

    def _rename(self, newuid, new_parentdn=None):
        olduid = self._get_rdn(orig=True)

        #Generate the new DN
        old_dn = ldap.dn.str2dn(self._dn)
        new_rdn = ldap.dn.str2dn(newuid)
        if old_dn and new_rdn:
            old_dn[0] = new_rdn[0]

            if new_parentdn is not None:
                parent = ldap.dn.str2dn(new_parentdn)
                old_dn[1:] = parent
        new_dn = ldap.dn.dn2str(old_dn)

        #Perform the rename
        try:
            self._ldap.rename(self.dn, newuid, new_parentdn)
        except ldap.ALREADY_EXISTS:
            raise DNConflict("DNConflict when renaming {0} to {1}".format(
                self.dn, new_dn))

        # Assign the new dn
        self._dn = new_dn

    def save(self, atomic=False):
        """ Attempt to save this object to the server.
        Params:
        - atomic: if supplied and true, force explicit value replacements,
                  which will fail if the data has changed on the server.
        """
        if self._ldap.is_dry_run():
            #Save the changed attributes as being "clean"
            self._origattrs = self._attrs.copy()
            return
        
        #Check if uid has changed. If so, rename
        new = self._attrs.copy()
        old = self._origattrs.copy()
        #Get the field that is used to calculate the RDN
        rdn_field = self._get_rdn_field()

        #Remove it from the attributes to change, rename will do it instead
        if new.has_key(rdn_field):
            del new[rdn_field]
        if old.has_key(rdn_field):
            del old[rdn_field]

        #If we changed a field that is used in the DN, we need to detect it
        # and perform a rename

        #Generate the full attr=value,attr=value strings for the rdn field
        olduid = self._get_rdn(orig=True)
        newuid = self._get_rdn(orig=False)

        #Perform the rename if the value has changed
        if olduid != newuid:
            self._rename(newuid)

        #Update values on the server if we changed other attributes
        if new != old:
            mod = modify_modlist(old, new, atomic)

            if mod:
                self._ldap.modify(self._dn, mod)

        #Save the changed attributes as being "clean"
        self._origattrs = self._attrs.copy()

    def move(self, parent_dn, addbase=False):
        """ Move this object to a new parent """
        new_parentdn = getattr(parent_dn, "dn", parent_dn)
        new_parentdn = prepare_str_for_ldap(new_parentdn)
        if addbase:
            new_parentdn = "{0},{1}".format(new_parentdn, self._ldap.base_dn)

        #TODO Check the parent object's type? (can it contain this?)
        self._rename(self.rdn, new_parentdn)
        

    def delete(self):
        """ Delete this object from the server """
        return self._ldap.delete(self._dn)[0]

    @classmethod
    def get(cls, dn=None, uid=None, la=None, addbase=False):
        """
            Retrieve a LdapObject by dn or uid
            @param dn object's dn
            @param uid object's unique identifier
            @param la LdapAdaptor to use
            @param addbase if True, the base is added to the dn


            You must provide either dn or uid.
            @return LdapObject or None
        """
        dn = prepare_str_for_ldap(dn)
        uid = prepare_str_for_ldap(uid)
        if dn:
            params = {"scope":ldap.SCOPE_BASE, 
                "filterstr":cls.get_objectClass_filter(),
                }
            if addbase:
                base = "{0},{1}".format(dn,cls.get_base_dn(la))
            else:
                base = dn
        elif uid:
            uid_field = cls.cfg.uid
            if uid_field is None:
                raise TypeError("Object uid field is not defined")
            params = {"scope":ldap.SCOPE_SUBTREE, 
                "filterstr":"(&(%(field)s=%(uid)s)%(objCls)s)" % {
                    "objCls":cls.get_objectClass_filter(),
                    "field":uid_field,
                    "uid":uid,
                }
            }
            base = cls.get_base_dn(la)
        else:
            raise TypeError("You must provide either a uid or dn.")
        #print "Searching", params, "in", base
        try:
            res = la.search(base, **params)
        except ldap.NO_SUCH_OBJECT, e:
            LOG.log(DEBUG2, _("Get failed for '{0}' with error: {1}").format(
                dn or uid,
                unicode(e),
                ))
            return None

        # Remove referals
        res = filter(lambda r: r[0] is not None, res)
        if len(res) < 1:
            #print "get", uid, dn, "result is none; params=", params, 'base=', base
            return None
        if len(res) == 1:
            return cls(la, res[0][0], res[0][1])
        if len(res) > 1:
            #Should not happen
            raise RuntimeError("More than one %s returned with %s in %s" % (cls.__name__, params["filterstr"], base ))

    @classmethod
    def create(cls, dn, attributes, la=None, addbase=False):
        """ Create an object.
            @param dn: Distinguished name of new user
            @param attributes: dictionary of attributes

            @return LdapObject
        """
        dn = prepare_str_for_ldap(dn)
        if addbase:
            dn = "{0},{1}".format(dn, cls.get_base_dn(la))

        attrs = CaseInsensitiveDict(objectClass=cls.cfg.objectClasses)
        for key, val in attributes.iteritems():
            attrs[key] = prepare_str_for_ldap(val)


        addlist = attrs.items()
        try:
            la.add(dn, addlist)
        except ldap.ALREADY_EXISTS:
            raise DNConflict("Add failed: an entry already exists at {0}".format(dn))
        
        # If we are in dry run mode
        if la.is_dry_run():
            # We return the same data that the function got
            return cls(la, dn, attrs)
        else:
            # Non-dry-run mode.
            # The object attributes may have been changed by the LDAP server.
            # We need to fetch the object anew from the server.
            return cls.get(dn, la=la)

    @classmethod
    def get_or_create(cls, dn, uid=None, attrs={}, la=None, addbase=False):
        """Fetch an object by uid (if not None) or by dn.
           Creates the object from the DN and the attributes if not found.
           
           If uid is defined, search will be done by uid.
           If uid is not defined, search will be done by dn.
           Creation is always done by dn.
        Returns:
            LdapObject, True if created
            LdapObject, False if found
        """
        
        res = None
        # Always find by dn to check for conflicts
        by_dn = cls.get(dn=dn, la=la, addbase=addbase)

        if uid:
            # Get by UID
            res = cls.get(uid=uid, la=la)

            if by_dn is not None:
                # We found by uid and by dn, make sure there is no conflict
                uid_field = cls.cfg.uid
                dn_uid = by_dn.get_attr(uid_field)[0]
                if uid != dn_uid:
                    # If we find something by DN and it has a different uid
                    # it is a conflict
                    raise DNConflict(_(
                            "An object with uid {uid} already exists at dn {dn}"
                        ).format(
                            dn=dn,
                            uid=dn_uid,
                        ))
        else:
            # Get by dn -> just use the result found earlier
            res = by_dn

        if res:
            return res, False
        else:
            return cls.create(dn, attrs, la=la, addbase=addbase), True

    @classmethod
    def search(cls, base=None, scope=None, filterstr=None, la=None): #left out attrlist, attrsonly
        """ Search for objects in the server
        @param base Base DN to search in (defaults to the base dn for the class)
        @param scope Search scope. Must be one of ldap.SCOPE_BASE (0), 
            ldap.SCOPE_ONELEVEL (1) or ldap.SCOPE_SUBTREE (2).
            default provided by LdapAdaptor.search() is ldap.SCOPE_SUBTREE
        @param filterstr Filter string, defaults to filtering objects of this
            class's objectClass
        @param la LdapAdaptor to use

        @return list of LdapObject instances
        """
        params = {}
        base = base or cls.get_base_dn(la)
        if not scope is None:
            params["scope"] = scope

        if filterstr:
            if not filterstr.strip().startswith("("):
                filterstr = "(%s)" % (filterstr.strip(), )

            params["filterstr"] = "(&%s%s)" % (
                filterstr, cls.get_objectClass_filter(),
                )
        else:
            params["filterstr"] = cls.get_objectClass_filter()

        # Allow searching in objects such as OU's
        if hasattr(base, "dn"):
            base = base.dn

        # The "if res[0]" part avoids returning referals
        return [cls(la,res[0],res[1]) for res in la.search(base, **params) if res[0]]


    def get_diff(self):
        """
        Return a diff of the attributes of this object in a tuple of 3 sets:
        added, changed, removed
        """
        return dict_diff(self._origattrs, self._attrs)


LdapObject = LdapType.from_config("LdapObject", {
    "objectClass" : "top",
    "rdn" : None,
    "uid" : None,
    "attributes" : {},
})
