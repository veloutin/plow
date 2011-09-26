import ldap

def smart_str_to_unicode(s):
    """ Convert to unicode if applicable; else leave as str.
        It is safe to call this function more than once on the same value. 
    
        Here are the expected results of calling this function (see also the "tests" directory) :
        
         input None : return None
        >>> smart_str_to_unicode(None)
        None
        
         input an instance of another type than str or unicode : return the instance
        >>> smart_str_to_unicode(Exception("An exception"))
        Exception('An exception',)
        
         input ascii str : return ascii str
        >>> smart_str_to_unicode("some string")
        "some string"
        
         input str with utf-8 encoded accents : return unicode string 
        >>> smart_str_to_unicode("some string \xc3\xa9\xc3\xa0\xc3\xa2!")
        u"some string \xe9\xe0\xe2!"
        
         input str with latin1 encoded accents : raises UnicodeDecodeError
         The AD is not expected to return such a string.
        >>> smart_str_to_unicode("some string \xe9\xe0\xe2!")
        UnicodeDecodeError : 'utf8' codec can't decode bytes in position 12-14: invalid data
        
         input unicode string with ascii characters : return the same unicode string
        >>> smart_str_to_unicode(u"some string")
        u"some string"

         input unicode string with accented characters : return the same unicode string
         No conversion is needed as python-ldap does not support unicode strings.
        >>> smart_str_to_unicode(u"some string \xe9\xe0\xe2!")
        u"some string \xe9\xe0\xe2!"

         input broken unicode string : return the same unicode string
        >>> smart_str_to_unicode(u"some string \xc3\xa9\xc3\xa0\xc3\xa2!")
        u"some string \xc3\xa9\xc3\xa0\xc3\xa2!"
    """

    # FIXME: Works for AD, needs testing for OpenLDAP
    
    if isinstance(s, unicode):
        # No conversion is done as python-ldap does not support unicode strings
        return s
    elif isinstance(s, str):
        s = unicode(s, 'utf-8')
        try:
            s = str(s)
        except UnicodeEncodeError as e:
            # Will return as unicode
            pass
    return s

def prepare_str_for_ldap(s):
    """ Prepare a str/unicode to send it to python-ldap, who does not support unicode strings.
        It is very important to call this function only ONCE on the data, else the string
        will be double-encoded and the data will become invalid.
        
        Here are the expected results of calling this function (see also the tests directory) :
        
         input None : return None 
        >>> prepare_str_for_ldap(None)
        None
        
         input an instance of another type than str or unicode : return the str representation of the object
        >>> prepare_str_for_ldap(Exception("An exception"))
        "An exception"
        
         input an ascii str : return ascii str
        >>> prepare_str_for_ldap("some string")
        "some string"
        
         input a str with latin1 encoded characters : return the same str
         ==> WARNING: This type of str will NOT work in AD
        >>> prepare_str_for_ldap("some string \xe9\xe0\xe2!")
        "some string \xe9\xe0\xe2!"
        
         input a str with utf-8 encoded characters : return the same str
          ==> This is the format required by AD
        >>> prepare_str_for_ldap("some string \xc3\xa9\xc3\xa0\xc3\xa2!")
        "some string\xc3\xa9\xc3\xa0\xc3\xa2!")
        
         input a unicode string with ascii characters : return ascii str  
        >>> prepare_str_for_ldap(u"some string")
        "some string"
            
         input a unicode string with accented characters : return a str with utf-8 encoded characters
        >>> prepare_str_for_ldap(u"some string \xe9\xe0\xe2!")
        "some string \xc3\xa9\xc3\xa0\xc3\xa2!")
        
         input a unicode string with double encoded characters (using u on already utf-8 characters) :
           return a str with double-encoded utf-8 characters
         ==> The input unicode string is already broken; garbage in, garbage out.
        >>> prepare_str_for_ldap(u"some string \xc3\xa9\xc3\xa0\xc3\xa2!")
        "some string \xc3\x83\xc2\xa9\xc3\x83\xc2\xa0\xc3\x83\xc2\xa2!")
    """
    

    if s is None:
        return s
    
    if isinstance(s, unicode):
        s = s.encode('utf-8')

    if isinstance(s, (list, tuple)):
        return [prepare_str_for_ldap(v) for v in s]

    return str(s)

def dict_diff(old, new):
    orig = set(old)
    curr = set(new)
    return (
        curr - orig,
        set([k for k in orig & curr if set(old[k]) != set(new[k])]),
        orig - curr,
    )


def modify_modlist(old, new, atomic=False):
    newattrs, upd, rem = dict_diff(old, new)
    if atomic:
        # in atomic mode, we remove all existing values to replace them
        # with new values in update ops
        mod = [
            (ldap.MOD_DELETE, attrname, value)
            for attrname in (upd | rem)
            for value in old[attrname]
        ] + [
            (ldap.MOD_ADD, attrname, value)
            for attrname in (newattrs | upd)
            for value in new[attrname]
        ]
    else:
        mod = [
            # Delete attributes that are to be removed
            (ldap.MOD_DELETE, attrname, None)
            for attrname in rem
        ] + [
            # For updates, remove values that are not in the new attrs
            (ldap.MOD_DELETE, attrname, value)
            for attrname in upd
            for value in set(old[attrname]) - set(new[attrname])
        ] + [
            # For updates, add values that weren't in the old attrs
            (ldap.MOD_ADD, attrname, value)
            for attrname in upd
            for value in set(new[attrname]) - set(old[attrname])
        ] + [
            # Add new attribute values
            (ldap.MOD_ADD, attrname, value)
            for attrname in newattrs
            for value in new[attrname]
        ]

    return mod
