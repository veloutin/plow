""" plow exceptions """


class DNConflict(Exception):
    """ Conflict in LDAP tree """

class LdapAdaptorError(Exception):
    """ Base class for LdapAdaptor exceptions """

