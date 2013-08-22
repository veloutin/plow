## What is PLOW? ##

PLOW stands for python-ldap object wrapper. As the name implies, it provides
an object wrapper around the python-ldap lib for simpler usage.

Build status: [![Build Status](https://travis-ci.org/veloutin/plow.png)](https://travis-ci.org/veloutin/plow)

## Example Usage ##


    from plow.ldapadaptor import LdapAdaptor
    from plow.ldapclass import LdapType

    srv = LdapAdaptor(
        'ldaps://localhost',
         base_dn='dc=example,dc=com',
         bind_user='cn=manager,dc=example,dc=com',
         bind_password='password',
         )

    User = LdapType.from_config("User",  {
            "rdn" : "uid",
            "uid" : "uid",
            "objectClass" : "inetOrgPerson",
            "attributes" : {
                "name" : {
                    "attribute" : "givenName",
                }
            }
        })

    Group = LdapType.from_config("Group", {
            "rdn" : "cn",
            "uid" : "cn",
            "objectClass" : "posixGroup",
            "attributes" : {
                "members" : {
                    "relation" : "member",
                    "attribute" : "memberUid",
                    "remote_attribute" : "uid",
                }
            }
        })

    OU = LdapType.fromConfig("OU", {
        "rdn" : "ou",
        "objectClass" : "organizationalUnit",
        "structural" : True,
        "attributes" : {},
    })

    user = User.get(uid='veloutin', la=srv)
    print "What's my name?", user.name
    group = Group.get(uid='employees', la=srv)

    if user not in group.members:
        group.members.add(user)
        group.save()

    base = OU.get("ou=People", la=srv, addbase=True)
    print user in base
