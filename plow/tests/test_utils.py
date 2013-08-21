import unittest

from ldap import MOD_ADD, MOD_DELETE, MOD_REPLACE

from plow.utils import modify_modlist

class Test_ModifyModList(unittest.TestCase):
    def test_atomic_update(self):
        self.assertEquals(
            modify_modlist({"a":["val1", "val2"]},
                           {"a":["val2", "val3"]},
                          True),
            [(MOD_DELETE, "a", "val1"),
             (MOD_ADD,    "a", "val3")])


        self.assertEquals(
            modify_modlist({"a":["val1"]},
                           {},
                          True),
            [(MOD_DELETE, "a", "val1")])


    def test_normal_update(self):
        self.assertEquals(
            modify_modlist({"a":["val1", "val2"]},
                           {"a":["val2", "val3"]}),
            [(MOD_REPLACE, "a", ["val2", "val3"])])


if __name__ == '__main__':
    unittest.main()
