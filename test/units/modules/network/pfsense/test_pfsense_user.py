# Copyright: (c) 2020, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from xml.etree.ElementTree import fromstring, ElementTree
from units.compat.mock import patch
from ansible.modules.network.pfsense import pfsense_user
from .pfsense_module import TestPFSenseModule, load_fixture

#def args_from_var(var, state='present', **kwargs):
#    """ return arguments for pfsense_user module from var """
#    args = {}
#    for field in ['name', 'descr', 'scope', 'uid', 'groups', ]:
#        if field in var and (state == 'present' or field == 'name'):
#            args[field] = var[field]
#
#    args['state'] = state
#    for key, value in kwargs.items():
#        args[key] = value
#
#    return args

class TestPFSenseUserModule(TestPFSenseModule):

    module = pfsense_user

    def __init__(self, *args, **kwargs):
        super(TestPFSenseUserModule, self).__init__(*args, **kwargs)
        self.config_file = 'pfsense_user_config.xml'
        self.pfmodule = pfsense_user.PFSenseUserModule

    @staticmethod
    def runTest():
        """ dummy function needed to instantiate this test module from another in python 2.7 """
        pass

    def get_target_elt(self, obj, absent=False):
        """ return target elt from XML """
        root_elt = self.assert_find_xml_elt(self.xml_result, 'system')
        result = root_elt.findall("user[name='{0}']".format(obj['name']))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.fail('Found multiple users for name {0}.'.format(obj['name']))
        else:
            return None

    def check_target_elt(self, params, target_elt):
        """ check XML definition of target elt """

        self.check_param_equal(params, target_elt, 'name')
        self.check_param_equal(params, target_elt, 'descr')
        self.check_param_equal(params, target_elt, 'scope', default='user')
        self.check_param_equal(params, target_elt, 'uid', default='2001')
        # TODO - need to load groups
        #self.check_param_equal(params, target_elt, 'groups')
        self.check_param_equal(params, target_elt, 'password', xml_field='bcrypt-hash')
        self.check_list_param_equal_or_not_find(params, target_elt, 'priv')
        self.check_param_equal_or_not_find(params, target_elt, 'authorizedkeys')

    ##############
    # tests
    #
    def test_user_create(self):
        """ test creation of a new user """
        obj = dict(name='user1', descr='User One', password='$2b$12$D2jkq4Iut3ODUBN0BCrDk.bV3J5N.MrY5YEnGvTXwxeNBkyxjbbtW')
        self.do_module_test(obj, command="create user 'user1', descr='User One'")

    def test_user_delete(self):
        """ test deletion of a user """
        obj = dict(name='testdel')
        self.do_module_test(obj, command="delete user 'testdel'", delete=True)

    def test_user_update_noop(self):
        """ test not updating a user """
        obj = dict(name='testdel', descr='Delete Me', uid='2000')
        self.do_module_test(obj, command="delete user 'testdel'", changed=False)

    def test_user_update_descr(self):
        """ test updating descr of a user """
        obj = dict(name='testdel', descr='Keep Me', uid='2000', password='$2b$12$D2jkq4Iut3ODUBN0BCrDk.bV3J5N.MrY5YEnGvTXwxeNBkyxjbbtW', priv=['page-dashboard-all'])
        self.do_module_test(obj, command="update user 'testdel' set descr='Keep Me'")

    ##############
    # misc
    #
    def test_create_user_invalid_password(self):
        """ test creation of a new user with invalid password """
        obj = dict(name='user1', descr='User One', password='password')
        self.do_module_test(obj, command="update user 'testdel'", failed=True, msg='Password (password) does not appear to be a bcrypt hash')

    def test_delete_inexistent_user(self):
        """ test deletion of an inexistent user """
        obj = dict(name='nouser')
        self.do_module_test(obj, state='absent', changed=False)
