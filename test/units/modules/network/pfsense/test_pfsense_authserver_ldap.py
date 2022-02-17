# Copyright: (c) 2022, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from xml.etree.ElementTree import fromstring, ElementTree
from units.compat.mock import patch
from ansible.modules.network.pfsense import pfsense_authserver_ldap
from .pfsense_module import TestPFSenseModule, load_fixture


class TestPFSenseAuthserverLDAPModule(TestPFSenseModule):

    module = pfsense_authserver_ldap

    def __init__(self, *args, **kwargs):
        super(TestPFSenseAuthserverLDAPModule, self).__init__(*args, **kwargs)
        self.config_file = 'pfsense_authserver_config.xml'
        self.pfmodule = pfsense_authserver_ldap.PFSenseAuthserverLDAPModule

    @staticmethod
    def runTest():
        """ dummy function needed to instantiate this test module from another in python 2.7 """
        pass

    def get_target_elt(self, obj, absent=False):
        """ return target elt from XML """
        root_elt = self.assert_find_xml_elt(self.xml_result, 'system')
        result = root_elt.findall("authserver[name='{0}']".format(obj['name']))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.fail('Found multiple authservers for name {0}.'.format(obj['name']))
        else:
            return None

    def check_target_elt(self, params, target_elt):
        """ check XML definition of target elt """

        urltype = dict({'tcp': 'Standard TCP', 'starttls': 'STARTTLS Encrypted', 'ssl': 'SSL/TLS Encrypted'})
        self.check_param_equal(params, target_elt, 'name')
        self.assert_xml_elt_match(target_elt, 'refid', r'[0-9a-f]{13}')
        self.assert_xml_elt_equal(target_elt, 'type', 'ldap')
        self.check_param_equal(params, target_elt, 'ldap_caref', default='global')
        self.check_param_equal(params, target_elt, 'host')
        self.check_param_equal(params, target_elt, 'port', xml_field='ldap_port', default=389)
        self.assert_xml_elt_equal(target_elt, 'ldap_urltype', urltype[params['transport']])
        self.check_param_equal(params, target_elt, 'protover', xml_field='ldap_protver', default=3)
        self.check_param_equal(params, target_elt, 'scope', xml_field='ldap_scope', default='one')
        self.check_param_equal(params, target_elt, 'basedn', xml_field='ldap_basedn', default=None)
        self.check_param_equal(params, target_elt, 'authcn', xml_field='ldap_authcn')
        self.check_param_bool(params, target_elt, 'extended_enabled', xml_field='ldap_extended_enabled', value_true='yes')
        self.check_param_equal(params, target_elt, 'extended_query', xml_field='ldap_extended_query')
        self.check_param_equal(params, target_elt, 'attr_user', xml_field='ldap_attr_user', default='cn')
        self.check_param_equal(params, target_elt, 'attr_group', xml_field='ldap_attr_group', default='cn')
        self.check_param_equal(params, target_elt, 'attr_member', xml_field='ldap_attr_member', default='member')
        self.check_param_equal(params, target_elt, 'attr_groupobj', xml_field='ldap_attr_groupobj', default='posixGroup')
        self.check_param_equal(params, target_elt, 'pam_groupdn', xml_field='ldap_pam_groupdn', default=None)
        self.check_param_bool(params, target_elt, 'allow_unauthenticated', xml_field='ldap_allow_unauthenticated', default=True)
        self.check_param_equal(params, target_elt, 'timeout', xml_field='ldap_timeout', default=25)

    ##############
    # tests
    #
    def test_authserver_create(self):
        """ test creation of a new authserver """
        obj = dict(name='authserver1', host='ldap.example.com', transport='tcp', scope='one', authcn='CN=Users')
        self.do_module_test(obj, command="create authserver_ldap 'authserver1'")

    def test_authserver_delete(self):
        """ test deletion of a authserver """
        obj = dict(name='DELLDAP')
        self.do_module_test(obj, command="delete authserver_ldap 'DELLDAP'", delete=True)

    def test_authserver_update_noop(self):
        """ test not updating a authserver """
        obj = dict(name='DELLDAP', host='ldap.example.com', transport='tcp', scope='one', authcn='CN=Users', timeout=25)
        self.do_module_test(obj, command="delete authserver_ldap 'DELLDAP'", changed=False)

    def test_authserver_update_host(self):
        """ test updating host of a authserver """
        obj = dict(name='DELLDAP', ldap_timeout=5, host='ldap2.blah.com', transport='tcp', scope='one', authcn='CN=Users')
        self.do_module_test(obj, command="update authserver_ldap 'DELLDAP' set ")

    ##############
    # misc
    #
    def test_create_authserver_invalid_timeout(self):
        """ test creation of a new authserver with invalid timeout """
        obj = dict(name='DELLDAP', host='ldap.example.com', transport='tcp', scope='one', authcn='CN=Users', timeout=0)
        self.do_module_test(obj, command="update authserver_ldap 'DELLDAP'", failed=True, msg='timeout 0 must be greater than 1')

    def test_delete_inexistent_authserver(self):
        """ test deletion of an inexistent authserver """
        obj = dict(name='noauthserver')
        self.do_module_test(obj, state='absent', changed=False)
