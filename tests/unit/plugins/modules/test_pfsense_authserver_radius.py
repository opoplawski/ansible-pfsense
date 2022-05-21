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
from ansible.modules.network.pfsense import pfsense_authserver_radius
from .pfsense_module import TestPFSenseModule, load_fixture


class TestPFSenseAuthserverRADIUSModule(TestPFSenseModule):

    module = pfsense_authserver_radius

    def __init__(self, *args, **kwargs):
        super(TestPFSenseAuthserverRADIUSModule, self).__init__(*args, **kwargs)
        self.config_file = 'pfsense_authserver_config.xml'
        self.pfmodule = pfsense_authserver_radius.PFSenseAuthserverRADIUSModule

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
        self.assert_xml_elt_equal(target_elt, 'type', 'radius')
        self.check_param_equal(params, target_elt, 'host')
        self.check_param_equal(params, target_elt, 'auth_port', xml_field='radius_auth_port', default=1812)
        self.check_param_equal(params, target_elt, 'acct_port', xml_field='radius_acct_port', default=1813)
        self.check_param_equal(params, target_elt, 'protocol', xml_field='radius_protocol', default='MSCHAPv2')
        self.check_param_equal(params, target_elt, 'secret', xml_field='radius_secret')
        self.check_param_equal(params, target_elt, 'timeout', xml_field='radius_timeout', default=5)
        self.check_param_equal(params, target_elt, 'nasip_attribute', xml_field='radius_nasip_attribute', default='lan')

    ##############
    # tests
    #
    def test_authserver_create(self):
        """ test creation of a new authserver """
        obj = dict(name='authserver1', host='radius.example.com', secret='password1')
        self.do_module_test(obj, command="create authserver_radius 'authserver1'")

    def test_authserver_delete(self):
        """ test deletion of a authserver """
        obj = dict(name='DELRADIUS')
        self.do_module_test(obj, command="delete authserver_radius 'DELRADIUS'", delete=True)

    def test_authserver_update_noop(self):
        """ test not updating a authserver """
        obj = dict(name='DELRADIUS', host='radius.example.com', secret='password1', auth_port=1812)
        self.do_module_test(obj, changed=False)

    def test_authserver_update_host(self):
        """ test updating host of a authserver """
        obj = dict(name='DELRADIUS', radius_timeout=25, host='radius2.blah.com', secret='password2')
        self.do_module_test(obj, command="update authserver_radius 'DELRADIUS' set ")

    ##############
    # misc
    #
    def test_create_authserver_invalid_timeout(self):
        """ test creation of a new authserver with invalid timeout """
        obj = dict(name='DELRADIUS', host='radius.example.com', secret='password1', timeout=0)
        self.do_module_test(obj, command="update authserver_radius 'DELRADIUS'", failed=True, msg='timeout 0 must be greater than 1')

    def test_delete_inexistent_authserver(self):
        """ test deletion of an inexistent authserver """
        obj = dict(name='noauthserver')
        self.do_module_test(obj, state='absent', changed=False)
