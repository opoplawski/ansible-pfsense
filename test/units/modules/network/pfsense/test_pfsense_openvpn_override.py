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
from ansible.modules.network.pfsense import pfsense_openvpn_override
from .pfsense_module import TestPFSenseModule, load_fixture


class TestPFSenseOpenVPNOverrideModule(TestPFSenseModule):

    module = pfsense_openvpn_override

    def __init__(self, *args, **kwargs):
        super(TestPFSenseOpenVPNOverrideModule, self).__init__(*args, **kwargs)
        self.config_file = 'pfsense_openvpn_config.xml'
        self.pfmodule = pfsense_openvpn_override.PFSenseOpenVPNOverrideModule

    @staticmethod
    def runTest():
        """ dummy function needed to instantiate this test module from another in python 2.7 """
        pass

    def get_target_elt(self, obj, absent=False):
        """ return target elt from XML """
        root_elt = self.xml_result.getroot().find('openvpn')
        result = root_elt.findall("openvpn-csc[common_name='{0}']".format(obj['name']))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.fail('Found multiple OpenVPN overrides for name {0}.'.format(obj['name']))
        else:
            return None

    def check_target_elt(self, params, target_elt):
        """ check XML definition of target elt """

        self.check_param_equal(params, target_elt, 'name', xml_field='common_name')
        self.check_param_bool(params, target_elt, 'disable')
        self.check_param_bool(params, target_elt, 'block', default=False, value_true='yes')
        self.check_param_equal(params, target_elt, 'tunnel_network')
        self.check_param_equal(params, target_elt, 'tunnel_networkv6')
        self.check_param_equal(params, target_elt, 'local_network')
        self.check_param_equal(params, target_elt, 'local_networkv6')
        self.check_param_equal(params, target_elt, 'remote_network')
        self.check_param_equal(params, target_elt, 'remote_networkv6')
        self.check_param_bool(params, target_elt, 'gwredir', default=False, value_true='yes')
        self.check_param_bool(params, target_elt, 'push_reset', default=False, value_true='yes')

    ##############
    # tests
    #
    def test_openvpn_override_create(self):
        """ test creation of a new OpenVPN override """
        obj = dict(name='vpnuser1', block=True)
        self.do_module_test(obj, command="create openvpn_override 'vpnuser1', common_name='vpnuser1'")

    def test_openvpn_override_delete(self):
        """ test deletion of a OpenVPN override """
        obj = dict(name='delvpnuser')
        self.do_module_test(obj, command="delete openvpn_override 'delvpnuser'", delete=True)

    def test_openvpn_override_update_noop(self):
        """ test not updating a OpenVPN override """
        obj = dict(name='delvpnuser', gwredir=True, server_list=1, custom_options='ifconfig-push 10.8.0.1 255.255.255.0')
        self.do_module_test(obj, changed=False)

    def test_openvpn_override_update_network(self):
        """ test updating network of a OpenVPN override """
        obj = dict(name='delvpnuser', gwredir=True, server_list=1, custom_options='ifconfig-push 10.8.0.1 255.255.255.0', tunnel_network='10.10.10.0/24')
        self.do_module_test(obj, command="update openvpn_override 'delvpnuser' set ")

    ##############
    # misc
    #
    def test_create_openvpn_override_invalid_network(self):
        """ test creation of a new OpenVPN override with invalid network """
        obj = dict(name='delvpnuser', remote_network='30.4.3.3/24')
        self.do_module_test(obj, failed=True, msg='A valid IPv4 network must be specified for remote_network.')

    def test_delete_nonexistent_openvpn_override(self):
        """ test deletion of an nonexistent OpenVPN override """
        obj = dict(name='novpnuser')
        self.do_module_test(obj, commmand=None, state='absent', changed=False)
