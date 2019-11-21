# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from copy import copy
import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from xml.etree.ElementTree import fromstring, ElementTree

from units.compat.mock import patch
from units.modules.utils import set_module_args
from ansible.modules.network.pfsense import pfsense_vlan

from .pfsense_module import TestPFSenseModule, load_fixture


def args_from_var(var, state='present', **kwargs):
    """ return arguments for pfsense_vlan module from var """
    args = {}

    fields = ['descr', 'vlan_id', 'interface', 'priority']
    for field in fields:
        if field in var:
            args[field] = var[field]

    args['state'] = state
    for key, value in kwargs.items():
        args[key] = value

    return args


class TestPFSenseVlanModule(TestPFSenseModule):

    module = pfsense_vlan

    ##############
    # tests utils
    #
    def load_fixtures(self, commands=None):
        """ loading data """
        config_file = 'pfsense_vlan_config.xml'
        self.parse.return_value = ElementTree(fromstring(load_fixture(config_file)))

    def do_vlan_test(self, vlan, command=None, changed=True, failed=False, msg=None, delete=False):
        """ test deletion of a vlan """
        if delete:
            set_module_args(args_from_var(vlan, 'absent'))
        else:
            set_module_args(args_from_var(vlan))

        result = self.execute_module(changed=changed, failed=failed, msg=msg)

        if failed:
            self.assertFalse(self.load_xml_result())
        elif not changed:
            self.assertFalse(self.load_xml_result())
            self.assertEqual(result['commands'], [])
        elif delete:
            self.get_vlan_elt(vlan, absent=True)
            self.assertEqual(result['commands'], [command])
        else:
            self.check_vlan_elt(vlan)
            self.assertEqual(result['commands'], [command])

    def get_vlan_elt(self, vlan, absent=False):
        """ get the generated vlan xml definition """
        elt_filter = {}
        elt_filter['if'] = self.unalias_interface(vlan['interface'], physical=True)
        elt_filter['tag'] = str(vlan['vlan_id'])

        return self.assert_has_xml_tag('vlans', elt_filter, absent=absent)

    def check_vlan_elt(self, vlan):
        """ test the xml definition of vlan """
        vlan_elt = self.get_vlan_elt(vlan)

        # checking vlanif
        self.assert_xml_elt_equal(vlan_elt, 'vlanif', '{0}.{1}'.format(self.unalias_interface(vlan['interface'], physical=True), vlan['vlan_id']))

        # checking descr
        if 'descr' in vlan:
            self.assert_xml_elt_equal(vlan_elt, 'descr', vlan['descr'])
        else:
            self.assert_xml_elt_is_none_or_empty(vlan_elt, 'descr')

        # checking priority
        if 'priority' in vlan and vlan['priority'] is not None:
            self.assert_xml_elt_equal(vlan_elt, 'pcp', str(vlan['priority']))
        else:
            self.assert_xml_elt_is_none_or_empty(vlan_elt, 'pcp')

    ##############
    # tests
    #
    def test_vlan_create(self):
        """ test creation of a new vlan """
        vlan = dict(vlan_id=100, interface='vmx0')
        command = "create vlan 'vmx0.100', descr='', priority=''"
        self.do_vlan_test(vlan, command=command)

    def test_vlan_create_with_assigned_name(self):
        """ test creation of a new vlan using assigned name """
        vlan = dict(vlan_id=100, interface='vpn')
        command = "create vlan 'vmx2.100', descr='', priority=''"
        self.do_vlan_test(vlan, command=command)

    def test_vlan_create_with_friendly_name(self):
        """ test creation of a new vlan using friendly name """
        vlan = dict(vlan_id=100, interface='opt2')
        command = "create vlan 'vmx3.100', descr='', priority=''"
        self.do_vlan_test(vlan, command=command)

    def test_vlan_create_with_wrong_inteface(self):
        """ test creation of a new vlan using wrong interface """
        vlan = dict(vlan_id=100, interface='opt3')
        msg = "Vlans can't be set on interface opt3"
        self.do_vlan_test(vlan, failed=True, msg=msg)

    def test_vlan_create_with_wrong_vlan(self):
        """ test creation of a new vlan using wrong vlan_id """
        vlan = dict(vlan_id=0, interface='opt2')
        msg = "vlan_id must be between 1 and 4094 on interface opt2"
        self.do_vlan_test(vlan, failed=True, msg=msg)

    def test_vlan_create_with_wrong_prioriy(self):
        """ test creation of a new vlan using wrong priority """
        vlan = dict(vlan_id=100, interface='opt2', priority=8)
        msg = "priority must be between 0 and 7 on interface opt2"
        self.do_vlan_test(vlan, failed=True, msg=msg)

    def test_vlan_create_with_priority(self):
        """ test creation of a new vlan """
        vlan = dict(vlan_id=100, interface='vmx0', descr='voice')
        command = "create vlan 'vmx0.100', descr='voice', priority=''"
        self.do_vlan_test(vlan, command=command)

    def test_vlan_create_with_descr(self):
        """ test creation of a new vlan """
        vlan = dict(vlan_id=100, interface='vmx0', priority=5)
        command = "create vlan 'vmx0.100', descr='', priority='5'"
        self.do_vlan_test(vlan, command=command)

    def test_vlan_delete(self):
        """ test deletion of a vlan """
        vlan = dict(vlan_id=100, interface='vmx1')
        command = "delete vlan 'vmx1.100'"
        self.do_vlan_test(vlan, delete=True, command=command)

    def test_vlan_delete_used(self):
        """ test deletion of a still used vlan """
        vlan = dict(vlan_id=1100, interface='vmx1')
        self.do_vlan_test(vlan, delete=True, failed=True, msg='vlan 1100 on vmx1 cannot be deleted because it is still being used as an interface')

    def test_vlan_delete_unexistent(self):
        """ test deletion of a vlan """
        vlan = dict(vlan_id=1200, interface='vmx1')
        self.do_vlan_test(vlan, delete=True, changed=False)

    def test_vlan_update_noop(self):
        """ test not updating a vlan """
        vlan = dict(vlan_id=1100, interface='vmx1')
        self.do_vlan_test(vlan, changed=False)

    def test_vlan_update_priority(self):
        """ test updating priority """
        vlan = dict(vlan_id=1100, interface='vmx1', priority=1)
        command = "update vlan 'vmx1.1100' set priority='1'"
        self.do_vlan_test(vlan, changed=True, command=command)

    def test_vlan_update_descr(self):
        """ test updating descr """
        vlan = dict(vlan_id=1100, interface='vmx1', descr='test')
        command = "update vlan 'vmx1.1100' set descr='test'"
        self.do_vlan_test(vlan, changed=True, command=command)
