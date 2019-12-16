# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from copy import copy
import sys
from xml.etree.ElementTree import fromstring, ElementTree
import pytest
from units.modules.utils import set_module_args
from ansible.modules.network.pfsense import pfsense_rule_separator
from .pfsense_module import TestPFSenseModule, load_fixture

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")


def args_from_var(var, state='present', **kwargs):
    """ return arguments for pfsense_rule_separator module from var """
    args = {}
    for field in ['interface', 'floating', 'color', 'after', 'before', 'state', 'name']:
        if field in var:
            args[field] = var[field]

    args['state'] = state
    for key, value in kwargs.items():
        args[key] = value

    return args


class TestPFSenseRuleSeparatorModule(TestPFSenseModule):

    module = pfsense_rule_separator

    def load_fixtures(self, commands=None):
        """ loading data """
        config_file = 'pfsense_rule_separator_config.xml'
        self.parse.return_value = ElementTree(fromstring(load_fixture(config_file)))

    ########################################################
    # Generic set of funcs used for testing separators
    # First we run the module
    # Then, we check return values
    # Finally, we check the xml
    def do_separator_creation_test(self, separator, failed=False, msg='', command=None):
        """ test creation of a new separator """
        set_module_args(args_from_var(separator))
        result = self.execute_module(changed=True, failed=failed, msg=msg)

        if not failed:
            self.assertTrue(self.load_xml_result())
            self.check_rule_separator_elt(separator)
            self.assertEqual(result['commands'], [command])
        else:
            self.assertFalse(self.load_xml_result())

    def do_separator_deletion_test(self, separator, command=None):
        """ test deletion of a separator """
        set_module_args(args_from_var(separator, 'absent'))
        result = self.execute_module(changed=True)
        self.assertTrue(self.load_xml_result())
        self.assertEqual(result['commands'], [command])

        if separator.get('floating'):
            interface = 'floatingrules'
        else:
            interface = self.unalias_interface(separator['interface'])
        separator_elt = self.get_separator_elt(interface, separator['name'], False)
        self.assertIsNone(separator_elt)

    def do_separator_update_noop_test(self, separator):
        """ test not updating a separator """
        set_module_args(args_from_var(separator))
        result = self.execute_module(changed=False)
        self.assertFalse(self.load_xml_result())
        self.assertEqual(result['commands'], [])

    def do_separator_update_test(self, separator, failed=False, msg='', command=None):
        """ test updating a separator """
        self.do_separator_creation_test(separator, failed, msg, command)

    def get_separator_elt(self, interface, sep_name, fail=True):
        """ get separator from XML """
        filter_elt = self.assert_find_xml_elt(self.xml_result, 'filter')
        separator_elt = self.assert_find_xml_elt(filter_elt, 'separator')
        iface_elt = self.assert_find_xml_elt(separator_elt, interface)
        for separator in iface_elt:
            text_elt = separator.find('text')
            if text_elt is not None and text_elt.text == sep_name:
                return separator

        if fail:
            self.fail('Separator ' + sep_name + ' not found on interface ' + interface)
        return None

    def check_rule_separator_elt(self, separator):
        """ check XML separator definition """
        if separator.get('floating'):
            interface = 'floatingrules'
        else:
            interface = self.unalias_interface(separator['interface'])
        separator_elt = self.get_separator_elt(interface, separator['name'])

        self.assert_xml_elt_equal(separator_elt, 'if', interface)

        if 'color' not in separator:
            self.assert_xml_elt_equal(separator_elt, 'color', 'bg-info')
        else:
            self.assert_xml_elt_equal(separator_elt, 'color', 'bg-' + separator['color'])

    def check_separator_idx(self, separator, expected_idx):
        """ test the logical position of separator """
        if separator.get('floating'):
            interface = 'floatingrules'
        else:
            interface = self.unalias_interface(separator['interface'])
        separator_elt = self.get_separator_elt(interface, separator['name'])
        row_elt = self.assert_find_xml_elt(separator_elt, 'row')
        idx = int(row_elt.text.replace('fr', ''))
        if idx != expected_idx:
            self.fail('Idx of separator ' + separator['name'] + ' if wrong: ' + str(idx) + ', expected: ' + str(expected_idx))

    ##############
    # hosts
    #
    def test_separator_create(self):
        """ test creation of a new separator """
        separator = dict(name='voip', interface='lan_100')
        command = "create rule_separator 'voip' on 'lan_100', color='info'"
        self.do_separator_creation_test(separator, command=command)
        self.check_separator_idx(separator, 6)

    def test_separator_create_floating(self):
        """ test creation of a new separator """
        separator = dict(name='voip', floating=True)
        command = "create rule_separator 'voip' on 'floating', color='info'"
        self.do_separator_creation_test(separator, command=command)
        self.check_separator_idx(separator, 0)

    def test_separator_create_top(self):
        """ test creation of a new separator at top """
        separator = dict(name='voip', interface='lan_100', after='top')
        command = "create rule_separator 'voip' on 'lan_100', color='info', after='top'"
        self.do_separator_creation_test(separator, command=command)
        self.check_separator_idx(separator, 0)

    def test_separator_create_bottom(self):
        """ test creation of a new separator at bottom """
        separator = dict(name='voip', interface='lan', before='bottom')
        command = "create rule_separator 'voip' on 'lan', color='info', before='bottom'"
        self.do_separator_creation_test(separator, command=command)
        self.check_separator_idx(separator, 14)

    def test_separator_create_after(self):
        """ test creation of a new separator at bottom """
        separator = dict(name='voip', interface='lan', after='antilock_out_1')
        command = "create rule_separator 'voip' on 'lan', color='info', after='antilock_out_1'"
        self.do_separator_creation_test(separator, command=command)
        self.check_separator_idx(separator, 1)

    def test_separator_create_before(self):
        """ test creation of a new separator at bottom """
        separator = dict(name='voip', interface='lan', before='antilock_out_2')
        command = "create rule_separator 'voip' on 'lan', color='info', before='antilock_out_2'"
        self.do_separator_creation_test(separator, command=command)
        self.check_separator_idx(separator, 1)

    def test_separator_delete(self):
        """ test deletion of a separator """
        separator = dict(name='test_separator', interface='lan')
        command = "delete rule_separator 'test_separator' on 'lan'"
        self.do_separator_deletion_test(separator, command=command)

    def test_separator_delete_inexistent(self):
        """ test deletion of an inexistent separator """
        separator = dict(name='test_separator', interface='wan')
        set_module_args(args_from_var(separator, 'absent'))
        result = self.execute_module(changed=False)
        self.assertFalse(self.load_xml_result())
        self.assertEqual(result['commands'], [])

    def test_separator_update_noop(self):
        """ test changing nothing to a separator """
        separator = dict(name='test_separator', interface='lan', color='info')
        self.do_separator_update_noop_test(separator)

    def test_separator_update_color(self):
        """ test updating color of a separator """
        separator = dict(name='test_separator', interface='lan', color='warning')
        command = "update rule_separator 'test_separator' on 'lan' set color='warning'"
        self.do_separator_update_test(separator, command=command)
        self.check_separator_idx(separator, 1)

    def test_separator_update_position(self):
        """ test updating position of a separator """
        separator = dict(name='test_separator', interface='lan', after='top')
        command = "update rule_separator 'test_separator' on 'lan' set color='info', after='top'"
        self.do_separator_update_test(separator, command=command)
        self.check_separator_idx(separator, 0)
