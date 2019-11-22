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
from ansible_collections.opoplawski.pfsense.plugins.network.pfsense import pfsense_ipsec

from .pfsense_module import TestPFSenseModule, load_fixture


def args_from_var(var, state='present', **kwargs):
    """ return arguments for pfsense_ipsec module from var """
    args = {}

    fields = ['descr', 'interface', 'iketype', 'protocol', 'remote_gateway', 'disabled', 'authentication_method', 'mode']
    fields.extend(['myid_type', 'myid_data', 'peerid_type', 'peerid_data', 'certificate', 'certificate_authority', 'preshared_key'])
    fields.extend(['lifetime', 'disable_rekey', 'margintime', 'responderonly', 'nat_traversal', 'enable_dpd', 'dpd_delay', 'dpd_maxfail', 'apply'])
    fields.extend(['disable_reauth', 'mobike', 'splitconn'])
    for field in fields:
        if field in var:
            args[field] = var[field]

    args['state'] = state
    for key, value in kwargs.items():
        args[key] = value

    return args


class TestPFSenseIpsecModule(TestPFSenseModule):

    module = pfsense_ipsec

    ##############
    # tests utils
    #
    def load_fixtures(self, commands=None):
        """ loading data """
        config_file = 'pfsense_ipsec_config.xml'
        self.parse.return_value = ElementTree(fromstring(load_fixture(config_file)))

    def do_ipsec_test(self, ipsec, command=None, changed=True, failed=False, msg=None, delete=False):
        """ test deletion of an ipsec tunnel """
        if delete:
            set_module_args(args_from_var(ipsec, 'absent'))
        else:
            set_module_args(args_from_var(ipsec))

        result = self.execute_module(changed=changed, failed=failed, msg=msg)

        if not isinstance(command, list):
            command = [command]

        if failed:
            self.assertFalse(self.load_xml_result())
        elif not changed:
            self.assertFalse(self.load_xml_result())
            self.assertEqual(result['commands'], [])
        elif delete:
            self.get_ipsec_elt(ipsec, absent=True)
            self.assertEqual(result['commands'], command)
        else:
            self.check_ipsec_elt(ipsec)
            self.assertEqual(result['commands'], command)

    def get_ipsec_elt(self, ipsec, absent=False):
        """ get the generated ipsec xml definition """
        elt_filter = {}
        elt_filter['descr'] = ipsec['descr']

        return self.assert_has_xml_tag('ipsec', elt_filter, absent=absent)

    @staticmethod
    def caref(descr):
        """ return refid for ca """
        if descr == 'test ca':
            return '5db509cfed87d'
        if descr == 'test ca copy':
            return '5db509cfed87e'
        return ''

    @staticmethod
    def certref(descr):
        """ return refid for cert """
        if descr == 'webConfigurator default (5c00e5f9029df)':
            return '5c00e5f9029df'
        if descr == 'webConfigurator default copy':
            return '5c00e5f9029de'
        return ''

    def check_ipsec_elt(self, ipsec):
        """ test the xml definition of ipsec elt """
        ipsec_elt = self.get_ipsec_elt(ipsec)

        # bools
        if ipsec.get('disabled'):
            self.assert_xml_elt_is_none_or_empty(ipsec_elt, 'disabled')
        else:
            self.assert_not_find_xml_elt(ipsec_elt, 'disabled')

        if ipsec.get('disable_rekey'):
            self.assert_xml_elt_is_none_or_empty(ipsec_elt, 'disable_rekey')
            self.assert_not_find_xml_elt(ipsec_elt, 'margintime')
        else:
            self.assert_not_find_xml_elt(ipsec_elt, 'disable_rekey')
            if ipsec.get('margintime'):
                self.assert_xml_elt_equal(ipsec_elt, 'margintime', ipsec['margintime'])
            else:
                self.assert_xml_elt_is_none_or_empty(ipsec_elt, 'margintime')

        if ipsec.get('responderonly'):
            self.assert_xml_elt_is_none_or_empty(ipsec_elt, 'responderonly')
        else:
            self.assert_not_find_xml_elt(ipsec_elt, 'responderonly')

        if ipsec.get('disable_reauth'):
            self.assert_xml_elt_is_none_or_empty(ipsec_elt, 'reauth_enable')
        else:
            self.assert_not_find_xml_elt(ipsec_elt, 'reauth_enable')

        if ipsec.get('splitconn'):
            self.assert_xml_elt_is_none_or_empty(ipsec_elt, 'splitconn')
        else:
            self.assert_not_find_xml_elt(ipsec_elt, 'splitconn')

        if ipsec.get('enable_dpd') is None or ipsec.get('enable_dpd'):
            if ipsec.get('dpd_delay') is not None:
                self.assert_xml_elt_equal(ipsec_elt, 'dpd_delay', ipsec['dpd_delay'])
            else:
                self.assert_xml_elt_equal(ipsec_elt, 'dpd_delay', '10')

            if ipsec.get('dpd_maxfail') is not None:
                self.assert_xml_elt_equal(ipsec_elt, 'dpd_maxfail', ipsec['dpd_maxfail'])
            else:
                self.assert_xml_elt_equal(ipsec_elt, 'dpd_maxfail', '5')
        else:
            self.assert_not_find_xml_elt(ipsec_elt, 'dpd_delay')
            self.assert_not_find_xml_elt(ipsec_elt, 'dpd_maxfail')

        if ipsec.get('mobike'):
            self.assert_xml_elt_equal(ipsec_elt, 'mobike', ipsec['mobike'])

        # iketype & mode
        self.assert_xml_elt_equal(ipsec_elt, 'iketype', ipsec['iketype'])
        if ipsec.get('mode') is not None:
            self.assert_xml_elt_equal(ipsec_elt, 'mode', ipsec['mode'])

        if ipsec.get('nat_traversal') is not None:
            self.assert_xml_elt_equal(ipsec_elt, 'nat_traversal', ipsec['nat_traversal'])
        else:
            self.assert_xml_elt_equal(ipsec_elt, 'nat_traversal', 'on')

        # auth
        self.assert_xml_elt_equal(ipsec_elt, 'authentication_method', ipsec['authentication_method'])
        if ipsec['authentication_method'] == 'rsasig':
            self.assert_xml_elt_equal(ipsec_elt, 'certref', self.certref(ipsec['certificate']))
            self.assert_xml_elt_equal(ipsec_elt, 'caref', self.caref(ipsec['certificate_authority']))
            self.assert_xml_elt_is_none_or_empty(ipsec_elt, 'pre-shared-key')
        else:
            self.assert_xml_elt_is_none_or_empty(ipsec_elt, 'certref')
            self.assert_xml_elt_is_none_or_empty(ipsec_elt, 'caref')
            self.assert_xml_elt_equal(ipsec_elt, 'pre-shared-key', ipsec['preshared_key'])

        # ids
        if ipsec.get('myid_type') is not None:
            self.assert_xml_elt_equal(ipsec_elt, 'myid_type', ipsec['myid_type'])
        else:
            self.assert_xml_elt_equal(ipsec_elt, 'myid_type', 'myaddress')
        if ipsec.get('myid_data') is not None:
            self.assert_xml_elt_equal(ipsec_elt, 'myid_data', ipsec['myid_data'])

        if ipsec.get('peerid_type') is not None:
            self.assert_xml_elt_equal(ipsec_elt, 'peerid_type', ipsec['peerid_type'])
        else:
            self.assert_xml_elt_equal(ipsec_elt, 'peerid_type', 'peeraddress')
        if ipsec.get('peerid_data') is not None:
            self.assert_xml_elt_equal(ipsec_elt, 'peerid_data', ipsec['peerid_data'])

        # misc
        self.assert_xml_elt_equal(ipsec_elt, 'interface', self.unalias_interface(ipsec['interface']))

        if ipsec.get('protocol') is not None:
            self.assert_xml_elt_equal(ipsec_elt, 'protocol', ipsec['protocol'])
        else:
            self.assert_xml_elt_equal(ipsec_elt, 'protocol', 'inet')
        self.assert_xml_elt_equal(ipsec_elt, 'remote-gateway', ipsec['remote_gateway'])

        if ipsec.get('lifetime') is not None:
            self.assert_xml_elt_equal(ipsec_elt, 'lifetime', ipsec['lifetime'])
        else:
            self.assert_xml_elt_equal(ipsec_elt, 'lifetime', '28800')

    ##############
    # tests
    #
    def test_ipsec_create_ikev2(self):
        """ test creation of a new ipsec tunnel """
        ipsec = dict(
            descr='new_tunnel', interface='lan_100', remote_gateway='1.2.3.4', iketype='ikev2',
            authentication_method='pre_shared_key', preshared_key='1234')
        command = (
            "create ipsec 'new_tunnel', iketype='ikev2', protocol='inet', interface='lan_100', remote_gateway='1.2.3.4', "
            "authentication_method='pre_shared_key', preshared_key='1234', myid_type='myaddress', peerid_type='peeraddress', lifetime='28800', "
            "disable_rekey=False, margintime='', mobike='off', responderonly=False, nat_traversal='on', enable_dpd=True, dpd_delay='10', dpd_maxfail='5'")
        self.do_ipsec_test(ipsec, command=command)

    def test_ipsec_create_ikev1(self):
        """ test creation of a new ipsec tunnel """
        ipsec = dict(
            descr='new_tunnel', interface='lan_100', remote_gateway='1.2.3.4', iketype='ikev1',
            authentication_method='pre_shared_key', preshared_key='1234', mode='main')
        command = (
            "create ipsec 'new_tunnel', iketype='ikev1', mode='main', protocol='inet', interface='lan_100', remote_gateway='1.2.3.4', "
            "authentication_method='pre_shared_key', preshared_key='1234', myid_type='myaddress', peerid_type='peeraddress', lifetime='28800', "
            "disable_rekey=False, margintime='', responderonly=False, nat_traversal='on', enable_dpd=True, dpd_delay='10', dpd_maxfail='5'")
        self.do_ipsec_test(ipsec, command=command)

    def test_ipsec_create_auto(self):
        """ test creation of a new ipsec tunnel """
        ipsec = dict(
            descr='new_tunnel', interface='lan_100', remote_gateway='1.2.3.4', iketype='auto',
            authentication_method='pre_shared_key', preshared_key='1234', mode='main')
        command = (
            "create ipsec 'new_tunnel', iketype='auto', mode='main', protocol='inet', interface='lan_100', remote_gateway='1.2.3.4', "
            "authentication_method='pre_shared_key', preshared_key='1234', myid_type='myaddress', peerid_type='peeraddress', lifetime='28800', "
            "disable_rekey=False, margintime='', responderonly=False, nat_traversal='on', enable_dpd=True, dpd_delay='10', dpd_maxfail='5'")
        self.do_ipsec_test(ipsec, command=command)

    def test_ipsec_create_auto_rsasig(self):
        """ test creation of a new ipsec tunnel with certificate """
        ipsec = dict(
            descr='new_tunnel', interface='lan_100', remote_gateway='1.2.3.4', iketype='ikev2',
            authentication_method='rsasig', certificate='webConfigurator default (5c00e5f9029df)', certificate_authority='test ca')
        command = (
            "create ipsec 'new_tunnel', iketype='ikev2', protocol='inet', interface='lan_100', remote_gateway='1.2.3.4', "
            "authentication_method='rsasig', certificate='webConfigurator default (5c00e5f9029df)', certificate_authority='test ca', "
            "myid_type='myaddress', peerid_type='peeraddress', lifetime='28800', disable_rekey=False, margintime='', mobike='off', responderonly=False, "
            "nat_traversal='on', enable_dpd=True, dpd_delay='10', dpd_maxfail='5'")
        self.do_ipsec_test(ipsec, command=command)

    def test_ipsec_delete(self):
        """ test deletion of an ipsec """
        ipsec = dict(descr='test_tunnel', state='absent')
        command = "delete ipsec 'test_tunnel'"
        self.do_ipsec_test(ipsec, delete=True, command=command)

    def test_ipsec_update_noop(self):
        """ test not updating a ipsec """
        ipsec = dict(
            descr='test_tunnel', interface='lan_100', remote_gateway='1.2.4.8', iketype='ikev2',
            authentication_method='pre_shared_key', preshared_key='1234')
        self.do_ipsec_test(ipsec, changed=False)

    def test_ipsec_update_ike(self):
        """ test updating ike """
        ipsec = dict(
            descr='test_tunnel', interface='lan_100', remote_gateway='1.2.4.8', iketype='ikev1',
            authentication_method='pre_shared_key', preshared_key='1234', mode='main')
        command = "update ipsec 'test_tunnel' set iketype='ikev1', mode='main'"
        self.do_ipsec_test(ipsec, command=command)

    def test_ipsec_update_gw(self):
        """ test updating gw """
        ipsec = dict(
            descr='test_tunnel', interface='lan_100', remote_gateway='1.2.3.5', iketype='ikev2',
            authentication_method='pre_shared_key', preshared_key='1234')
        command = "update ipsec 'test_tunnel' set remote_gateway='1.2.3.5'"
        self.do_ipsec_test(ipsec, command=command)

    def test_ipsec_update_auth(self):
        """ test updating auth """
        ipsec = dict(
            descr='test_tunnel', interface='lan_100', remote_gateway='1.2.4.8', iketype='ikev2',
            authentication_method='rsasig', certificate='webConfigurator default (5c00e5f9029df)', certificate_authority='test ca')
        command = (
            "update ipsec 'test_tunnel' set authentication_method='rsasig', "
            "certificate='webConfigurator default (5c00e5f9029df)', certificate_authority='test ca'")
        self.do_ipsec_test(ipsec, command=command)

    def test_ipsec_update_cert(self):
        """ test updating certificates """
        ipsec = dict(
            descr='test_tunnel2', interface='lan_100', remote_gateway='1.2.3.6', iketype='ikev2',
            authentication_method='rsasig', certificate='webConfigurator default copy', certificate_authority='test ca copy')
        command = "update ipsec 'test_tunnel2' set certificate='webConfigurator default copy', certificate_authority='test ca copy'"
        self.do_ipsec_test(ipsec, command=command)

    def test_ipsec_duplicate_gw(self):
        """ test using a duplicate gw """
        ipsec = dict(
            descr='new_tunnel', interface='lan_100', remote_gateway='1.2.4.8', iketype='ikev1',
            authentication_method='pre_shared_key', preshared_key='1234', mode='main')
        msg = 'The remote gateway "1.2.4.8" is already used by phase1 "test_tunnel".'
        self.do_ipsec_test(ipsec, msg=msg, failed=True)
