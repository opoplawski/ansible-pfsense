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
from ansible.modules.network.pfsense import pfsense_haproxy_backend

from .pfsense_module import TestPFSenseModule, load_fixture


def args_from_var(var, state='present', **kwargs):
    """ return arguments for pfsense_haproxy_backend module from var """
    args = {}

    fields = ['balance', 'balance_urilen', 'balance_uridepth', 'balance_uriwhole', 'connection_timeout', 'server_timeout']
    fields += ['check_type', 'check_frequency', 'retries', 'log_checks', 'httpcheck_method', 'monitor_uri']
    fields += ['monitor_httpversion', 'monitor_username', 'monitor_domain', 'name']
    for field in fields:
        if field in var:
            args[field] = var[field]

    args['state'] = state
    for key, value in kwargs.items():
        args[key] = value

    return args


class TestPFSenseHaproxyBackendModule(TestPFSenseModule):

    module = pfsense_haproxy_backend

    ##############
    # tests utils
    #
    def load_fixtures(self, commands=None):
        """ loading data """
        config_file = 'pfsense_haproxy_backend_config.xml'
        self.parse.return_value = ElementTree(fromstring(load_fixture(config_file)))

    def do_haproxy_backend_test(self, backend, command=None, changed=True, failed=False, msg=None, delete=False, backend_id=100):
        """ test deletion of a backend """
        if delete:
            set_module_args(args_from_var(backend, 'absent'))
        else:
            set_module_args(args_from_var(backend))

        result = self.execute_module(changed=changed, failed=failed, msg=msg)

        if failed:
            self.assertFalse(self.load_xml_result())
        elif not changed:
            self.assertFalse(self.load_xml_result())
            self.assertEqual(result['commands'], [])
        elif delete:
            self.assertTrue(self.load_xml_result())
            self.get_haproxy_backend_elt(backend, absent=True)
            self.assertEqual(result['commands'], [command])
        else:
            self.assertTrue(self.load_xml_result())
            self.check_haproxy_backend_elt(backend, backend_id)
            self.assertEqual(result['commands'], [command])

    def get_haproxy_backend_elt(self, backend, absent=False):
        """ get the generated backend xml definition """
        pkgs_elt = self.assert_find_xml_elt(self.xml_result, 'installedpackages')
        hap_elt = self.assert_find_xml_elt(pkgs_elt, 'haproxy')
        backends_elt = self.assert_find_xml_elt(hap_elt, 'ha_pools')

        for item in backends_elt:
            name_elt = item.find('name')
            if name_elt is not None and name_elt.text == backend['name']:
                return item

        if not absent:
            self.fail('haproxy_backend ' + backend['name'] + ' not found.')
        return None

    def check_haproxy_backend_elt(self, backend, backend_id):
        """ test the xml definition of backend """
        def _check_elt(name, fname=None, default=None):
            if fname is None:
                fname = name

            if name in backend and backend[name] is not None:
                self.assert_xml_elt_equal(backend_elt, fname, str(backend[name]))
            elif default is not None:
                self.assert_xml_elt_equal(backend_elt, fname, default)
            else:
                self.assert_xml_elt_is_none_or_empty(backend_elt, fname)

        def _check_bool_elt(name, fname=None):
            if fname is None:
                fname = name

            if backend.get(name):
                self.assert_xml_elt_equal(backend_elt, fname, 'yes')
            else:
                self.assert_xml_elt_is_none_or_empty(backend_elt, fname)

        backend_elt = self.get_haproxy_backend_elt(backend)
        self.assert_xml_elt_equal(backend_elt, 'id', str(backend_id))

        # checking balance
        if 'balance' in backend and backend['balance'] != 'none':
            self.assert_xml_elt_equal(backend_elt, 'balance', backend['balance'])
        else:
            self.assert_xml_elt_is_none_or_empty(backend_elt, 'balance')

        # check everything else
        _check_elt('balance_urilen')
        _check_elt('balance_uridepth')
        _check_bool_elt('balance_uriwhole')
        _check_elt('connection_timeout')
        _check_elt('server_timeout')
        _check_elt('check_type', default='none')
        _check_elt('check_frequency', 'checkinter')
        _check_elt('retries')
        _check_bool_elt('log_checks', 'log-health-checks')
        _check_elt('httpcheck_method')
        _check_elt('monitor_uri')
        _check_elt('monitor_httpversion')
        _check_elt('monitor_username')
        _check_elt('monitor_domain')

    ##############
    # tests
    #
    def test_haproxy_backend_create(self):
        """ test creation of a new backend """
        backend = dict(name='exchange')
        command = "create haproxy_backend 'exchange', balance='none', check_type='none'"
        self.do_haproxy_backend_test(backend, command=command, backend_id=102)

    def test_haproxy_backend_create2(self):
        """ test creation of a new backend with some parameters"""
        backend = dict(name='exchange', balance='roundrobin', check_type='HTTP')
        command = "create haproxy_backend 'exchange', balance='roundrobin', check_type='HTTP'"
        self.do_haproxy_backend_test(backend, command=command, backend_id=102)

    def test_haproxy_backend_create_invalid_name(self):
        """ test creation of a new backend """
        backend = dict(name='exchange test')
        msg = "The field 'name' contains invalid characters."
        self.do_haproxy_backend_test(backend, msg=msg, failed=True)

    def test_haproxy_backend_delete(self):
        """ test deletion of a backend """
        backend = dict(name='test-backend')
        command = "delete haproxy_backend 'test-backend'"
        self.do_haproxy_backend_test(backend, delete=True, command=command)

    def test_haproxy_backend_update_noop(self):
        """ test not updating a backend """
        backend = dict(
            name='test-backend', balance='uri', balance_uriwhole=True, log_checks=True, check_type='SSL', check_frequency=123456, httpcheck_method='OPTIONS'
        )
        self.do_haproxy_backend_test(backend, changed=False)

    def test_haproxy_backend_update_bools(self):
        """ test updating bools """
        backend = dict(name='test-backend', balance='uri', check_type='SSL', check_frequency=123456, httpcheck_method='OPTIONS')
        command = "update haproxy_backend 'test-backend' set balance_uriwhole=False, log_checks=False"
        self.do_haproxy_backend_test(backend, changed=True, command=command)
