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
from ansible.modules.network.pfsense import pfsense_ipsec_proposal

from .pfsense_module import TestPFSenseModule, load_fixture


def args_from_var(var, state='present', **kwargs):
    """ return arguments for pfsense_ipsec_proposal module from var """
    args = {}

    fields = ['descr', 'apply', 'encryption', 'key_length', 'hash', 'dhgroup']
    for field in fields:
        if field in var:
            args[field] = var[field]

    args['state'] = state
    for key, value in kwargs.items():
        args[key] = value

    return args


class TestPFSenseIpsecProposalModule(TestPFSenseModule):

    module = pfsense_ipsec_proposal

    ##############
    # tests utils
    #
    def load_fixtures(self, commands=None):
        """ loading data """
        config_file = 'pfsense_ipsec_proposal_config.xml'
        self.parse.return_value = ElementTree(fromstring(load_fixture(config_file)))

    def do_ipsec_proposal_test(self, proposal, command=None, changed=True, failed=False, msg=None, delete=False):
        """ test deletion of an ipsec proposal """
        if delete:
            set_module_args(args_from_var(proposal, 'absent'))
        else:
            set_module_args(args_from_var(proposal))

        result = self.execute_module(changed=changed, failed=failed, msg=msg)

        if not isinstance(command, list):
            command = [command]

        if failed:
            self.assertFalse(self.load_xml_result())
        elif not changed:
            self.assertFalse(self.load_xml_result())
            self.assertEqual(result['commands'], [])
        elif delete:
            proposal_elt = self.get_proposal_elt(proposal)
            if proposal_elt is not None:
                self.fail('Proposal found')
            self.assertEqual(result['commands'], command)
        else:
            self.check_proposal_elt(proposal)
            self.assertEqual(result['commands'], command)

    def get_proposal_elt(self, proposal):
        """ get the generated proposal xml definition """
        elt_filter = {}
        elt_filter['descr'] = proposal['descr']

        ipsec_elt = self.assert_has_xml_tag('ipsec', elt_filter)
        if ipsec_elt is None:
            return None

        encryption_elt = ipsec_elt.find('encryption')
        if encryption_elt is None:
            return None

        for item_elt in encryption_elt:
            elt = item_elt.find('dhgroup')
            if elt is None or elt.text != str(proposal['dhgroup']):
                continue

            elt = item_elt.find('hash-algorithm')
            if elt is None or elt.text != proposal['hash']:
                continue

            encalg_elt = item_elt.find('encryption-algorithm')
            if encalg_elt is None:
                continue

            elt = encalg_elt.find('name')
            if elt is None or elt.text != proposal['encryption']:
                continue

            elt = encalg_elt.find('keylen')
            if (elt is None or elt.text == '') and proposal.get('key_length') is None:
                return item_elt
            if elt is not None and elt.text == str(proposal.get('key_length')):
                return item_elt
        return None

    def check_proposal_elt(self, proposal):
        """ test the xml definition of proposal elt """
        proposal_elt = self.get_proposal_elt(proposal)

        if proposal_elt is None:
            self.fail('Unable to find proposal on ' + proposal['descr'])

    ##############
    # tests
    #
    def test_ipsec_proposal_create(self):
        """ test creation of a new proposal """
        proposal = dict(descr='test_tunnel', encryption='aes128gcm', key_length=128, hash='sha256', dhgroup=21)
        command = "create ipsec_proposal 'test_tunnel', encryption='aes128gcm', key_length=128, hash='sha256', dhgroup='21'"
        self.do_ipsec_proposal_test(proposal, command=command)

    def test_ipsec_proposal_create_nokeylen(self):
        """ test creation of a new proposal """
        proposal = dict(descr='test_tunnel2', encryption='cast128', hash='sha256', dhgroup=21)
        command = "create ipsec_proposal 'test_tunnel2', encryption='cast128', hash='sha256', dhgroup='21'"
        self.do_ipsec_proposal_test(proposal, command=command)

    def test_ipsec_proposal_delete(self):
        """ test deletion of an ipsec proposal """
        proposal = dict(descr='test_tunnel', encryption='aes128gcm', key_length=128, hash='sha256', dhgroup=14, state='absent')
        command = "delete ipsec_proposal 'test_tunnel', encryption='aes128gcm', key_length=128, hash='sha256', dhgroup='14'"
        self.do_ipsec_proposal_test(proposal, delete=True, command=command)

    def test_ipsec_proposal_update_noop(self):
        """ test not updating a ipsec proposal """
        proposal = dict(descr='test_tunnel', encryption='aes128gcm', key_length=128, hash='sha256', dhgroup=14)
        self.do_ipsec_proposal_test(proposal, changed=False)

    def test_ipsec_proposal_wrong_keylen(self):
        """ test using a wrong key_length """
        proposal = dict(descr='test_tunnel', encryption='aes128gcm', key_length=256, hash='sha256', dhgroup=14)
        msg = 'key_length for encryption aes128gcm must be one of: 64, 96, 128.'
        self.do_ipsec_proposal_test(proposal, msg=msg, failed=True)

    def test_ipsec_proposal_wrong_tunnel(self):
        """ test using a wrong tunnel """
        proposal = dict(descr='test_tunnel3', encryption='aes128gcm', key_length=128, hash='sha256', dhgroup=14)
        msg = 'No ipsec tunnel named test_tunnel3'
        self.do_ipsec_proposal_test(proposal, msg=msg, failed=True)

    def test_ipsec_proposal_wrong_encryption(self):
        """ test using a wrong encryption """
        proposal = dict(descr='test_tunnel2', encryption='aes128gcm', key_length=128, hash='sha256', dhgroup=14)
        msg = 'Encryption Algorithm AES-GCM can only be used with IKEv2'
        self.do_ipsec_proposal_test(proposal, msg=msg, failed=True)
