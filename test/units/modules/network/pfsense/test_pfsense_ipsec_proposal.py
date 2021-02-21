# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from ansible.modules.network.pfsense import pfsense_ipsec_proposal
from ansible.module_utils.network.pfsense.ipsec_proposal import PFSenseIpsecProposalModule
from .pfsense_module import TestPFSenseModule
from parameterized import parameterized


class TestPFSenseIpsecProposalModule(TestPFSenseModule):

    module = pfsense_ipsec_proposal

    def __init__(self, *args, **kwargs):
        super(TestPFSenseIpsecProposalModule, self).__init__(*args, **kwargs)
        self.pfmodule = PFSenseIpsecProposalModule

    def get_config_file(self):
        """ get config file """
        if self.get_version.return_value.startswith("2.4."):
            return '2.4/pfsense_ipsec_proposal_config.xml'

        return 'pfsense_ipsec_proposal_config.xml'

    ##############
    # tests utils
    #
    def get_target_elt(self, proposal, absent=False):
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

            if not self.get_version.return_value.startswith("2.4."):
                elt = item_elt.find('prf-algorithm')
                if elt is None or 'prf' not in proposal and elt.text != 'sha256' and elt.text != proposal['prf']:
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

    def check_target_elt(self, proposal, proposal_elt):
        """ test the xml definition of proposal elt """
        if proposal_elt is None:
            self.fail('Unable to find proposal on ' + proposal['descr'])

    def strip_commands(self, commands):
        """ remove old or new parameters """
        if self.get_version.return_value.startswith("2.4."):
            commands = commands.replace(", prf='sha256'", "")
        return commands

    ##############
    # tests
    #
    @parameterized.expand([["2.4.4"], ["2.5.0"]])
    def test_ipsec_proposal_create(self, pfsense_version):
        """ test creation of a new proposal """
        self.get_version.return_value = pfsense_version
        proposal = dict(descr='test_tunnel', encryption='aes128gcm', key_length=128, hash='sha256', dhgroup=21)
        command = "create ipsec_proposal 'test_tunnel', encryption='aes128gcm', key_length=128, hash='sha256', dhgroup='21', prf='sha256'"
        self.do_module_test(proposal, command=command)

    @parameterized.expand([["2.4.4"], ["2.5.0"]])
    def test_ipsec_proposal_create_nokeylen(self, pfsense_version):
        """ test creation of a new proposal """
        self.get_version.return_value = pfsense_version
        proposal = dict(descr='test_tunnel2', encryption='cast128', hash='sha256', dhgroup=21)
        command = "create ipsec_proposal 'test_tunnel2', encryption='cast128', hash='sha256', dhgroup='21', prf='sha256'"
        self.do_module_test(proposal, command=command)

    @parameterized.expand([["2.4.4"], ["2.5.0"]])
    def test_ipsec_proposal_delete(self, pfsense_version):
        """ test deletion of an ipsec proposal """
        self.get_version.return_value = pfsense_version
        proposal = dict(descr='test_tunnel', encryption='aes128gcm', key_length=128, hash='sha256', dhgroup=14, state='absent')
        command = "delete ipsec_proposal 'test_tunnel', encryption='aes128gcm', key_length=128, hash='sha256', dhgroup='14', prf='sha256'"
        self.do_module_test(proposal, delete=True, command=command)

    @parameterized.expand([["2.4.4"], ["2.5.0"]])
    def test_ipsec_proposal_update_noop(self, pfsense_version):
        """ test not updating a ipsec proposal """
        self.get_version.return_value = pfsense_version
        proposal = dict(descr='test_tunnel', encryption='aes128gcm', key_length=128, hash='sha256', dhgroup=14)
        self.do_module_test(proposal, changed=False)

    def test_ipsec_proposal_wrong_keylen(self):
        """ test using a wrong key_length """
        proposal = dict(descr='test_tunnel', encryption='aes128gcm', key_length=256, hash='sha256', dhgroup=14)
        msg = 'key_length for encryption aes128gcm must be one of: 64, 96, 128.'
        self.do_module_test(proposal, msg=msg, failed=True)

    def test_ipsec_proposal_wrong_tunnel(self):
        """ test using a wrong tunnel """
        proposal = dict(descr='test_tunnel3', encryption='aes128gcm', key_length=128, hash='sha256', dhgroup=14)
        msg = 'No ipsec tunnel named test_tunnel3'
        self.do_module_test(proposal, msg=msg, failed=True)

    def test_ipsec_proposal_wrong_encryption(self):
        """ test using a wrong encryption """
        proposal = dict(descr='test_tunnel2', encryption='aes128gcm', key_length=128, hash='sha256', dhgroup=14)
        msg = 'Encryption Algorithm AES-GCM can only be used with IKEv2'
        self.do_module_test(proposal, msg=msg, failed=True)
