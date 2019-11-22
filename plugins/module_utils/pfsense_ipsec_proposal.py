# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
from ansible_collections.opoplawski.pfsense.plugins.module_utils.pfsense import PFSenseModule, PFSenseModuleBase


IPSEC_PROPOSAL_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),
    descr=dict(required=False, type='str'),
    encryption=dict(required=True, choices=['aes', 'aes128gcm', 'aes192gcm', 'aes256gcm', 'blowfish', '3des', 'cast128'], type='str'),
    key_length=dict(required=False, choices=[64, 96, 128, 192, 256], type='int'),
    hash=dict(required=True, choices=['md5', 'sha1', 'sha256', 'sha384', 'sha512', 'aesxcbc'], type='str'),
    dhgroup=dict(required=True, choices=[1, 2, 5, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 28, 29, 30], type='int'),
    apply=dict(default=True, type='bool'),
)

IPSEC_PROPOSAL_REQUIRED_IF = [
    ["encryption", "aes", ["key_length"]],
    ["encryption", "aes128-gcm", ["key_length"]],
    ["encryption", "aes192-gcm", ["key_length"]],
    ["encryption", "aes256-gcm", ["key_length"]],
    ["encryption", "blowfish", ["key_length"]],
]


class PFSenseIpsecProposalModule(PFSenseModuleBase):
    """ module managing pfsense ipsec phase 1 proposals """

    def __init__(self, module, pfsense=None):
        if pfsense is None:
            pfsense = PFSenseModule(module)
        self.module = module
        self.pfsense = pfsense
        self.ipsec = self.pfsense.ipsec

        self.change_descr = ''

        self.result = {}
        self.result['changed'] = False
        self.result['commands'] = []

        self._params = None
        self._phase1 = None

    def _log_create(self, proposal):
        """ generate pseudo-CLI command to create an ipsec proposal """
        log = "create ipsec_proposal on '{0}'".format(self._params['descr'])

        log += self.format_cli_field(self._params, 'encryption')
        log += self.format_cli_field(self._params, 'key_length')
        log += self.format_cli_field(proposal, 'hash-algorithm', fname='hash')
        log += self.format_cli_field(proposal, 'dhgroup')

        self.result['commands'].append(log)

    def _log_delete(self, proposal):
        """ generate pseudo-CLI command to delete an ipsec proposal """
        log = "delete ipsec_proposal on '{0}'".format(self._params['descr'])

        log += self.format_cli_field(self._params, 'encryption')
        log += self.format_cli_field(self._params, 'key_length')
        log += self.format_cli_field(proposal, 'hash-algorithm', fname='hash')
        log += self.format_cli_field(proposal, 'dhgroup')

        self.result['commands'].append(log)

    def _find_proposal_elt(self, proposal):
        encryption_elt = self._phase1.find('encryption')
        if encryption_elt is None:
            return None

        items_elt = encryption_elt.findall('item')
        for item in items_elt:
            existing = self.pfsense.element_to_dict(item)
            if existing == proposal:
                return item
        return None

    def _add(self, proposal):
        """ add proposal """
        proposal_elt = self._find_proposal_elt(proposal)
        if proposal_elt is None:
            encryption_elt = self._phase1.find('encryption')
            if encryption_elt is None:
                encryption_elt = self.pfsense.new_element('encryption')
                self._phase1.append(encryption_elt)

            proposal_elt = self.pfsense.new_element('item')
            self.pfsense.copy_dict_to_element(proposal, proposal_elt)
            encryption_elt.append(proposal_elt)

            changed = True
            self.change_descr = 'ansible pfsense_ipsec_proposal added to {0}'.format(self._params['descr'])
            self._log_create(proposal)
        else:
            changed = False

        self.result['changed'] = changed

    def _remove_proposal_elt(self, proposal_elt):
        """ delete proposal_elt from xml """
        encryption_elt = self._phase1.find('encryption')
        encryption_elt.remove(proposal_elt)
        self.result['changed'] = True

    def _remove(self, proposal):
        """ delete proposal """
        proposal_elt = self._find_proposal_elt(proposal)
        if proposal_elt is not None:
            self._log_delete(proposal)
            self._remove_proposal_elt(proposal_elt)
            self.change_descr = 'ansible pfsense_ipsec_proposal removed from {0}'.format(self._params['descr'])

    def _validate_params(self, params):
        """ do some extra checks on input parameters """
        key_length = dict()
        key_length['aes'] = ['128', '192', '256']
        key_length['aes192gcm'] = ['64', '96', '128']
        key_length['aes128gcm'] = ['64', '96', '128']
        key_length['aes256gcm'] = ['64', '96', '128']
        key_length['blowfish'] = ['128', '192', '256']
        if params['encryption'] in key_length.keys() and str(params['key_length']) not in key_length[params['encryption']]:
            msg = 'key_length for encryption {0} must be one of: {1}.'.format(params['encryption'], ', '.join(key_length[params['encryption']]))
            self.module.fail_json(msg=msg)

        # called from ipsec_aggregate
        if params.get('ikeid') is not None:
            self._phase1 = self.pfsense.find_ipsec_phase1(params['ikeid'], 'ikeid')
            if self._phase1 is None:
                self.module.fail_json(msg='No ipsec tunnel with ikeid {0}'.format(params['ikeid']))
        else:
            self._phase1 = self.pfsense.find_ipsec_phase1(params['descr'])
            if self._phase1 is None:
                self.module.fail_json(msg='No ipsec tunnel named {0}'.format(params['descr']))

        if params['encryption'] in ['aes128gcm', 'aes192gcm', 'aes256gcm']:
            iketype_elt = self._phase1.find('iketype')
            if iketype_elt is not None and iketype_elt.text != 'ikev2':
                self.module.fail_json(msg='Encryption Algorithm AES-GCM can only be used with IKEv2')

    def _params_to_proposal(self, params):
        """ return a proposal dict from module params """
        self._validate_params(params)

        proposal = dict()
        proposal['encryption-algorithm'] = dict()
        proposal['encryption-algorithm']['name'] = params['encryption']
        if params.get('key_length') is not None:
            proposal['encryption-algorithm']['keylen'] = str(params['key_length'])
        else:
            proposal['encryption-algorithm']['keylen'] = ''
        proposal['hash-algorithm'] = params['hash']
        proposal['dhgroup'] = str(params['dhgroup'])

        return proposal

    def _update(self):
        return self.pfsense.phpshell(
            "require_once('vpn.inc');"
            "$ipsec_dynamic_hosts = vpn_ipsec_configure();"
            "$retval = 0;"
            "$retval |= filter_configure();"
            "if ($ipsec_dynamic_hosts >= 0 && is_subsystem_dirty('ipsec'))"
            "   clear_subsystem_dirty('ipsec');"
        )

    def commit_changes(self):
        """ apply changes and exit module """
        self.result['stdout'] = ''
        self.result['stderr'] = ''
        if self.result['changed'] and not self.module.check_mode:
            self.pfsense.write_config(descr=self.change_descr)
            if self._params['apply']:
                (dummy, self.result['stdout'], self.result['stderr']) = self._update()

        self.module.exit_json(**self.result)

    def run(self, params):
        """ process input params to add/update/delete an ipsec proposal """
        self._params = params
        proposal = self._params_to_proposal(params)

        if params['state'] == 'absent':
            self._remove(proposal)
        else:
            self._add(proposal)
