# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
from ansible.module_utils.network.pfsense.pfsense import PFSenseModule, PFSenseModuleBase
from copy import deepcopy

IPSEC_P2_ARGUMENT_SPEC = dict(
    apply=dict(default=True, type='bool'),
    state=dict(default='present', choices=['present', 'absent']),
    descr=dict(required=True, type='str'),
    p1_descr=dict(required=True, type='str'),

    disabled=dict(default=False, type='bool'),
    mode=dict(choices=['tunnel', 'tunnel6', 'transport', 'vti'], type='str'),
    protocol=dict(default='esp', choices=['esp', 'ah'], type='str'),

    # addresses
    local=dict(required=False, type='str'),
    nat=dict(required=False, type='str'),
    remote=dict(required=False, type='str'),

    # encryptions
    aes=dict(required=False, type='bool'),
    aes128gcm=dict(required=False, type='bool'),
    aes192gcm=dict(required=False, type='bool'),
    aes256gcm=dict(required=False, type='bool'),
    blowfish=dict(required=False, type='bool'),
    des=dict(required=False, type='bool'),
    cast128=dict(required=False, type='bool'),
    aes_len=dict(required=False, choices=['auto', '128', '192', '256'], type='str'),
    aes128gcm_len=dict(required=False, choices=['auto', '64', '96', '128'], type='str'),
    aes192gcm_len=dict(required=False, choices=['auto', '64', '96', '128'], type='str'),
    aes256gcm_len=dict(required=False, choices=['auto', '64', '96', '128'], type='str'),
    blowfish_len=dict(required=False, choices=['auto', '128', '192', '256'], type='str'),

    # hashes
    md5=dict(required=False, type='bool'),
    sha1=dict(required=False, type='bool'),
    sha256=dict(required=False, type='bool'),
    sha384=dict(required=False, type='bool'),
    sha512=dict(required=False, type='bool'),
    aesxcbc=dict(required=False, type='bool'),

    # misc
    pfsgroup=dict(default='14', choices=['0', '1', '2', '5', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '28', '29', '30'], type='str'),
    lifetime=dict(default=3600, type='int'),
    pinghost=dict(required=False, type='str')
)

IPSEC_P2_REQUIRED_IF = [
    ["state", "present", ["mode"]],

    ["mode", "tunnel", ["local", "remote"]],
    ["mode", "tunnel6", ["local", "remote"]],
    ["mode", "vti", ["local", "remote"]],

    # encryptions
    ["aes", True, ["aes_len"]],
    ["aes128gcm", True, ["aes128gcm_len"]],
    ["aes192gcm", True, ["aes192gcm_len"]],
    ["aes256gcm", True, ["aes256gcm_len"]],
    ["blowfish", True, ["blowfish_len"]],
]


class PFSenseIpsecP2Module(PFSenseModuleBase):
    """ module managing pfsense ipsec phase 2 options and proposals """

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

    def _log_create(self, phase2):
        """ generate pseudo-CLI command to create a phase2 """
        def log_enc(name):
            log = ''
            log += self.format_cli_field(self._params, name, fvalue=self.fvalue_bool)
            if self._params.get(name) and self._params.get(name + '_len') is not None:
                log += self.format_cli_field(self._params, name + '_len')
            return log
        log = "create ipsec_p2 '{0}' on '{1}'".format(phase2['descr'], self._params['p1_descr'])
        log += self.format_cli_field(self._params, 'disabled', fvalue=self.fvalue_bool)
        log += self.format_cli_field(phase2, 'mode')

        log += self.format_cli_field(self._params, 'local')
        log += self.format_cli_field(self._params, 'remote')
        log += self.format_cli_field(self._params, 'nat')

        log += log_enc('aes')
        log += log_enc('aes128gcm')
        log += log_enc('aes192gcm')
        log += log_enc('aes256gcm')
        log += log_enc('blowfish')
        log += log_enc('des')
        log += log_enc('cast128')

        log += self.format_cli_field(self._params, 'md5', fvalue=self.fvalue_bool)
        log += self.format_cli_field(self._params, 'sha1', fvalue=self.fvalue_bool)
        log += self.format_cli_field(self._params, 'sha256', fvalue=self.fvalue_bool)
        log += self.format_cli_field(self._params, 'sha384', fvalue=self.fvalue_bool)
        log += self.format_cli_field(self._params, 'sha512', fvalue=self.fvalue_bool)
        log += self.format_cli_field(self._params, 'aesxcbc', fvalue=self.fvalue_bool)

        log += self.format_cli_field(self._params, 'pfsgroup')
        log += self.format_cli_field(self._params, 'lifetime')
        log += self.format_cli_field(self._params, 'pinghost')

        self.result['commands'].append(log)

    def _log_delete(self, phase2):
        """ generate pseudo-CLI command to delete a phase2 """
        log = "delete ipsec_p2 '{0}' on '{1}'".format(phase2['descr'], self._params['p1_descr'])
        self.result['commands'].append(log)

    def _prepare_log_address(self, before, param, name):
        """ reparse some params for logging """
        if before.get(name) is None or not isinstance(before[name], dict) or before[name].get('type') is None:
            before[param] = None
            return

        if before[name]['type'] == 'address':
            before[param] = before[name]['address']
        elif before[name]['type'] == 'network':
            before[param] = before[name]['address'] + '/' + str(before[name]['netbits'])
        else:
            before[param] = self.pfsense.get_interface_display_name(before[name]['type'])

    @staticmethod
    def _prepare_log_encryptions(before, before_elt):
        """ reparse some params for logging """
        encryptions_elt = before_elt.findall('encryption-algorithm-option')
        for encryption_elt in encryptions_elt:
            name = encryption_elt.find('name').text
            len_elt = encryption_elt.find('keylen')
            if name == '3des':
                name = 'des'
            before[name] = True
            if len_elt is not None:
                before[name + '_len'] = len_elt.text

        encs = ['aes', 'aes128gcm', 'aes192gcm', 'aes256gcm', 'blowfish', 'des', 'cast128']
        for enc in encs:
            if enc not in before.keys():
                before[enc] = False
            if enc + '_len' not in before.keys():
                before[enc + '_len'] = None

    @staticmethod
    def _prepare_log_hashes(before, before_elt):
        """ reparse some params for logging """
        hashes_elt = before_elt.findall('hash-algorithm-option')
        for hash_elt in hashes_elt:
            name = hash_elt.text.replace("hmac_", "")
            before[name] = True

    def _log_update(self, phase2, before, before_elt):
        """ generate pseudo-CLI command to update a phase2 """
        self._prepare_log_address(before, 'local', 'localid')
        self._prepare_log_address(before, 'nat', 'natlocalid')
        self._prepare_log_address(before, 'remote', 'remoteid')
        self._prepare_log_encryptions(before, before_elt)
        self._prepare_log_hashes(before, before_elt)

        log = "update ipsec_p2 '{0}' on '{1}'".format(phase2['descr'], self._params['p1_descr'])
        values = ''
        values += self.format_updated_cli_field(phase2, before, 'disabled', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(phase2, before, 'mode', add_comma=(values))

        values += self.format_updated_cli_field(self._params, before, 'local', add_comma=(values))
        values += self.format_updated_cli_field(self._params, before, 'remote', add_comma=(values))
        values += self.format_updated_cli_field(self._params, before, 'nat', add_comma=(values))

        values += self.format_updated_cli_field(self._params, before, 'aes', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(self._params, before, 'aes_len', add_comma=(values))
        values += self.format_updated_cli_field(self._params, before, 'aes128gcm', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(self._params, before, 'aes128gcm_len', add_comma=(values))
        values += self.format_updated_cli_field(self._params, before, 'aes192gcm', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(self._params, before, 'aes192gcm_len', add_comma=(values))
        values += self.format_updated_cli_field(self._params, before, 'aes256gcm', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(self._params, before, 'aes256gcm_len', add_comma=(values))
        values += self.format_updated_cli_field(self._params, before, 'blowfish', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(self._params, before, 'blowfish_len', add_comma=(values))
        values += self.format_updated_cli_field(self._params, before, 'des', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(self._params, before, 'cast128', add_comma=(values), fvalue=self.fvalue_bool)

        values += self.format_updated_cli_field(self._params, before, 'md5', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(self._params, before, 'sha1', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(self._params, before, 'sha256', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(self._params, before, 'sha384', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(self._params, before, 'sha512', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(self._params, before, 'aesxcbc', add_comma=(values), fvalue=self.fvalue_bool)

        values += self.format_updated_cli_field(phase2, before, 'pfsgroup', add_comma=(values))
        values += self.format_updated_cli_field(phase2, before, 'lifetime', add_comma=(values))
        values += self.format_updated_cli_field(phase2, before, 'pinghost', add_comma=(values))

        self.result['commands'].append(log + ' set ' + values)

    def _find_free_reqid(self):
        """ return first unused reqid """
        reqid = 1
        while True:
            found = False
            for phase2_elt in self.ipsec:
                if phase2_elt.tag != 'phase2':
                    continue
                reqid_elt = phase2_elt.find('reqid')
                if reqid_elt is not None and reqid_elt.text == str(reqid):
                    found = True
                    break

            if not found:
                return reqid
            reqid = reqid + 1

    def _find_ipsec_phase2(self, descr):
        """ return ipsec phase2 elt if found """
        ikeid = self._phase1.find('ikeid').text
        for phase2_elt in self.ipsec:
            if phase2_elt.tag != 'phase2':
                continue

            if phase2_elt.find('ikeid').text != ikeid:
                continue

            descr_elt = phase2_elt.find('descr')
            if descr_elt is not None and descr_elt.text == descr:
                return phase2_elt

        return None

    def _sync_encryptions(self, phase2_elt):
        """ sync encryptions params """
        def get_encryption(encryptions_elt, name):
            for encryption_elt in encryptions_elt:
                name_elt = encryption_elt.find('name')
                if name_elt is not None and name_elt.text == name:
                    return encryption_elt
            return None

        def sync_encryption(encryptions_elt, name, param_name):
            encryption_elt = get_encryption(encryptions_elt, name)
            if self._params.get(param_name):
                encryption = dict()
                encryption['name'] = name
                if self._params.get(param_name + '_len') is not None:
                    encryption['keylen'] = self._params[param_name + '_len']
                if encryption_elt is None:
                    encryption_elt = self.pfsense.new_element('encryption-algorithm-option')
                    self.pfsense.copy_dict_to_element(encryption, encryption_elt)
                    phase2_elt.append(encryption_elt)
                    return True
                else:
                    old_encryption = self.pfsense.element_to_dict(encryption_elt)
                    if old_encryption != encryption:
                        self.pfsense.copy_dict_to_element(encryption, encryption_elt)
                        return True
            else:
                if encryption_elt is not None:
                    phase2_elt.remove(encryption_elt)
                    return True
            return False

        changed = False
        encryptions_elt = phase2_elt.findall('encryption-algorithm-option')
        if sync_encryption(encryptions_elt, 'aes', 'aes'):
            changed = True
        if sync_encryption(encryptions_elt, 'aes128gcm', 'aes128gcm'):
            changed = True
        if sync_encryption(encryptions_elt, 'aes192gcm', 'aes192gcm'):
            changed = True
        if sync_encryption(encryptions_elt, 'aes256gcm', 'aes256gcm'):
            changed = True
        if sync_encryption(encryptions_elt, 'blowfish', 'blowfish'):
            changed = True
        if sync_encryption(encryptions_elt, '3des', 'des'):
            changed = True
        if sync_encryption(encryptions_elt, 'cast128', 'cast128'):
            changed = True
        return changed

    def _sync_hashes(self, phase2_elt):
        """ sync hashes params """
        def get_hash(hashes_elt, name):
            for hash_elt in hashes_elt:
                if hash_elt.text == name:
                    return hash_elt
            return None

        def sync_hash(hashes_elt, name, param_name):
            if self._params.get(param_name) is not None:
                if get_hash(hashes_elt, name) is None:
                    hash_elt = self.pfsense.new_element('hash-algorithm-option')
                    hash_elt.text = name
                    phase2_elt.append(hash_elt)
                    return True
            else:
                hash_elt = get_hash(hashes_elt, name)
                if hash_elt is not None:
                    phase2_elt.remove(hash_elt)
                    return True
            return False

        changed = False
        hashes_elt = phase2_elt.findall('hash-algorithm-option')
        if sync_hash(hashes_elt, 'hmac_md5', 'md5'):
            changed = True
        if sync_hash(hashes_elt, 'hmac_sha1', 'sha1'):
            changed = True
        if sync_hash(hashes_elt, 'hmac_sha256', 'sha256'):
            changed = True
        if sync_hash(hashes_elt, 'hmac_sha384', 'sha384'):
            changed = True
        if sync_hash(hashes_elt, 'hmac_sha512', 'sha512'):
            changed = True
        if sync_hash(hashes_elt, 'aesxcbc', 'aesxcbc'):
            changed = True
        return changed

    def _add(self, phase2):
        """ add or update phase2 """
        phase2_elt = self._find_ipsec_phase2(phase2['descr'])
        if phase2_elt is None:
            phase2_elt = self.pfsense.new_element('phase2')
            phase2['ikeid'] = self._phase1.find('ikeid').text
            phase2['uniqid'] = self.pfsense.uniqid()
            phase2['reqid'] = str(self._find_free_reqid())

            self.pfsense.copy_dict_to_element(phase2, phase2_elt)
            self._sync_encryptions(phase2_elt)
            self._sync_hashes(phase2_elt)
            self.ipsec.append(phase2_elt)

            changed = True
            self.change_descr = 'ansible pfsense_ipsec_p2 added {0}'.format(phase2['descr'])
            self._log_create(phase2)
        else:
            before_elt = deepcopy(phase2_elt)
            before = self.pfsense.element_to_dict(phase2_elt)
            changed = self.pfsense.copy_dict_to_element(phase2, phase2_elt)

            if self._sync_encryptions(phase2_elt):
                changed = True

            if self._sync_hashes(phase2_elt):
                changed = True

            if self._remove_deleted_ipsec_params(phase2_elt, phase2):
                changed = True

            if changed:
                self.change_descr = 'ansible pfsense_ipsec_p2 updated {0}'.format(phase2['descr'])
                self._log_update(phase2, before, before_elt)

        if changed:
            self.result['changed'] = changed

    def _remove_extra_deleted_ipsec_params(self, name, phase2_elt, phase2):
        """ Remove from phase2 a few extra deleted params """
        changed = False

        params = ['type', 'address', 'netbits']
        sub_elt = phase2_elt.find(name)
        if sub_elt is not None:
            for param in params:
                if name in phase2:
                    if self.pfsense.remove_deleted_param_from_elt(sub_elt, param, phase2[name]):
                        changed = True
                else:
                    if self.pfsense.remove_deleted_param_from_elt(sub_elt, param, dict()):
                        changed = True

            if not sub_elt:
                phase2_elt.remove(sub_elt)

        return changed

    def _remove_deleted_ipsec_params(self, phase2_elt, phase2):
        """ Remove from phase2 a few deleted params """
        changed = False
        params = ['disabled']

        for param in params:
            if self.pfsense.remove_deleted_param_from_elt(phase2_elt, param, phase2):
                changed = True

        if self._remove_extra_deleted_ipsec_params('localid', phase2_elt, phase2):
            changed = True
        if self._remove_extra_deleted_ipsec_params('remoteid', phase2_elt, phase2):
            changed = True
        if self._remove_extra_deleted_ipsec_params('natlocalid', phase2_elt, phase2):
            changed = True

        return changed

    def _remove_phase2_elt(self, phase2_elt):
        """ delete phase2_elt from xml """
        self.ipsec.remove(phase2_elt)
        self.result['changed'] = True

    def _remove(self, phase2):
        """ delete ipsec phase2 """
        phase2_elt = self._find_ipsec_phase2(phase2['descr'])
        if phase2_elt is not None:
            self._log_delete(phase2)
            self._remove_phase2_elt(phase2_elt)
            self.change_descr = 'ansible pfsense_ipsec_p2 removed {0}'.format(phase2['descr'])

    def _validate_params(self, params):
        """ do some extra checks on input parameters """
        def has_one_of(bools):
            for name in bools:
                if params.get(name):
                    return True
            return False

        self._phase1 = self.pfsense.find_ipsec_phase1(params['p1_descr'])
        if self._phase1 is None:
            self.module.fail_json(msg='No ipsec tunnel named {0}'.format(params['p1_descr']))

        if params['state'] == 'present':
            encs = ['aes', 'aes128gcm', 'aes192gcm', 'aes256gcm', 'blowfish', 'des', 'cast128']
            if params['protocol'] == 'esp' and not has_one_of(encs):
                self.module.fail_json(msg='At least one encryption algorithm must be selected.')

            hashes = ['md5', 'sha1', 'sha256', 'sha384', 'sha512', 'aesxcbc']
            if not has_one_of(hashes):
                self.module.fail_json(msg='At least one hashing algorithm needs to be selected.')

    def _parse_ipsec_interface(self, interface):
        """ validate and return an interface param """
        if self.pfsense.is_interface_name(interface):
            return self.pfsense.get_interface_pfsense_by_name(interface)
        elif self.pfsense.is_interface_pfsense(interface):
            return interface

        return None

    def _id_to_phase2(self, name, phase2, address, param_name):
        """ setup ipsec phase2 with address """
        def set_ip_address():
            phase2[name]['type'] = 'address'
            phase2[name]['address'] = address

        def set_ip_network():
            phase2[name]['type'] = 'network'
            (phase2[name]['address'], phase2[name]['netbits']) = self.pfsense.parse_ip_network(address, False)
            phase2[name]['netbits'] = str(phase2[name]['netbits'])
        phase2[name] = dict()

        interface = self._parse_ipsec_interface(address)
        if interface is not None:
            if phase2['mode'] == 'vti':
                msg = 'VTI requires a valid local network or IP address for its endpoint address.'
                self.module.fail_json(msg=msg)
            phase2[name]['type'] = interface
        elif self.pfsense.is_ipv4_address(address):
            if self._params['mode'] == 'tunnel6':
                self.module.fail_json(msg='A valid IPv6 address or network must be specified in {0} with tunnel6.'.format(param_name))
            set_ip_address()
        elif self.pfsense.is_ipv6_address(address):
            if self._params['mode'] == 'tunnel':
                self.module.fail_json(msg='A valid IPv4 address or network must be specified in {0} with tunnel.'.format(param_name))
            set_ip_address()
        elif self.pfsense.is_ipv4_network(address, False):
            if self._params['mode'] == 'tunnel6':
                self.module.fail_json(msg='A valid IPv6 address or network must be specified in {0} with tunnel6.'.format(param_name))
            set_ip_network()
        elif self.pfsense.is_ipv6_network(address, False):
            if self._params['mode'] == 'tunnel':
                self.module.fail_json(msg='A valid IPv4 address or network must be specified in {0} with tunnel.'.format(param_name))
            set_ip_network()
        else:
            self.module.fail_json(msg='A valid IP address, network or interface must be specified in {0}.'.format(param_name))

    def _check_for_duplicate_phase2(self, phase2):
        """ check for another phase2 with same remote and local """
        def strip_phase(phase):
            _phase2 = {}
            if phase.get('localid') is not None:
                _phase2['localid'] = phase['localid']
            if phase.get('remoteid') is not None:
                _phase2['remoteid'] = phase['remoteid']
            return _phase2

        _phase2 = strip_phase(phase2)
        ikeid = self._phase1.find('ikeid').text
        for phase2_elt in self.ipsec:
            if phase2_elt.tag != 'phase2':
                continue

            if phase2_elt.find('ikeid').text != ikeid:
                continue

            if phase2_elt.find('descr').text == phase2['descr']:
                continue

            other_phase2 = self.pfsense.element_to_dict(phase2_elt)
            if _phase2 == strip_phase(other_phase2):
                self.module.fail_json(msg='Phase2 with this Local/Remote networks combination is already defined for this Phase1.')

    def _params_to_phase2(self, params):
        """ return an phase2 dict from module params """
        self._validate_params(params)

        phase2 = dict()
        phase2['descr'] = params['descr']

        if params['state'] == 'present':
            phase2['mode'] = params['mode']
            if phase2['mode'] != 'transport':

                if phase2['mode'] == 'vti' and not self.pfsense.is_ip_address(params['remote']):
                    msg = 'VTI requires a valid remote IP address for its endpoint address.'
                    self.module.fail_json(msg=msg)

                self._id_to_phase2('localid', phase2, params['local'], 'local')
                self._id_to_phase2('remoteid', phase2, params['remote'], 'remote')

                if phase2['mode'] != 'vti' and params.get('nat') is not None:
                    self._id_to_phase2('natlocalid', phase2, params['nat'], 'nat')

            if params.get('disabled'):
                phase2['disabled'] = ''

            phase2['protocol'] = params['protocol']
            phase2['pfsgroup'] = params['pfsgroup']
            if params.get('lifetime') is not None and params['lifetime'] > 0:
                phase2['lifetime'] = str(params['lifetime'])
            else:
                phase2['lifetime'] = ''

            if phase2.get('pinghost'):
                phase2['pinghost'] = params['pinghost']
            else:
                phase2['pinghost'] = ''

            self._check_for_duplicate_phase2(phase2)

        return phase2

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
        """ process input params to add/update/delete an ipsec phase2 """
        self._params = params
        phase2 = self._params_to_phase2(params)

        if params['state'] == 'absent':
            self._remove(phase2)
        else:
            self._add(phase2)
