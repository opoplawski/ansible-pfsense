# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
from ansible.module_utils.network.pfsense.pfsense import PFSenseModule, PFSenseModuleBase


IPSEC_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),
    descr=dict(required=True, type='str'),
    iketype=dict(choices=['ikev1', 'ikev2', 'auto'], type='str'),
    protocol=dict(default='inet', choices=['inet', 'inet6', 'both']),
    interface=dict(required=False, type='str'),
    remote_gateway=dict(required=False, type='str'),
    disabled=dict(required=False, type='bool'),

    authentication_method=dict(choices=['pre_shared_key', 'rsasig']),
    mode=dict(required=False, choices=['main', 'aggressive']),
    myid_type=dict(default='myaddress', choices=['myaddress', 'address', 'fqdn', 'user_fqdn', 'asn1dn', 'keyid tag', 'dyn_dns']),
    myid_data=dict(required=False, type='str'),
    peerid_type=dict(default='peeraddress', choices=['any', 'peeraddress', 'address', 'fqdn', 'user_fqdn', 'asn1dn', 'keyid tag']),
    peerid_data=dict(required=False, type='str'),
    certificate=dict(required=False, type='str'),
    certificate_authority=dict(required=False, type='str'),
    preshared_key=dict(required=False, type='str'),

    lifetime=dict(default=28800, type='int'),

    disable_rekey=dict(default=False, type='bool'),
    margintime=dict(required=False, type='int'),
    responderonly=dict(default=False, type='bool'),
    disable_reauth=dict(default=False, type='bool'),
    mobike=dict(default='off', choices=['on', 'off']),
    splitconn=dict(default=False, type='bool'),

    nat_traversal=dict(default='on', choices=['on', 'force']),
    enable_dpd=dict(default=True, type='bool'),
    dpd_delay=dict(default=10, type='int'),
    dpd_maxfail=dict(default=5, type='int'),
    apply=dict(default=True, type='bool'),
)

IPSEC_REQUIRED_IF = [
    ["state", "present", ["remote_gateway", "interface", "iketype", "authentication_method"]],

    ["enable_dpd", True, ["dpd_delay", "dpd_maxfail"]],
    ["iketype", "auto", ["mode"]],
    ["iketype", "ikev1", ["mode"]],
    ["authentication_method", "pre_shared_key", ["preshared_key"]],
    ["authentication_method", "rsasig", ["certificate", "certificate_authority"]],
    ["myid_type", "address", ["myid_data"]],
    ["myid_type", "fqdn", ["myid_data"]],
    ["myid_type", "user_fqdn", ["myid_data"]],
    ["myid_type", "asn1dn", ["myid_data"]],
    ["myid_type", "keyid tag", ["myid_data"]],
    ["myid_type", "dyn_dns", ["myid_data"]],

    ["peerid_type", "address", ["peerid_data"]],
    ["peerid_type", "fqdn", ["peerid_data"]],
    ["peerid_type", "user_fqdn", ["peerid_data"]],
    ["peerid_type", "asn1dn", ["peerid_data"]],
    ["peerid_type", "keyid tag", ["peerid_data"]],
]


class PFSenseIpsecModule(PFSenseModuleBase):
    """ module managing pfsense ipsec tunnels phase 1 options """

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

    def _log_create(self, ipsec):
        """ generate pseudo-CLI command to create an ipsec tunnel """
        log = "create ipsec '{0}'".format(ipsec['descr'])
        log += self.format_cli_field(self._params, 'disabled', fvalue=self.fvalue_bool)
        log += self.format_cli_field(ipsec, 'iketype')
        if ipsec['iketype'] != 'ikev2':
            log += self.format_cli_field(ipsec, 'mode')

        log += self.format_cli_field(ipsec, 'protocol')
        log += self.format_cli_field(self._params, 'interface')
        log += self.format_cli_field(ipsec, 'remote-gateway', fname='remote_gateway')
        log += self.format_cli_field(ipsec, 'authentication_method')
        if ipsec['authentication_method'] == 'rsasig':
            log += self.format_cli_field(self._params, 'certificate')
            log += self.format_cli_field(self._params, 'certificate_authority')
        else:
            log += self.format_cli_field(ipsec, 'pre-shared-key', fname='preshared_key')

        id_types = ['address', 'fqdn', 'user_fqdn', 'asn1dn', 'keyid tag', 'dyn_dns']
        log += self.format_cli_field(ipsec, 'myid_type')
        if ipsec['myid_type'] in id_types:
            log += self.format_cli_field(ipsec, 'myid_data')

        log += self.format_cli_field(ipsec, 'peerid_type')
        if ipsec['peerid_type'] in id_types:
            log += self.format_cli_field(ipsec, 'peerid_data')

        log += self.format_cli_field(ipsec, 'lifetime')

        log += self.format_cli_field(self._params, 'disable_rekey', fvalue=self.fvalue_bool)
        if not self._params['disable_rekey']:
            log += self.format_cli_field(ipsec, 'margintime')

        if ipsec['iketype'] == 'ikev2':
            log += self.format_cli_field(ipsec, 'reauth_enable', fname='disable_reauth', fvalue=self.fvalue_bool)
            log += self.format_cli_field(ipsec, 'mobike')
            log += self.format_cli_field(ipsec, 'splitconn', fvalue=self.fvalue_bool)

        log += self.format_cli_field(self._params, 'responderonly', fvalue=self.fvalue_bool)
        log += self.format_cli_field(ipsec, 'nat_traversal')

        log += self.format_cli_field(self._params, 'enable_dpd', fvalue=self.fvalue_bool)
        if self._params['enable_dpd']:
            log += self.format_cli_field(ipsec, 'dpd_delay')
            log += self.format_cli_field(ipsec, 'dpd_maxfail')

        self.result['commands'].append(log)

    def _log_delete(self, ipsec):
        """ generate pseudo-CLI command to delete an ipsec tunnel """
        log = "delete ipsec '{0}'".format(ipsec['descr'])
        self.result['commands'].append(log)

    def _get_ref_names(self, before):
        """ get cert and ca names """
        if before['caref'] is not None and before['caref'] != '':
            elt = self.pfsense.find_ca_elt(before['caref'], 'refid')
            if elt is not None:
                before['certificate_authority'] = elt.find('descr').text

        if before['certref'] is not None and before['certref'] != '':
            elt = self.pfsense.find_cert_elt(before['certref'], 'refid')
            if elt is not None:
                before['certificate'] = elt.find('descr').text

    def _log_update(self, ipsec, before):
        """ generate pseudo-CLI command to update an ipsec tunnel """

        self._get_ref_names(before)

        log = "update ipsec '{0}'".format(ipsec['descr'])
        values = ''
        values += self.format_updated_cli_field(ipsec, before, 'disabled', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(ipsec, before, 'iketype', add_comma=(values))
        if ipsec['iketype'] != 'ikev2':
            values += self.format_updated_cli_field(ipsec, before, 'mode', add_comma=(values))
        values += self.format_updated_cli_field(ipsec, before, 'protocol', add_comma=(values))
        values += self.format_updated_cli_field(ipsec, before, 'interface', add_comma=(values))
        values += self.format_updated_cli_field(ipsec, before, 'remote-gateway', add_comma=(values), fname='remote_gateway')
        values += self.format_updated_cli_field(ipsec, before, 'authentication_method', add_comma=(values))
        if ipsec['authentication_method'] == 'rsasig':
            values += self.format_updated_cli_field(self._params, before, 'certificate', add_comma=(values))
            values += self.format_updated_cli_field(self._params, before, 'certificate_authority', add_comma=(values))
        else:
            values += self.format_updated_cli_field(ipsec, before, 'pre-shared-key', add_comma=(values), fname='preshared_key')
        values += self.format_updated_cli_field(ipsec, before, 'myid_type', add_comma=(values))
        id_types = ['address', 'fqdn', 'user_fqdn', 'asn1dn', 'keyid tag', 'dyn_dns']
        if ipsec['myid_type'] in id_types:
            values += self.format_updated_cli_field(ipsec, before, 'myid_data', add_comma=(values))

        values += self.format_updated_cli_field(ipsec, before, 'peerid_type', add_comma=(values))
        if ipsec['peerid_type'] in id_types:
            values += self.format_updated_cli_field(ipsec, before, 'peerid_data', add_comma=(values))

        values += self.format_updated_cli_field(ipsec, before, 'lifetime', add_comma=(values))

        values += self.format_updated_cli_field(ipsec, before, 'disable_rekey', add_comma=(values), fvalue=self.fvalue_bool)
        if not self._params['disable_rekey']:
            values += self.format_updated_cli_field(ipsec, before, 'margintime', add_comma=(values))

        if ipsec['iketype'] == 'ikev2':
            values += self.format_updated_cli_field(ipsec, before, 'reauth_enable', add_comma=(values), fname='disable_reauth', fvalue=self.fvalue_bool)
            values += self.format_updated_cli_field(ipsec, before, 'mobike', add_comma=(values))
            values += self.format_updated_cli_field(ipsec, before, 'splitconn', add_comma=(values), fvalue=self.fvalue_bool)

        values += self.format_updated_cli_field(ipsec, before, 'responderonly', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(ipsec, before, 'nat_traversal', add_comma=(values))
        values += self.format_updated_cli_field(ipsec, before, 'enable_dpd', add_comma=(values), fvalue=self.fvalue_bool)
        if self._params['enable_dpd']:
            values += self.format_updated_cli_field(ipsec, before, 'dpd_delay', add_comma=(values))
            values += self.format_updated_cli_field(ipsec, before, 'dpd_maxfail', add_comma=(values))
        self.result['commands'].append(log + ' set ' + values)

    def _find_free_ikeid(self):
        """ return first unused ikeid """
        ikeid = 1
        while True:
            found = False
            for ipsec_elt in self.ipsec:
                ikeid_elt = ipsec_elt.find('ikeid')
                if ikeid_elt is not None and ikeid_elt.text == str(ikeid):
                    found = True
                    break

            if not found:
                return ikeid
            ikeid = ikeid + 1

    def _add(self, ipsec):
        """ add or update ipsec """
        # called from ipsec_aggregate
        if self._params.get('ikeid') is not None:
            ipsec_elt = self.pfsense.find_ipsec_phase1(self._params['ikeid'], 'ikeid')
        else:
            ipsec_elt = self.pfsense.find_ipsec_phase1(ipsec['descr'])
        if ipsec_elt is None:
            ipsec_elt = self.pfsense.new_element('phase1')
            ipsec['ikeid'] = str(self._find_free_ikeid())
            self.pfsense.copy_dict_to_element(ipsec, ipsec_elt)
            self.ipsec.append(ipsec_elt)

            changed = True
            self.change_descr = 'ansible pfsense_ipsec added {0}'.format(ipsec['descr'])
            self._log_create(ipsec)
        else:
            before = self.pfsense.element_to_dict(ipsec_elt)
            changed = self.pfsense.copy_dict_to_element(ipsec, ipsec_elt)

            if self._remove_deleted_ipsec_params(ipsec_elt, ipsec):
                changed = True

            if changed:
                self.change_descr = 'ansible pfsense_ipsec updated {0}'.format(ipsec['descr'])
                self._log_update(ipsec, before)

        if changed:
            self.result['changed'] = changed

    def _remove_deleted_ipsec_params(self, ipsec_elt, ipsec):
        """ Remove from ipsec a few deleted params """
        changed = False
        params = ['disabled', 'rekey_enable', 'reauth_enable', 'splitconn']

        if self._params['disable_rekey']:
            params.append('margintime')

        if not self._params['enable_dpd']:
            params.append('dpd_delay')
            params.append('dpd_maxfail')

        for param in params:
            if self.pfsense.remove_deleted_param_from_elt(ipsec_elt, param, ipsec):
                changed = True

        return changed

    def _remove_ipsec_elt(self, ipsec_elt):
        """ delete ipsec_elt from xml """
        self.ipsec.remove(ipsec_elt)
        self.result['changed'] = True

    def _remove_phases2(self, ipsec_elt):
        """ remove phase2 elts from xml """
        ikeid_elt = ipsec_elt.find('ikeid')
        if ikeid_elt is None:
            return
        ikeid = ikeid_elt.text
        phase2_elts = self.ipsec.findall('phase2')
        for phase2_elt in phase2_elts:
            ikeid_elt = phase2_elt.find('ikeid')
            if ikeid_elt is None:
                continue
            if ikeid == ikeid_elt.text:
                self.ipsec.remove(phase2_elt)

    def _remove(self, ipsec):
        """ delete ipsec """
        ipsec_elt = self.pfsense.find_ipsec_phase1(ipsec['descr'])
        if ipsec_elt is not None:
            self._log_delete(ipsec)
            self._remove_phases2(ipsec_elt)
            self._remove_ipsec_elt(ipsec_elt)
            self.change_descr = 'ansible pfsense_ipsec removed {0}'.format(ipsec['descr'])

    def _validate_params(self, params):
        """ do some extra checks on input parameters """
        if params['state'] == 'absent':
            return

        for ipsec_elt in self.ipsec:
            if ipsec_elt.tag != 'phase1':
                continue

            # don't check on ourself
            name = ipsec_elt.find('descr')
            if name is None:
                name = ''
            else:
                name = name.text

            if name == params['descr']:
                continue

            # two ikev2 can share the same gateway
            iketype_elt = ipsec_elt.find('iketype')
            if iketype_elt is None:
                continue

            if iketype_elt.text == 'ikev2' and iketype_elt.text == params['iketype']:
                continue

            # others can't share the same gateway
            rgw_elt = ipsec_elt.find('remote-gateway')
            if rgw_elt is None:
                continue

            if rgw_elt.text == params['remote_gateway']:
                self.module.fail_json(msg='The remote gateway "{0}" is already used by phase1 "{1}".'.format(params['remote_gateway'], name))

    def _parse_ipsec_interface(self, interface):
        """ validate and return the tunnel interface param """
        if self.pfsense.is_interface_name(interface):
            return self.pfsense.get_interface_pfsense_by_name(interface)
        elif self.pfsense.is_interface_pfsense(interface):
            return interface

        self.module.fail_json(msg='%s is not a valid interface' % (interface))
        return None

    def _params_to_ipsec(self, params):
        """ return an ipsec dict from module params """
        self._validate_params(params)

        ipsec = dict()
        ipsec['descr'] = params['descr']

        if params['state'] == 'present':
            ipsec['interface'] = self._parse_ipsec_interface(params['interface'])
            ipsec['iketype'] = params['iketype']

            if params.get('mode') is not None:
                ipsec['mode'] = params['mode']
            ipsec['nat_traversal'] = params['nat_traversal']

            ipsec['protocol'] = params['protocol']
            ipsec['remote-gateway'] = params['remote_gateway']
            if params.get('disabled'):
                ipsec['disabled'] = None

            ipsec['myid_type'] = params['myid_type']
            ipsec['myid_data'] = params['myid_data']
            ipsec['peerid_type'] = params['peerid_type']
            ipsec['peerid_data'] = params['peerid_data']

            ipsec['authentication_method'] = params['authentication_method']
            if params['authentication_method'] == 'rsasig':
                ca_elt = self.pfsense.find_ca_elt(params['certificate_authority'])
                if ca_elt is None:
                    self.module.fail_json(msg='%s is not a valid certificate authority' % (params['certificate_authority']))
                ipsec['caref'] = ca_elt.find('refid').text

                cert = self.pfsense.find_cert_elt(params['certificate'])
                if cert is None:
                    self.module.fail_json(msg='%s is not a valid certificate' % (params['certificate']))
                ipsec['certref'] = cert.find('refid').text
                ipsec['pre-shared-key'] = ''
            else:
                ipsec['caref'] = ''
                ipsec['certref'] = ''
                ipsec['pre-shared-key'] = params['preshared_key']

            ipsec['lifetime'] = str(params['lifetime'])

            if params.get('disable_rekey'):
                ipsec['rekey_enable'] = ''

            if params.get('margintime') is not None:
                ipsec['margintime'] = str(params['margintime'])
            else:
                ipsec['margintime'] = ''

            if params.get('responderonly'):
                ipsec['responderonly'] = params['responderonly']

            if params.get('enable_dpd'):
                ipsec['dpd_delay'] = str(params['dpd_delay'])
                ipsec['dpd_maxfail'] = str(params['dpd_maxfail'])

            if params.get('disable_reauth'):
                ipsec['reauth_enable'] = ''
            if params.get('splitconn'):
                ipsec['splitconn'] = ''
            if params.get('mobike'):
                ipsec['mobike'] = params['mobike']

        return ipsec

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
        """ process input params to add/update/delete an ipsec tunnel """
        self._params = params
        ipsec = self._params_to_ipsec(params)

        if params['state'] == 'absent':
            self._remove(ipsec)
        else:
            self._add(ipsec)
