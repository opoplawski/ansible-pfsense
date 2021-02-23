# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase


IPSEC_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),
    descr=dict(required=True, type='str'),
    iketype=dict(choices=['ikev1', 'ikev2', 'auto'], type='str'),
    protocol=dict(default='inet', choices=['inet', 'inet6', 'both']),
    interface=dict(required=False, type='str'),
    remote_gateway=dict(required=False, type='str'),
    nattport=dict(required=False, type='int'),

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
    rekey_time=dict(required=False, type='int'),
    reauth_time=dict(required=False, type='int'),
    rand_time=dict(required=False, type='int'),

    disable_rekey=dict(required=False, type='bool'),
    margintime=dict(required=False, type='int'),
    responderonly=dict(default=False, type='bool'),
    disable_reauth=dict(default=False, type='bool'),
    mobike=dict(default='off', choices=['on', 'off']),
    gw_duplicates=dict(required=False, type='bool'),
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

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return IPSEC_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseIpsecModule, self).__init__(module, pfsense)
        self.name = "pfsense_ipsec"
        self.obj = dict()
        self.apply = True

        self.root_elt = self.pfsense.ipsec

    ##############################
    # XML processing
    #
    def _create_target(self):
        """ create the XML target_elt """
        ipsec_elt = self.pfsense.new_element('phase1')
        self.obj['ikeid'] = str(self._find_free_ikeid())
        return ipsec_elt

    def _find_free_ikeid(self):
        """ return first unused ikeid """
        ikeid = 1
        while True:
            found = False
            for ipsec_elt in self.root_elt:
                ikeid_elt = ipsec_elt.find('ikeid')
                if ikeid_elt is not None and ikeid_elt.text == str(ikeid):
                    found = True
                    break

            if not found:
                return ikeid
            ikeid = ikeid + 1

    def _find_target(self):
        """ find the XML target_elt """
        if self.params.get('ikeid') is not None:
            return self.pfsense.find_ipsec_phase1(self.params['ikeid'], 'ikeid')
        return self.pfsense.find_ipsec_phase1(self.obj['descr'])

    def _get_params_to_remove(self):
        """ returns the list of params to remove if they are not set """
        params = ['disabled', 'rekey_enable', 'reauth_enable', 'splitconn', 'nattport', 'gw_duplicates']
        if self.params.get('disable_rekey'):
            params.append('margintime')

        if not self.params['enable_dpd']:
            params.append('dpd_delay')
            params.append('dpd_maxfail')

        return params

    def _pre_remove_target_elt(self):
        """ processing before removing elt """
        self._remove_phases2()

    def _remove_phases2(self):
        """ remove phase2 elts from xml """
        ikeid_elt = self.target_elt.find('ikeid')
        if ikeid_elt is None:
            return
        ikeid = ikeid_elt.text
        phase2_elts = self.root_elt.findall('phase2')
        for phase2_elt in phase2_elts:
            ikeid_elt = phase2_elt.find('ikeid')
            if ikeid_elt is None:
                continue
            if ikeid == ikeid_elt.text:
                self.root_elt.remove(phase2_elt)

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return an ipsec dict from module params """

        params = self.params
        self.apply = params['apply']

        ipsec = dict()
        ipsec['descr'] = params['descr']

        if params['state'] == 'present':
            # Valid interfaces are physical, virtual IPs, and gateway groups
            # TODO - handle gateway groups
            if params['interface'].lower().startswith('vip:'):
                ipsec['interface'] = self.pfsense.get_virtual_ip_interface(params['interface'][4:])
            else:
                ipsec['interface'] = self.pfsense.parse_interface(params['interface'], with_virtual=False)
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

            if self.pfsense.is_at_least_2_5_0():
                self._get_ansible_param_bool(ipsec, 'gw_duplicates', value='')
                self._get_ansible_param(ipsec, 'nattport')
                self._get_ansible_param(ipsec, 'rekey_time', force=True)
                self._get_ansible_param(ipsec, 'reauth_time', force=True)
                self._get_ansible_param(ipsec, 'rand_time', force=True)
            else:
                self._get_ansible_param(ipsec, 'margintime', force=True)

        return ipsec

    def _deprecated_params(self):
        return [
            ['disable_rekey', self.pfsense.is_at_least_2_5_0],
            ['margintime', self.pfsense.is_at_least_2_5_0],
        ]

    def _onward_params(self):
        return [
            ['gw_duplicates', self.pfsense.is_at_least_2_5_0],
            ['nattport', self.pfsense.is_at_least_2_5_0],
            ['rekey_time', self.pfsense.is_at_least_2_5_0],
            ['reauth_time', self.pfsense.is_at_least_2_5_0],
            ['rand_time', self.pfsense.is_at_least_2_5_0],
        ]

    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params
        if params['state'] == 'absent':
            return

        if self.pfsense.is_at_least_2_5_0():
            if params.get('lifetime') is not None:
                if (params.get('rekey_time') is not None and params.get('rekey_time') >= params.get('lifetime') or
                        params.get('reauth_time') is not None and params.get('reauth_time') >= params.get('lifetime')):
                    self.module.fail_json(msg='Life Time must be larger than Rekey Time and Reauth Time.')
        else:
            if params.get('disable_rekey') is None:
                params['disable_rekey'] = False

        for ipsec_elt in self.root_elt:
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

            # Valid interfaces are physical, virtual IPs, and gateway groups
            # TODO - handle gateway groups
            if params['interface'].lower().startswith('vip:'):
                if self.pfsense.get_virtual_ip_interface(params['interface'][4:]) is None:
                    self.module.fail_json(msg='Cannot find virtual IP "{0}".'.format(params['interface'][4:]))

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

    ##############################
    # run
    #
    def _update(self):
        """ make the target pfsense reload """
        return self.pfsense.apply_ipsec_changes()

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return "'" + self.obj['descr'] + "'"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            values += self.format_cli_field(self.params, 'disabled', fvalue=self.fvalue_bool)
            values += self.format_cli_field(self.obj, 'iketype')
            if self.obj['iketype'] != 'ikev2':
                values += self.format_cli_field(self.obj, 'mode')

            values += self.format_cli_field(self.obj, 'protocol')
            values += self.format_cli_field(self.params, 'interface')
            values += self.format_cli_field(self.obj, 'remote-gateway', fname='remote_gateway')
            values += self.format_cli_field(self.obj, 'nattport')
            values += self.format_cli_field(self.obj, 'authentication_method')
            if self.obj['authentication_method'] == 'rsasig':
                values += self.format_cli_field(self.params, 'certificate')
                values += self.format_cli_field(self.params, 'certificate_authority')
            else:
                values += self.format_cli_field(self.obj, 'pre-shared-key', fname='preshared_key')

            id_types = ['address', 'fqdn', 'user_fqdn', 'asn1dn', 'keyid tag', 'dyn_dns']
            values += self.format_cli_field(self.obj, 'myid_type')
            if self.obj['myid_type'] in id_types:
                values += self.format_cli_field(self.obj, 'myid_data')

            values += self.format_cli_field(self.obj, 'peerid_type')
            if self.obj['peerid_type'] in id_types:
                values += self.format_cli_field(self.obj, 'peerid_data')

            values += self.format_cli_field(self.obj, 'lifetime')
            values += self.format_cli_field(self.obj, 'rekey_time')
            values += self.format_cli_field(self.obj, 'reauth_time')
            values += self.format_cli_field(self.obj, 'rand_time')

            if not self.pfsense.is_at_least_2_5_0():
                values += self.format_cli_field(self.params, 'disable_rekey', fvalue=self.fvalue_bool)
                if not self.params['disable_rekey']:
                    values += self.format_cli_field(self.obj, 'margintime')

            if self.obj['iketype'] == 'ikev2':
                values += self.format_cli_field(self.obj, 'reauth_enable', fname='disable_reauth', fvalue=self.fvalue_bool)
                values += self.format_cli_field(self.obj, 'mobike')
                values += self.format_cli_field(self.obj, 'splitconn', fvalue=self.fvalue_bool)

            values += self.format_cli_field(self.obj, 'gw_duplicates', fvalue=self.fvalue_bool)

            values += self.format_cli_field(self.params, 'responderonly', fvalue=self.fvalue_bool)
            values += self.format_cli_field(self.obj, 'nat_traversal')

            values += self.format_cli_field(self.params, 'enable_dpd', fvalue=self.fvalue_bool)
            if self.params['enable_dpd']:
                values += self.format_cli_field(self.obj, 'dpd_delay')
                values += self.format_cli_field(self.obj, 'dpd_maxfail')
        else:
            values += self.format_updated_cli_field(self.obj, before, 'disabled', add_comma=(values), fvalue=self.fvalue_bool)
            values += self.format_updated_cli_field(self.obj, before, 'iketype', add_comma=(values))
            if self.obj['iketype'] != 'ikev2':
                values += self.format_updated_cli_field(self.obj, before, 'mode', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'protocol', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'interface', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'remote-gateway', add_comma=(values), fname='remote_gateway')
            values += self.format_updated_cli_field(self.obj, before, 'nattport', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'authentication_method', add_comma=(values))
            if self.obj['authentication_method'] == 'rsasig':
                values += self.format_updated_cli_field(self.params, before, 'certificate', add_comma=(values))
                values += self.format_updated_cli_field(self.params, before, 'certificate_authority', add_comma=(values))
            else:
                values += self.format_updated_cli_field(self.obj, before, 'pre-shared-key', add_comma=(values), fname='preshared_key')
            values += self.format_updated_cli_field(self.obj, before, 'myid_type', add_comma=(values))
            id_types = ['address', 'fqdn', 'user_fqdn', 'asn1dn', 'keyid tag', 'dyn_dns']
            if self.obj['myid_type'] in id_types:
                values += self.format_updated_cli_field(self.obj, before, 'myid_data', add_comma=(values))

            values += self.format_updated_cli_field(self.obj, before, 'peerid_type', add_comma=(values))
            if self.obj['peerid_type'] in id_types:
                values += self.format_updated_cli_field(self.obj, before, 'peerid_data', add_comma=(values))

            values += self.format_updated_cli_field(self.obj, before, 'lifetime', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'rekey_time', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'reauth_time', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'rand_time', add_comma=(values))

            if not self.pfsense.is_at_least_2_5_0():
                values += self.format_updated_cli_field(self.obj, before, 'disable_rekey', add_comma=(values), fvalue=self.fvalue_bool)
                if not self.params['disable_rekey']:
                    values += self.format_updated_cli_field(self.obj, before, 'margintime', add_comma=(values))

            if self.obj['iketype'] == 'ikev2':
                values += self.format_updated_cli_field(self.obj, before, 'reauth_enable', add_comma=(values), fname='disable_reauth', fvalue=self.fvalue_bool)
                values += self.format_updated_cli_field(self.obj, before, 'mobike', add_comma=(values))
                values += self.format_updated_cli_field(self.obj, before, 'splitconn', add_comma=(values), fvalue=self.fvalue_bool)

            values += self.format_updated_cli_field(self.obj, before, 'gw_duplicates', add_comma=(values), fvalue=self.fvalue_bool)

            values += self.format_updated_cli_field(self.obj, before, 'responderonly', add_comma=(values), fvalue=self.fvalue_bool)
            values += self.format_updated_cli_field(self.obj, before, 'nat_traversal', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'enable_dpd', add_comma=(values), fvalue=self.fvalue_bool)
            if self.params['enable_dpd']:
                values += self.format_updated_cli_field(self.obj, before, 'dpd_delay', add_comma=(values))
                values += self.format_updated_cli_field(self.obj, before, 'dpd_maxfail', add_comma=(values))
        return values

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
