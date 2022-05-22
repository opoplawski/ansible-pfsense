# -*- coding: utf-8 -*-

# Copyright: (c) 2020-2022, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2020, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase


OPENVPN_OVERRIDE_ARGUMENT_SPEC = dict(
    name=dict(required=True, type='str'),
    state=dict(default='present', choices=['present', 'absent']),
    server_list=dict(default=None, type='list', elements='str'),
    disable=dict(default=False, required=False, type='bool'),
    descr=dict(default=None, required=False, type='str'),
    block=dict(default=False, required=False, type='bool'),
    tunnel_network=dict(default=None, required=False, type='str'),
    tunnel_networkv6=dict(default=None, required=False, type='str'),
    local_network=dict(default=None, required=False, type='str'),
    local_networkv6=dict(default=None, required=False, type='str'),
    remote_network=dict(default=None, required=False, type='str'),
    remote_networkv6=dict(default=None, required=False, type='str'),
    gwredir=dict(default=False, required=False, type='bool'),
    push_reset=dict(default=False, required=False, type='bool'),
    netbios_enable=dict(default=False, required=False, type='bool'),
    netbios_ntype=dict(required=False, choices=['none', 'b-node', 'p-node', 'm-node', 'h-node']),
    netbios_scope=dict(required=False, type='str'),
    wins_server_enable=dict(default=False, required=False, type='bool'),
    custom_options=dict(default=None, required=False, type='str'),
)

OPENVPN_OVERRIDE_REQUIRED_IF = [
]

OPENVPN_OVERRIDE_PHP_COMMAND_PREFIX = """
require_once('openvpn.inc');
init_config_arr(array('openvpn', 'openvpn-csc'));
$a_csc = &$config['openvpn']['openvpn-csc'];
$csc = $a_csc[{idx}];
"""

OPENVPN_OVERRIDE_PHP_COMMAND_SET = OPENVPN_OVERRIDE_PHP_COMMAND_PREFIX + """
openvpn_resync_csc($csc);
"""

OPENVPN_OVERRIDE_PHP_COMMAND_DEL = OPENVPN_OVERRIDE_PHP_COMMAND_PREFIX + """
openvpn_delete_csc($a_csc[{idx}]);
unset($a_csc[{idx}]);
"""


class PFSenseOpenVPNOverrideModule(PFSenseModuleBase):
    """ module managing pfSense OpenVPN Client Specific Overrides """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return OPENVPN_OVERRIDE_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseOpenVPNOverrideModule, self).__init__(module, pfsense)
        self.name = "pfsense_openvpn_override"
        self.root_elt = self.pfsense.get_element('openvpn')
        self.openvpn_csc_elt = self.root_elt.findall('openvpn-csc')
        self.obj = dict()

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return dict from module params """
        obj = dict()
        obj['common_name'] = self.params['name']
        if self.params['state'] == 'present':
            # Find the ids for server names
            server_list = list()
            if self.params['server_list'] is not None:
                for server in self.params['server_list']:
                    vpnid = ''
                    if isinstance(server, int) or (isinstance(server, str) and server.isdigit()):
                        openvpn_server_elt = self.pfsense.find_elt('openvpn-server', str(server), 'vpnid', root_elt=self.root_elt)
                    else:
                        openvpn_server_elt = self.pfsense.find_elt('openvpn-server', server, 'description', root_elt=self.root_elt)
                    if openvpn_server_elt is None:
                        self.module.fail_json(msg="Could not find openvpn server '%s'" % (server))
                    vpnid = openvpn_server_elt.find('vpnid').text
                    server_list.append(vpnid)
            obj['server_list'] = ','.join(server_list)
            self.result['vpnids'] = server_list

            obj['custom_options'] = self.params['custom_options']
            obj['description'] = self.params['descr']
            self._get_ansible_param_bool(obj, 'disable')
            self._get_ansible_param_bool(obj, 'block', force=True, value='yes')
            self._get_ansible_param_bool(obj, 'gwredir', force=True, value='yes')
            self._get_ansible_param_bool(obj, 'push_reset', force=True, value='yes')
            obj['tunnel_network'] = self.params['tunnel_network']
            obj['tunnel_networkv6'] = self.params['tunnel_networkv6']
            obj['local_network'] = self.params['local_network']
            obj['local_networkv6'] = self.params['local_networkv6']
            obj['remote_network'] = self.params['remote_network']
            obj['remote_networkv6'] = self.params['remote_networkv6']
            self._get_ansible_param_bool(obj, 'netbios_enable')
            if self.params['netbios_enable']:
                obj['netbios_ntype'] = self.params['netbios_ntype']
                obj['netbios_scope'] = str(self.params['netbios_scope'])
                self._get_ansible_param(obj, 'netbios_scope')
            self._get_ansible_param_bool(obj, 'wins_server_enable')

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        # check name
        self.pfsense.validate_string(params['name'], 'openvpn_override')

        if params.get('tunnel_network') and not self.pfsense.is_ipv4_network(params['tunnel_network']):
            self.module.fail_json(msg='A valid IPv4 network must be specified for tunnel_network.')
        if params.get('tunnel_network6') and not self.pfsense.is_ipv6_network(params['tunnel_networkv6']):
            self.module.fail_json(msg='A valid IPv6 network must be specified for tunnel_network6.')
        if params.get('local_network') and not self.pfsense.is_ipv4_network(params['local_network']):
            self.module.fail_json(msg='A valid IPv4 network must be specified for local_network.')
        if params.get('local_network6') and not self.pfsense.is_ipv6_network(params['local_networkv6']):
            self.module.fail_json(msg='A valid IPv6 network must be specified for local_network6.')
        if params.get('remote_network') and not self.pfsense.is_ipv4_network(params['remote_network']):
            self.module.fail_json(msg='A valid IPv4 network must be specified for remote_network.')
        if params.get('remote_network6') and not self.pfsense.is_ipv6_network(params['remote_networkv6']):
            self.module.fail_json(msg='A valid IPv6 network must be specified for remote_network6.')

    ##############################
    # XML processing
    #
    def _find_openvpn_csc(self, value, field='common_name'):
        """ return openvpn-csc element """
        i = 0
        for csc_elt in self.openvpn_csc_elt:
            field_elt = csc_elt.find(field)
            if field_elt is not None and field_elt.text == value:
                return (csc_elt, i)
            i += 1
        return (None, -1)

    def _find_last_openvpn_idx(self):
        found = False
        i = 0
        for elt in self.openvpn_csc_elt:
            i += 1
        return i

    def _copy_and_update_target(self):
        """ update the XML target_elt """
        before = self.pfsense.element_to_dict(self.target_elt)
        changed = self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        if self._remove_deleted_params():
            changed = True

        self.diff['before'] = before
        if changed:
            self.diff['after'] = self.pfsense.element_to_dict(self.target_elt)
            self.result['changed'] = True
        else:
            self.diff['after'] = self.obj

        return (before, changed)

    def _create_target(self):
        """ create the XML target_elt """
        target_elt = self.pfsense.new_element('openvpn-csc')
        self.diff['before'] = ''
        self.diff['after'] = self.obj
        self.result['changed'] = True
        self.idx = self._find_last_openvpn_idx()
        return target_elt

    def _find_target(self):
        """ find the XML target_elt """
        (target_elt, self.idx) = self._find_openvpn_csc(self.obj['common_name'])
        return target_elt

    def _remove_target_elt(self):
        """ delete target_elt from xml """
        super(PFSenseOpenVPNOverrideModule, self)._remove_target_elt()
        self.diff['before'] = self.pfsense.element_to_dict(self.target_elt)

    ##############################
    # run
    #
    def _remove(self):
        """ delete obj """
        self.diff['after'] = ''
        self.diff['before'] = ''
        super(PFSenseOpenVPNOverrideModule, self)._remove()
        return self.pfsense.phpshell(OPENVPN_OVERRIDE_PHP_COMMAND_DEL.format(idx=self.idx))

    def _update(self):
        """ make the target pfsense reload """
        return self.pfsense.phpshell(OPENVPN_OVERRIDE_PHP_COMMAND_SET.format(idx=self.idx))

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return "'" + self.obj['common_name'] + "'"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            values += self.format_cli_field(self.obj, 'common_name')
            values += self.format_cli_field(self.obj, 'descr')
        else:
            values += self.format_updated_cli_field(self.obj, before, 'descr', add_comma=(values))
        return values
