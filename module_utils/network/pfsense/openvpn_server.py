# -*- coding: utf-8 -*-

# Copyright: (c) 2020-2022, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2020, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import base64
import re

from ansible.module_utils.network.pfsense.module_base import PFSenseModuleBase

OPENVPN_SERVER_ARGUMENT_SPEC = dict(
    name=dict(required=True, type='str'),
    mode=dict(type='str', choices=['p2p_tls', 'p2p_shared_key', 'server_tls', 'server_tls_user', 'server_user']),
    authmode=dict(default=list(), required=False, type='list', elements='str'),
    state=dict(default='present', choices=['present', 'absent']),
    custom_options=dict(default=None, required=False, type='str'),
    disable=dict(default=False, required=False, type='bool'),
    interface=dict(default='wan', required=False, type='str'),
    local_port=dict(default=1194, required=False, type='int'),
    protocol=dict(default='UDP4', required=False, choices=['UDP4', 'TCP4']),
    dev_mode=dict(default='tun', required=False, choices=['tun', 'tap']),
    tls=dict(required=False, type='str'),
    tls_type=dict(required=False, choices=['auth', 'crypt']),
    ca=dict(required=False, type='str'),
    crl=dict(required=False, type='str'),
    cert=dict(required=False, type='str'),
    cert_depth=dict(default=1, required=False, type='int'),
    strictuserdn=dict(default=False, required=False, type='bool'),
    shared_key=dict(required=False, type='str'),
    dh_length=dict(default=2048, required=False, type='int'),
    ecdh_curve=dict(default='none', required=False, choices=['none', 'prime256v1', 'secp384r1', 'secp521r1']),
    ncp_enable=dict(default=True, required=False, type='bool'),
    # ncp_ciphers=dict(default=list('AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305'), required=False,
    #                  choices=['AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305'], type='list', elements='str'),
    data_ciphers=dict(default=['AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305'], required=False,
                      choices=['AES-256-CBC', 'AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305'], type='list', elements='str'),
    data_ciphers_fallback=dict(default='AES-256-CBC', required=False, choices=['AES-256-CBC', 'AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305']),
    digest=dict(default='SHA256', required=False, choices=['SHA256', 'SHA1']),
    tunnel_network=dict(default='', required=False, type='str'),
    tunnel_networkv6=dict(default='', required=False, type='str'),
    local_network=dict(default='', required=False, type='str'),
    local_networkv6=dict(default='', required=False, type='str'),
    remote_network=dict(default='', required=False, type='str'),
    remote_networkv6=dict(default='', required=False, type='str'),
    gwredir=dict(default=False, required=False, type='bool'),
    gwredir6=dict(default=False, required=False, type='bool'),
    maxclients=dict(default=None, required=False, type='int'),
    allow_compression=dict(default='no', required=False, choices=['no', 'asym', 'yes']),
    compression=dict(default='', required=False, choices=['', 'none', 'stub', 'stub-v2', 'lz4', 'lz4-v2', 'lzo', 'noadapt', 'adaptive', 'yes', 'no']),
    compression_push=dict(default=False, required=False, type='bool'),
    passtos=dict(default=False, required=False, type='bool'),
    client2client=dict(default=False, required=False, type='bool'),
    dynamic_ip=dict(default=False, required=False, type='bool'),
    topology=dict(default='subnet', required=False, choices=['net30', 'subnet']),
    dns_domain=dict(default='', required=False, type='str'),
    dns_server1=dict(default='', required=False, type='str'),
    dns_server2=dict(default='', required=False, type='str'),
    dns_server3=dict(default='', required=False, type='str'),
    dns_server4=dict(default='', required=False, type='str'),
    push_register_dns=dict(default=False, required=False, type='bool'),
    username_as_common_name=dict(default=False, required=False, type='bool'),
    create_gw=dict(default='both', required=False, type='str', choices=['both', 'v4only', 'v6only']),
    verbosity_level=dict(default=1, required=False, type='int'),
)

OPENVPN_SERVER_REQUIRED_IF = [
    ['state', 'present', ['mode']],
    ['mode', 'p2p_tls', ['ca']],
    ['mode', 'server_tls', ['ca']],
    ['mode', 'server_tls_user', ['ca']],
    ['mode', 'p2p_shared_key', ['shared_key']],
]

OPENVPN_SERVER_PHP_COMMAND_PREFIX = """
require_once('openvpn.inc');
init_config_arr(array('openvpn', 'openvpn-server'));
$a = &$config['openvpn']['openvpn-server'];
$ovpn = $a[{idx}];
"""

OPENVPN_SERVER_PHP_COMMAND_SET = OPENVPN_SERVER_PHP_COMMAND_PREFIX + """
openvpn_resync('server',$ovpn);
openvpn_resync_csc_all();
"""

OPENVPN_SERVER_PHP_COMMAND_DEL = OPENVPN_SERVER_PHP_COMMAND_PREFIX + """
openvpn_delete('server',$a[{idx}]);
"""


class PFSenseOpenVPNServerModule(PFSenseModuleBase):
    """ module managing pfSense OpenVPN configuration """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return OPENVPN_SERVER_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseOpenVPNServerModule, self).__init__(module, pfsense)
        self.name = "pfsense_openvpn_server"
        self.root_elt = self.pfsense.get_element('openvpn')
        self.obj = dict()

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return dict from module params """
        obj = dict()
        obj['description'] = self.params['name']
        if self.params['state'] == 'present':
            obj['custom_options'] = self.params['custom_options']
            self._get_ansible_param_bool(obj, 'disable')
            self._get_ansible_param_bool(obj, 'strictuserdn')
            obj['mode'] = self.params['mode']
            obj['dev_mode'] = self.params['dev_mode']
            obj['interface'] = self.params['interface']
            obj['protocol'] = self.params['protocol']
            obj['local_port'] = str(self.params['local_port'])
            self._get_ansible_param(obj, 'maxclients')
            obj['verbosity_level'] = str(self.params['verbosity_level'])
            obj['data_ciphers_fallback'] = self.params['data_ciphers_fallback']
            obj['data_ciphers'] = ",".join(self.params['data_ciphers'])
            self._get_ansible_param_bool(obj, 'ncp_enable', force=True, value='enabled', value_false='disabled')
            self._get_ansible_param_bool(obj, 'gwredir', force=True, value='yes')
            self._get_ansible_param_bool(obj, 'gwredir6', force=True, value='yes')
            self._get_ansible_param_bool(obj, 'compression_push', force=True, value='yes', value_false='')
            self._get_ansible_param_bool(obj, 'passtos', force=True, value='yes', value_false='')
            self._get_ansible_param_bool(obj, 'client2client', force=True, value='yes', value_false='')
            self._get_ansible_param_bool(obj, 'dynamic_ip', force=True, value='yes', value_false='')
            self._get_ansible_param_bool(obj, 'push_register_dns')
            self._get_ansible_param_bool(obj, 'username_as_common_name', force=True, value='enabled', value_false='disabled')
            obj['digest'] = self.params['digest']
            obj['tunnel_network'] = self.params['tunnel_network']
            obj['tunnel_networkv6'] = self.params['tunnel_networkv6']
            obj['local_network'] = self.params['local_network']
            obj['local_networkv6'] = self.params['local_networkv6']
            obj['remote_network'] = self.params['remote_network']
            obj['remote_networkv6'] = self.params['remote_networkv6']
            obj['allow_compression'] = self.params['allow_compression']
            obj['compression'] = self.params['compression']
            obj['topology'] = self.params['topology']
            obj['create_gw'] = self.params['create_gw']

            if 'user' in self.params['mode']:
                obj['authmode'] = ",".join(sorted(self.params['authmode']))

            if 'tls' in self.params['mode']:
                # Find the caref id for the named CA
                if self.params is not None:
                    ca_elt = self.pfsense.find_ca_elt(self.params['ca'])
                    if ca_elt is None:
                        self.module.fail_json(msg='{0} is not a valid certificate authority'.format(self.params['ca']))
                    obj['caref'] = ca_elt.find('refid').text
                # Find the crlref id for the named CRL if any
                if self.params['crl'] is not None:
                    crl_elt = self.pfsense.find_crl_elt(self.params['crl'])
                    if crl_elt is None:
                        self.module.fail_json(msg='{0} is not a valid certificate revocation list'.format(self.params['crl']))
                    obj['crlref'] = crl_elt.find('refid').text
                else:
                    obj['crlref'] = ''
                # Find the certref id for the named certificate if any
                if self.params['cert'] is not None:
                    cert_elt = self.pfsense.find_cert_elt(self.params['cert'])
                    if cert_elt is None:
                        self.module.fail_json(msg='{0} is not a valid certificate'.format(self.params['cert']))
                    obj['certref'] = cert_elt.find('refid').text

                obj['cert_depth'] = str(self.params['cert_depth'])
                obj['dh_length'] = str(self.params['dh_length'])
                obj['ecdh_curve'] = self.params['ecdh_curve']
                self._get_ansible_param(obj, 'tls')

            if 'server_tls' in self.params['mode']:
                obj['tls_type'] = self.params['tls_type']

            if 'server' in self.params['mode']:
                obj['dns_domain'] = self.params['dns_domain']
                obj['dns_server1'] = self.params['dns_server1']
                obj['dns_server2'] = self.params['dns_server2']
                obj['dns_server3'] = self.params['dns_server3']
                obj['dns_server4'] = self.params['dns_server4']

            if self.params['mode'] == 'p2p_shared_key':
                obj['shared_key'] = self.params['shared_key']

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        # check name
        self.pfsense.validate_string(params['name'], 'openvpn')

        # Check auth servers
        if len(params['authmode']) > 0:
            system = self.pfsense.get_element('system')
            for authsrv in params['authmode']:
                if len(system.findall("authserver[name='{0}']".format(authsrv))) == 0:
                    self.module.fail_json(msg='Cannot find authentication server {0}.'.format(authsrv))

        # validate key
        for param in ['shared_key', 'tls']:
            if params[param] is not None:
                key = params[param]
                if re.search('^-----BEGIN OpenVPN Static key V1-----.*-----END OpenVPN Static key V1-----$', key, flags=re.MULTILINE | re.DOTALL):
                    params[param] = base64.b64encode(key.encode()).decode()
                else:
                    key_decoded = base64.b64decode(params[param].encode()).decode()
                    if not re.search('^-----BEGIN OpenVPN Static key V1-----.*-----END OpenVPN Static key V1-----$',
                                     key_decoded, flags=re.MULTILINE | re.DOTALL):
                        self.module.fail_json(msg='Could not recognize {0} key format: {1}'.format(param, key_decoded))

    def _openvpn_port_used(self, protocol, interface, port, vpnid=0):
        for elt in self.root_elt.findall('*[local_port]'):
            if (elt.find('disable')):
                continue

            this_vpnid = int(elt.find('vpnid').text)
            if (this_vpnid == int(vpnid)):
                continue

            this_interface = elt.find('interface').text
            this_protocol = elt.find('protocol').text
            # (TCP|UDP)(4|6) does not conflict unless interface is any
            if ((this_interface != "any" and interface != "any") and (len(protocol) == 4) and
                (len(this_protocol) == 4) and (this_protocol[0:3] == protocol[0:3]) and (this_protocol[3] != protocol[3])):
                continue

            this_port_text = elt.find('local_port').text
            if this_port_text is None:
                continue

            this_port = int(this_port_text)
            if (this_port == port and (this_protocol[0:3] == protocol[0:3]) and
                (this_interface == interface or this_interface == "any" or interface == "any")):
                self.module.fail_json(msg='The specified local_port ({0}) is in use by vpn ID {1}'.format(port, this_vpnid))

    def _nextvpnid(self):
        """ find next available vpnid """
        vpnid = 1
        while len(self.root_elt.findall("*[vpnid='{0}']".format(vpnid))) != 0:
            vpnid += 1
        return str(vpnid)

    ##############################
    # XML processing
    #
    def _find_openvpn_server(self, value, field='description'):
        """ return openvpn-server element """
        i = 0
        for elt in self.root_elt.findall('openvpn-server'):
            field_elt = elt.find(field)
            if field_elt is not None and field_elt.text == value:
                return (elt, i)
            i += 1
        return (None, -1)

    def _find_last_openvpn_idx(self):
        i = 0
        for elt in self.root_elt.findall('openvpn-server'):
            i += 1
        return i

    def _get_params_to_remove(self):
        """ returns the list of params to remove if they are not set """
        params_to_remove = []
        for param in ['disable', 'strictuserdn', 'push_register_dns']:
            if not self.params[param]:
                params_to_remove.append(param)

        return params_to_remove

    def _copy_and_update_target(self):
        """ update the XML target_elt """
        before = self.pfsense.element_to_dict(self.target_elt)
        # Check if local port is used
        portused_vpnid = self._openvpn_port_used(self.params['protocol'], self.params['interface'], self.params['local_port'], before['vpnid'])
        changed = self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        if self._remove_deleted_params():
            changed = True

        self.diff['before'] = before
        if changed:
            self.diff['after'] = self.pfsense.element_to_dict(self.target_elt)
            self.result['changed'] = True
        else:
            self.diff['after'] = self.obj

        self.result['vpnid'] = int(self.diff['before']['vpnid'])
        return (before, changed)

    def _create_target(self):
        """ create the XML target_elt """
        # Check if local port is used
        self._openvpn_port_used(self.params['protocol'], self.params['interface'], self.params['local_port'])
        target_elt = self.pfsense.new_element('openvpn-server')
        self.obj['vpnid'] = self._nextvpnid()
        self.result['vpnid'] = int(self.obj['vpnid'])
        self.diff['before'] = ''
        self.diff['after'] = self.obj
        self.result['changed'] = True
        self.idx = self._find_last_openvpn_idx()
        return target_elt

    def _find_target(self):
        """ find the XML target_elt """
        (target_elt, self.idx) = self._find_openvpn_server(self.obj['description'])
        return target_elt

    ##############################
    # run
    #
    def _pre_remove_target_elt(self):
        """ processing before removing elt """
        self.diff['before'] = self.pfsense.element_to_dict(self.target_elt)
        self.result['vpnid'] = int(self.diff['before']['vpnid'])
        self.command_output = self.pfsense.phpshell(OPENVPN_SERVER_PHP_COMMAND_DEL.format(idx=self.idx))

    def _update(self):
        """ make the target pfsense reload """
        if self.params['state'] == 'present':
            return self.pfsense.phpshell(OPENVPN_SERVER_PHP_COMMAND_SET.format(idx=self.idx))
        else:
            return self.command_output

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return "'" + self.obj['description'] + "'"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            values += self.format_cli_field(self.obj, 'description')
        else:
            values += self.format_updated_cli_field(self.obj, before, 'description', add_comma=(values))
        return values
