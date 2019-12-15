# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
import re
from ansible.module_utils.network.pfsense.pfsense import PFSenseModule, PFSenseModuleBase

HAPROXY_BACKEND_SERVER_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),
    backend=dict(required=True, type='str'),
    name=dict(required=True, type='str'),
    mode=dict(default='active', choices=['active', 'backup', 'disabled', 'inactive']),
    forwardto=dict(required=False, type='str'),
    address=dict(required=False, type='str'),
    port=dict(required=False, type='int'),
    ssl=dict(required=False, type='bool'),
    checkssl=dict(required=False, type='bool'),
    weight=dict(required=False, type='int'),
    sslserververify=dict(required=False, type='bool'),
    verifyhost=dict(required=False, type='str'),
    ca=dict(required=False, type='str'),
    crl=dict(required=False, type='str'),
    clientcert=dict(required=False, type='str'),
    cookie=dict(required=False, type='str'),
    maxconn=dict(required=False, type='int'),
    advanced=dict(required=False, type='str'),
    istemplate=dict(required=False, type='str'),
)

HAPROXY_BACKEND_SERVER_MUTUALLY_EXCLUSIVE = [
    ['forwardto', 'address'],
    ['forwardto', 'port'],
]


class PFSenseHaproxyBackendServerModule(PFSenseModuleBase):
    """ module managing pfsense haproxy backend servers """

    def __init__(self, module, pfsense=None):
        if pfsense is None:
            pfsense = PFSenseModule(module)
        self.module = module
        self.pfsense = pfsense
        self.params = None

        pkgs_elt = self.pfsense.get_element('installedpackages')
        self.haproxy = pkgs_elt.find('haproxy') if pkgs_elt is not None else None
        self.backends = self.haproxy.find('ha_pools') if self.haproxy is not None else None
        if self.backends is None:
            self.module.fail_json(msg='Unable to find backends XML configuration entry. Are you sure haproxy is installed ?')

        self.backend = None
        self.servers = None

        self.change_descr = ''

        self.result = {}
        self.result['changed'] = False
        self.result['commands'] = []

    def _log_create(self, server):
        """ generate pseudo-CLI command to create a server """
        log = "create haproxy_backend_server '{0}' on '{1}'".format(server['name'], self.params['backend'])
        log += self.format_cli_field(self.params, 'mode', fname='status')
        log += self.format_cli_field(self.params, 'forwardto')
        log += self.format_cli_field(self.params, 'address')
        log += self.format_cli_field(self.params, 'port')
        log += self.format_cli_field(self.params, 'ssl', fvalue=self.fvalue_bool)
        log += self.format_cli_field(self.params, 'checkssl', fvalue=self.fvalue_bool)
        log += self.format_cli_field(self.params, 'weight')
        log += self.format_cli_field(self.params, 'sslserververify', fvalue=self.fvalue_bool)
        log += self.format_cli_field(self.params, 'ca')
        log += self.format_cli_field(self.params, 'crl')
        log += self.format_cli_field(self.params, 'clientcert')
        log += self.format_cli_field(self.params, 'cookie')
        log += self.format_cli_field(self.params, 'maxconn')
        log += self.format_cli_field(self.params, 'advanced')
        log += self.format_cli_field(self.params, 'istemplate')
        self.result['commands'].append(log)

    def _log_delete(self, server):
        """ generate pseudo-CLI command to delete a server """
        log = "delete haproxy_backend_server '{0}' on '{1}'".format(server['name'], self.params['backend'])
        self.result['commands'].append(log)

    def _get_ref_names(self, before):
        """ get cert and ca names """
        if 'ssl-server-ca' in before and before['ssl-server-ca'] is not None and before['ssl-server-ca'] != '':
            elt = self.pfsense.find_ca_elt(before['ssl-server-ca'], 'refid')
            if elt is not None:
                before['ca'] = elt.find('descr').text
        if 'ca' not in before:
            before['ca'] = None

        if 'ssl-server-crl' in before and before['ssl-server-crl'] is not None and before['ssl-server-crl'] != '':
            elt = self.pfsense.find_crl_elt(before['ssl-server-crl'], 'refid')
            if elt is not None:
                before['crl'] = elt.find('descr').text
        if 'crl' not in before:
            before['crl'] = None

        if 'ssl-server-clientcert' in before and before['ssl-server-clientcert'] is not None and before['ssl-server-clientcert'] != '':
            elt = self.pfsense.find_cert_elt(before['ssl-server-clientcert'], 'refid')
            if elt is not None:
                before['clientcert'] = elt.find('descr').text
        if 'clientcert' not in before:
            before['clientcert'] = None

    def _log_update(self, server, before):
        """ generate pseudo-CLI command to update a server """
        for param in ['ssl', 'checkssl', 'sslserververify']:
            if param in before and before[param] == '':
                before[param] = None
        self._get_ref_names(before)

        log = "update haproxy_backend_server '{0}' on '{1}'".format(server['name'], self.params['backend'])
        values = ''
        values += self.format_updated_cli_field(server, before, 'status', add_comma=(values), fname='mode')
        values += self.format_updated_cli_field(server, before, 'forwardto', add_comma=(values))
        values += self.format_updated_cli_field(server, before, 'address', add_comma=(values))
        values += self.format_updated_cli_field(server, before, 'port', add_comma=(values))
        values += self.format_updated_cli_field(server, before, 'ssl', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(server, before, 'checkssl', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(server, before, 'weight', add_comma=(values))
        values += self.format_updated_cli_field(server, before, 'sslserververify', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(server, before, 'verifyhost', add_comma=(values))
        values += self.format_updated_cli_field(self.params, before, 'ca', add_comma=(values))
        values += self.format_updated_cli_field(self.params, before, 'crl', add_comma=(values))
        values += self.format_updated_cli_field(self.params, before, 'clientcert', add_comma=(values))
        values += self.format_updated_cli_field(server, before, 'cookie', add_comma=(values))
        values += self.format_updated_cli_field(server, before, 'maxconn', add_comma=(values))
        values += self.format_updated_cli_field(server, before, 'advanced', add_comma=(values))
        values += self.format_updated_cli_field(server, before, 'istemplate', add_comma=(values))
        self.result['commands'].append(log + ' set ' + values)

    def _find_server(self, server):
        """ return the target server_elt if found """
        for item_elt in self.servers:
            if item_elt.tag != 'item':
                continue
            name_elt = item_elt.find('name')
            if name_elt is not None and name_elt.text == server['name']:
                return item_elt
        return None

    def _get_next_id(self):
        """ get next free haproxy id  """
        max_id = 99
        id_elts = self.haproxy.findall('.//id')
        for id_elt in id_elts:
            if id_elt.text is None:
                continue
            ha_id = int(id_elt.text)
            if ha_id > max_id:
                max_id = ha_id
        return str(max_id + 1)

    def _add(self, server):
        """ add or update server """
        server_elt = self._find_server(server)
        if server_elt is None:
            server_elt = self.pfsense.new_element('item')
            server['id'] = self._get_next_id()
            self.pfsense.copy_dict_to_element(server, server_elt)
            self.servers.append(server_elt)

            changed = True
            self.change_descr = 'ansible pfsense_haproxy_backend_server added {0} on {1}'.format(server['name'], self.params['backend'])
            self._log_create(server)
        else:
            before = self.pfsense.element_to_dict(server_elt)
            changed = self.pfsense.copy_dict_to_element(server, server_elt)
            if self._remove_deleted_server_params(server, server_elt):
                changed = True

            if changed:
                self.change_descr = 'ansible pfsense_haproxy_backend_server updated {0} on {1}'.format(server['name'], self.params['backend'])
                self._log_update(server, before)

        if changed:
            self.result['changed'] = changed

    def _remove_deleted_server_params(self, server, server_elt):
        """ Remove from server a few deleted params """
        changed = False
        params = ['ssl', 'checkssl', 'sslserververify', 'forwardto', 'address', 'port', 'weight', 'istemplate', 'verifyhost']
        params += ['ssl-server-crl', 'ssl-server-ca', 'ssl-server-clientcert', 'cookie', 'maxconn', 'advanced']
        for param in params:
            if self.pfsense.remove_deleted_param_from_elt(server_elt, param, server):
                changed = True

        return changed

    def _remove_server_elt(self, server_elt):
        """ delete server_elt from xml """
        self.servers.remove(server_elt)
        self.result['changed'] = True

    def _remove(self, server):
        """ delete server """
        server_elt = self._find_server(server)
        if server_elt is not None:

            self._log_delete(server)
            self._remove_server_elt(server_elt)
            self.change_descr = 'ansible pfsense_haproxy_backend_server removed {0} on {1}'.format(server['name'], self.params['backend'])

    def _find_backend(self, name):
        """ return the target backend_elt if found """
        for item_elt in self.backends:
            if item_elt.tag != 'item':
                continue
            name_elt = item_elt.find('name')
            if name_elt is not None and name_elt.text == name:
                return item_elt
        return None

    def _validate_params(self, params):
        """ do some extra checks on input parameters """
        # check name
        if re.search(r'[^a-zA-Z0-9\.\-_]', params['name']) is not None:
            self.module.fail_json(msg="The field 'name' contains invalid characters")

        if len(params['name']) < 2:
            self.module.fail_json(msg="The field 'name' must be at least 2 characters")

        self.backend = self._find_backend(params['backend'])
        if self.backend is None:
            self.module.fail_json(msg="The backend named '{0}' does not exist".format(params['backend']))

        self.servers = self.backend.find('ha_servers')
        if self.servers is None:
            self.servers = self.pfsense.new_element('ha_servers')
            self.backend.append(self.servers)

        if 'forwardto' in params and params['forwardto'] is not None:
            frontend_elt = None
            frontends = self.haproxy.find('ha_backends')
            for item_elt in frontends:
                if item_elt.tag != 'item':
                    continue
                name_elt = item_elt.find('name')
                if name_elt is not None and name_elt.text == params['forwardto']:
                    frontend_elt = item_elt
                    break
            if frontend_elt is None:
                self.module.fail_json(msg="The frontend named '{0}' does not exist".format(params['forwardto']))

    def _params_to_server(self, params):
        """ return a server dict from module params """
        def _get_param(name):
            if params.get(name) is None:
                return
            server[name] = str(params[name])

        self._validate_params(params)

        server = dict()
        server['name'] = params['name']
        if params['state'] == 'present':
            server['status'] = params['mode']

            for param in ['ssl', 'checkssl', 'sslserververify']:
                if params.get(param):
                    server[param] = 'yes'

            _get_param('forwardto')
            _get_param('address')
            _get_param('port')
            _get_param('weight')
            _get_param('verifyhost')

            if 'ca' in params and params['ca'] is not None and params['ca'] != '':
                ca_elt = self.pfsense.find_ca_elt(params['ca'])
                if ca_elt is None:
                    self.module.fail_json(msg='%s is not a valid certificate authority' % (params['ca']))
                server['ssl-server-ca'] = ca_elt.find('refid').text

            if 'crl' in params and params['crl'] is not None and params['crl'] != '':
                crl_elt = self.pfsense.find_crl_elt(params['crl'])
                if crl_elt is None:
                    self.module.fail_json(msg='%s is not a valid certificate revocation list' % (params['crl']))
                server['ssl-server-crl'] = crl_elt.find('refid').text

            if 'clientcert' in params and params['clientcert'] is not None and params['clientcert'] != '':
                cert = self.pfsense.find_cert_elt(params['clientcert'])
                if cert is None:
                    self.module.fail_json(msg='%s is not a valid certificate' % (params['clientcert']))
                server['ssl-server-clientcert'] = cert.find('refid').text

            _get_param('cookie')
            _get_param('maxconn')
            _get_param('advanced')
            _get_param('istemplate')

        return server

    def _update(self):
        """ make the target pfsense reload haproxy """
        return self.pfsense.phpshell('''require_once("haproxy/haproxy.inc");
$result = haproxy_check_and_run($savemsg, true); if ($result) unlink_if_exists($d_haproxyconfdirty_path);''')

    def commit_changes(self):
        """ apply changes and exit module """
        self.result['stdout'] = ''
        self.result['stderr'] = ''
        if self.result['changed'] and not self.module.check_mode:
            self.pfsense.write_config(descr=self.change_descr)
            (dummy, self.result['stdout'], self.result['stderr']) = self._update()

        self.module.exit_json(**self.result)

    def run(self, params):
        """ process input params to add/update/delete a server """
        self.params = params
        server = self._params_to_server(params)

        if params['state'] == 'absent':
            self._remove(server)
        else:
            self._add(server)
