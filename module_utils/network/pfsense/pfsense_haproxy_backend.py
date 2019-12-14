# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
import re
from ansible.module_utils.network.pfsense.pfsense import PFSenseModule, PFSenseModuleBase

HAPROXY_BACKEND_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),
    name=dict(required=True, type='str'),
    balance=dict(default='none', choices=['none', 'roundrobin', 'static-rr', 'leastconn', 'source', 'uri']),
    balance_urilen=dict(required=False, type='int'),
    balance_uridepth=dict(required=False, type='int'),
    balance_uriwhole=dict(required=False, type='bool'),
    connection_timeout=dict(required=False, type='int'),
    server_timeout=dict(required=False, type='int'),
    check_type=dict(default='none', choices=['none', 'Basic', 'HTTP', 'Agent', 'LDAP', 'MySQL', 'PostgreSQL', 'Redis', 'SMTP', 'ESMTP', 'SSL']),
    check_frequency=dict(required=False, type='int'),
    retries=dict(required=False, type='int'),
    log_checks=dict(required=False, type='bool'),
    httpcheck_method=dict(required=False, choices=['OPTIONS', 'HEAD', 'GET', 'POST', 'PUT', 'DELETE', 'TRACE']),
    monitor_uri=dict(required=False, type='str'),
    monitor_httpversion=dict(required=False, type='str'),
    monitor_username=dict(required=False, type='str'),
    monitor_domain=dict(required=False, type='str'),
)


class PFSenseHaproxyBackendModule(PFSenseModuleBase):
    """ module managing pfsense haproxy backends """

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

        self.change_descr = ''

        self.result = {}
        self.result['changed'] = False
        self.result['commands'] = []

    def _log_create(self, backend):
        """ generate pseudo-CLI command to create a backend """
        log = "create haproxy_backend '{0}'".format(backend['name'])
        log += self.format_cli_field(self.params, 'balance')
        log += self.format_cli_field(self.params, 'balance_urilen')
        log += self.format_cli_field(self.params, 'balance_uridepth')
        log += self.format_cli_field(self.params, 'balance_uriwhole', fvalue=self.fvalue_bool)
        log += self.format_cli_field(self.params, 'connection_timeout')
        log += self.format_cli_field(self.params, 'server_timeout')
        log += self.format_cli_field(self.params, 'check_type')
        log += self.format_cli_field(self.params, 'check_frequency')
        log += self.format_cli_field(self.params, 'retries')
        log += self.format_cli_field(self.params, 'log_checks', fvalue=self.fvalue_bool)
        log += self.format_cli_field(self.params, 'httpcheck_method')
        log += self.format_cli_field(self.params, 'monitor_uri')
        log += self.format_cli_field(self.params, 'monitor_httpversion')
        log += self.format_cli_field(self.params, 'monitor_username')
        log += self.format_cli_field(self.params, 'monitor_domain')
        self.result['commands'].append(log)

    def _log_delete(self, backend):
        """ generate pseudo-CLI command to delete a backend """
        log = "delete haproxy_backend '{0}'".format(backend['name'])
        self.result['commands'].append(log)

    def _log_update(self, backend, before):
        """ generate pseudo-CLI command to update a backend """
        if before['balance'] == '':
            before['balance'] = None
        if before['log-health-checks'] == '':
            before['log-health-checks'] = None
        if before['balance_uriwhole'] == '':
            before['balance_uriwhole'] = None

        log = "update haproxy_backend '{0}'".format(backend['name'])
        values = ''
        values += self.format_updated_cli_field(backend, before, 'balance', add_comma=(values))
        values += self.format_updated_cli_field(backend, before, 'balance_urilen', add_comma=(values))
        values += self.format_updated_cli_field(backend, before, 'balance_uridepth', add_comma=(values))
        values += self.format_updated_cli_field(backend, before, 'balance_uriwhole', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(backend, before, 'connection_timeout', add_comma=(values))
        values += self.format_updated_cli_field(backend, before, 'server_timeout', add_comma=(values))
        values += self.format_updated_cli_field(backend, before, 'check_type', add_comma=(values))
        values += self.format_updated_cli_field(backend, before, 'checkinter', add_comma=(values), fname='check_frequency')
        values += self.format_updated_cli_field(backend, before, 'retries', add_comma=(values))
        values += self.format_updated_cli_field(backend, before, 'log-health-checks', add_comma=(values), fname='log_checks', fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(backend, before, 'httpcheck_method', add_comma=(values))
        values += self.format_updated_cli_field(backend, before, 'monitor_uri', add_comma=(values))
        values += self.format_updated_cli_field(backend, before, 'monitor_httpversion', add_comma=(values))
        values += self.format_updated_cli_field(backend, before, 'monitor_username', add_comma=(values))
        values += self.format_updated_cli_field(backend, before, 'monitor_domain', add_comma=(values))
        self.result['commands'].append(log + ' set ' + values)

    def _find_backend(self, backend):
        """ return the target backend_elt if found """
        for item_elt in self.backends:
            if item_elt.tag != 'item':
                continue
            name_elt = item_elt.find('name')
            if name_elt is not None and name_elt.text == backend['name']:
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

    def _add(self, backend):
        """ add or update backend """
        backend_elt = self._find_backend(backend)
        if backend_elt is None:
            backend_elt = self.pfsense.new_element('item')
            backend['id'] = self._get_next_id()
            self.pfsense.copy_dict_to_element(backend, backend_elt)
            self.backends.append(backend_elt)

            changed = True
            self.change_descr = 'ansible pfsense_haproxy_backend added {0}'.format(backend['name'])
            self._log_create(backend)
        else:
            before = self.pfsense.element_to_dict(backend_elt)
            changed = self.pfsense.copy_dict_to_element(backend, backend_elt)

            if changed:
                self.change_descr = 'ansible pfsense_haproxy_backend updated {0}'.format(backend['name'])
                self._log_update(backend, before)

        if changed:
            self.result['changed'] = changed

    def _remove_backend_elt(self, backend_elt):
        """ delete backend_elt from xml """
        self.backends.remove(backend_elt)
        self.result['changed'] = True

    def _remove(self, backend):
        """ delete backend """
        backend_elt = self._find_backend(backend)
        if backend_elt is not None:

            self._log_delete(backend)
            self._remove_backend_elt(backend_elt)
            self.change_descr = 'ansible pfsense_haproxy_backend removed {0}'.format(backend['name'])

    def _validate_params(self, params):
        """ do some extra checks on input parameters """
        # check name
        if re.search(r'[^a-zA-Z0-9\.\-_]', params['name']) is not None:
            self.module.fail_json(msg="The field 'name' contains invalid characters.")

    def _params_to_backend(self, params):
        """ return a backend dict from module params """
        def _get_param(name):
            if params.get(name) is None:
                return ''
            return str(params[name])

        self._validate_params(params)

        backend = dict()
        backend['name'] = params['name']
        if params['state'] == 'present':
            backend['balance'] = params['balance']
            if backend['balance'] == 'none':
                backend['balance'] = None
            backend['balance_urilen'] = _get_param('balance_urilen')
            backend['balance_uridepth'] = _get_param('balance_uridepth')
            backend['connection_timeout'] = _get_param('connection_timeout')
            backend['server_timeout'] = _get_param('server_timeout')
            backend['check_type'] = _get_param('check_type')
            backend['checkinter'] = _get_param('check_frequency')
            backend['retries'] = _get_param('retries')
            backend['log-health-checks'] = 'yes' if params.get('log_checks') else None
            backend['balance_uriwhole'] = 'yes' if params.get('balance_uriwhole') else None
            backend['httpcheck_method'] = _get_param('httpcheck_method')
            backend['monitor_uri'] = _get_param('monitor_uri')
            backend['monitor_httpversion'] = _get_param('monitor_httpversion')
            backend['monitor_username'] = _get_param('monitor_username')
            backend['monitor_domain'] = _get_param('monitor_domain')

        return backend

    def _update(self):
        """ make the target pfsense reload separators """
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
        """ process input params to add/update/delete a backend """
        self.params = params
        backend = self._params_to_backend(params)

        if params['state'] == 'absent':
            self._remove(backend)
        else:
            self._add(backend)
