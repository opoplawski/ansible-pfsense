# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Chris Morton, cosmo@cosmo.2y.net
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
import re
from ansible.module_utils.network.pfsense.module_base import PFSenseModuleBase

HAPROXY_FRONTEND_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),
    name=dict(required=True, type='str'),
    status=dict(required=True, type='str'),
    desc=dict(required=True, type='str'),
    type=dict(default='http', choices=['http', 'https']),
    httpclose=dict(default='http-keep-alive', choices=['http-keep-alive']),
    backend_serverpool=dict(required=False, type='str'),
    ssloffloadcert=dict(required=False, type='str'),
    ssloffloadacl_an=dict(required=False, type='str'),
    extaddr=dict(required=True, type='str'),
    extaddr_port=dict(required=True, type='int'),
    extaddr_ssl=dict(required=True, type='str'),
    addhttp_https_redirect=dict(required=False, type='bool')
    
)


class PFSenseHaproxyFrontendModule(PFSenseModuleBase):
    """ module managing pfsense haproxy frontends """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return HAPROXY_FRONTEND_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseHaproxyFrontendModule, self).__init__(module, pfsense)
        self.name = "pfsense_haproxy_frontend"
        self.obj = dict()

        pkgs_elt = self.pfsense.get_element('installedpackages')
        self.haproxy = pkgs_elt.find('haproxy') if pkgs_elt is not None else None
        self.root_elt = self.haproxy.find('ha_backends') if self.haproxy is not None else None
        if self.root_elt is None:
            self.module.fail_json(msg='Unable to find frontends (ha_backends) XML configuration entry. Are you sure haproxy is installed ?')

        self.servers = None

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return a frontend dict from module params """
        params = self.params

        obj = dict()
        obj['name'] = self.params['name']
        if self.params['state'] == 'present':
            self._get_ansible_param(obj, 'desc')
            self._get_ansible_param(obj, 'type')
            self._get_ansible_param(obj, 'status')
            self._get_ansible_param(obj, 'httpclose')
            self._get_ansible_param(obj, 'backend_serverpool')
            
            if 'ssloffloadcert' in params and params['ssloffloadcert'] is not None and params['ssloffloadcert'] != '':
                cert_elt = self.pfsense.find_cert_elt(params['ssloffloadcert'], search_field='type')
                if cert_elt is None:
                    self.module.fail_json(msg='%s is not a valid certificate ' % (params['ssloffloadcert']))
                obj['ssloffloadcert'] = cert_elt.find('refid').text

            self._get_ansible_param(obj, 'ssloffloadacl_an')
            
            aval = dict()
            aval['item'] = dict()
            val = aval['item']
            self._get_ansible_param(val, 'extaddr')
            self._get_ansible_param(val, 'extaddr_port')
            self._get_ansible_param(val, 'extaddr_ssl')
            obj['a_extaddr'] = aval


            #check for redirect
            if 'addhttp_https_redirect' in params and params['addhttp_https_redirect'] is not None and params['addhttp_https_redirect'] != '' and params['addhttp_https_redirect']:
                #add redirect rules
                aval = dict()
                val = dict()
                val['action'] = 'http-request_redirect'
                val['http-request_redirectrule'] = 'scheme https'
                aval['item'] = val
                obj['a_actionitems'] = aval
                

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """
        # check name
        if re.search(r'[^a-zA-Z0-9\.\-_]', self.params['name']) is not None:
            self.module.fail_json(msg="The field 'name' contains invalid characters.")

    ##############################
    # XML processing
    #
    def _create_target(self):
        """ create the XML target_elt """
        server_elt = self.pfsense.new_element('item')
        return server_elt
        
    def _find_target(self):
        """ find the XML target_elt """
        for item_elt in self.root_elt:
            if item_elt.tag != 'item':
                continue
            name_elt = item_elt.find('name')
            if name_elt is not None and name_elt.text == self.obj['name']:
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

    ##############################
    # run
    #
    def _update(self):
        """ make the target pfsense reload haproxy """
        return self.pfsense.phpshell('''require_once("haproxy/haproxy.inc");
$result = haproxy_check_and_run($savemsg, true); if ($result) unlink_if_exists($d_haproxyconfdirty_path);''')

    ##############################
    # Logging
    #
    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            values += self.format_cli_field(self.params, 'desc')
            values += self.format_cli_field(self.params, 'type')
            values += self.format_cli_field(self.params, 'httpclose')
            values += self.format_cli_field(self.params, 'backend_serverpool')
            values += self.format_cli_field(self.params, 'ssloffloadcert') 
            values += self.format_cli_field(self.params, 'ssloffloadacl_an')
        else:
            values += self.format_updated_cli_field(self.obj, before, 'desc', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'type', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'httpclose', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'backend_serverpool', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'ssloffloadcert', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'ssloffloadacl_an', add_comma=(values))
        return values

    def _get_obj_name(self):
        """ return obj's name """
        return "'{0}'".format(self.obj['name'])
