#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018-2020, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_authserver_ldap
version_added: 0.1.0
short_description: Manage pfSense LDAP authentication servers
description:
  >
    Manage pfSense LDAP authentication servers
author: Orion Poplawski (@opoplawski)
notes:
options:
  name:
    description: The name of the authentication server
    required: true
    type: str
  state:
    description: State in which to leave the authentication server
    default: 'present'
    choices: [ "present", "absent" ]
    type: str
  host:
    description: The hostname or IP address of the authentication server
    required: false
    type: str
  port:
    description: Port to connect to
    default: 389
    type: str
  transport:
    description: Transport to use
    choices: [ "tcp", "starttls", "ssl" ]
    type: str
  ca:
    description: Certificate Authority
    default: global
    type: str
  protver:
    description: LDAP protocol version
    default: 3
    choices: [ "2", "3" ]
    type: str
  timeout:
    description: Server timeout in seconds
    default: 25
    type: str
  scope:
    description: Search scope
    choices: [ 'one', 'subtree' ]
    type: str
  basedn:
    description: Search base DN
    type: str
  authcn:
    description: Authentication containers added to basedn
    required: false
    type: str
  extended_enabled:
    description: Enable extended query
    default: False
    type: bool
  extended_query:
    description: Extended query
    type: str
  binddn:
    description: Search bind DN
    type: str
  bindpw:
    description: Search bind password
    type: str
  attr_user:
    description: LDAP User naming attribute
    default: cn
    type: str
  attr_group:
    description: LDAP Group naming attribute
    default: cn
    type: str
  attr_member:
    description: LDAP Group member naming attribute
    default: member
    type: str
  attr_groupobj:
    description: LDAP Group objectClass naming attribute
    default: posixGroup
    type: str

"""

EXAMPLES = """
- name: Add adservers authentication server
  pfsense_authserver_ldap:
    name: AD
    host: adserver.example.com
    port: 636
    transport: ssl
    scope: subtree
    authcn: cn=users
    basedn: dc=example,dc=com
    binddn: cn=bind,ou=Service Accounts,dc=example,dc=com
    bindpw: "{{ vaulted_bindpw }}"
    attr_user: samAccountName
    attr_member: memberOf
    attr_groupobj: group
    state: present

- name: Remove LDAP authentication server
  pfsense_authserver_ldap:
    name: AD
    state: absent
"""

RETURN = """

"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase


class PFSenseAuthserverLDAPModule(PFSenseModuleBase):
    """ module managing pfsense LDAP authentication """

    def __init__(self, module, pfsense=None):
        super(PFSenseAuthserverLDAPModule, self).__init__(module, pfsense)
        self.name = "pfsense_authserver_ldap"
        self.root_elt = self.pfsense.get_element('system')
        self.authservers = self.root_elt.findall('authserver')

    ##############################
    # params processing
    #
    def _validate_params(self):
        """ do some extra checks on input parameters """

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()
        self.obj = obj

        obj['name'] = params['name']
        if params['state'] == 'present':
            obj['type'] = 'ldap'
            for option in ['host']:
                if option in params and params[option] is not None:
                    obj[option] = params[option]

            obj['ldap_port'] = params['port']
            if self.pfsense.config_version >= 20.1:
                urltype = dict({'tcp': 'Standard TCP', 'starttls': 'STARTTLS Encrypted', 'ssl': 'SSL/TLS Encrypted'})
            else:
                urltype = dict({'tcp': 'TCP - Standard', 'starttls': 'TCP - STARTTLS', 'ssl': 'SSL - Encrypted'})
            obj['ldap_urltype'] = urltype[params['transport']]
            obj['ldap_protver'] = params['protver']
            obj['ldap_timeout'] = params['timeout']
            obj['ldap_scope'] = params['scope']
            obj['ldap_basedn'] = params['basedn']
            obj['ldap_authcn'] = params['authcn']
            if params['extended_enabled']:
                obj['ldap_extended_enabled'] = 'yes'
            else:
                obj['ldap_extended_enabled'] = ''
            obj['ldap_extended_query'] = params['extended_query']
            if params['binddn']:
                obj['ldap_binddn'] = params['binddn']
            if params['bindpw']:
                obj['ldap_bindpw'] = params['bindpw']
            obj['ldap_attr_user'] = params['attr_user']
            obj['ldap_attr_group'] = params['attr_group']
            obj['ldap_attr_member'] = params['attr_member']
            obj['ldap_attr_groupobj'] = params['attr_groupobj']

            # Find the caref id for the named CA
            obj['ldap_caref'] = self.pfsense.get_caref(params['ca'])
            # CA is required for SSL/TLS
            if self.pfsense.config_version >= 20.1:
                if obj['ldap_caref'] is None and obj['ldap_urltype'] != 'Standard TCP':
                    self.module.fail_json(msg="Could not find CA '%s'" % (params['ca']))
            else:
                if obj['ldap_caref'] is None and obj['ldap_urltype'] != 'TCP - Standard':
                    self.module.fail_json(msg="Could not find CA '%s'" % (params['ca']))

        return obj

    ##############################
    # XML processing
    #
    def _find_target(self):
        result = self.root_elt.findall("authserver[name='{0}'][type='ldap']".format(self.obj['name']))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple ldap authentication servers for name {0}.'.format(self.obj['name']))
        else:
            return None

    def _find_this_index(self):
        return self.authservers.index(self.target_elt)

    def _find_last_index(self):
        return list(self.root_elt).index(self.authservers[len(self.authservers) - 1])

    def _create_target(self):
        """ create the XML target_elt """
        return self.pfsense.new_element('user')

    def _copy_and_add_target(self):
        """ populate the XML target_elt """
        obj = self.obj

        self.target_elt = self.pfsense.new_element('authserver')
        obj['refid'] = self.pfsense.uniqid()
        self.pfsense.copy_dict_to_element(obj, self.target_elt)
        self.diff['after'] = obj
        self.root_elt.insert(self._find_last_index(), self.target_elt)

    def _copy_and_update_target(self):
        """ update the XML target_elt """
        before = self.pfsense.element_to_dict(self.target_elt)
        self.diff['before'] = before
        changed = self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.diff['after'] = self.pfsense.element_to_dict(self.target_elt)
        return (before, changed)

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return self.obj['name']

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        return values


def main():
    module = AnsibleModule(
        argument_spec={
            'name': {'required': True, 'type': 'str'},
            'state': {
                'default': 'present',
                'choices': ['present', 'absent']
            },
            'host': {'type': 'str'},
            'port': {'default': '389', 'type': 'str'},
            'transport': {
                'choices': ['tcp', 'starttls', 'ssl']
            },
            'ca': {'default': 'global', 'type': 'str'},
            'protver': {
                'default': '3',
                'choices': ['2', '3']
            },
            'timeout': {'default': '25', 'type': 'str'},
            'scope': {
                'choices': ['one', 'subtree']
            },
            'basedn': {'required': False, 'type': 'str'},
            'authcn': {'required': False, 'type': 'str'},
            'extended_enabled': {'default': False, 'type': 'bool'},
            'extended_query': {'default': '', 'type': 'str'},
            'binddn': {'required': False, 'type': 'str'},
            'bindpw': {'required': False, 'type': 'str'},
            'attr_user': {'default': 'cn', 'type': 'str'},
            'attr_group': {'default': 'cn', 'type': 'str'},
            'attr_member': {'default': 'member', 'type': 'str'},
            'attr_groupobj': {'default': 'posixGroup', 'type': 'str'},
        },
        required_if=[
            ["state", "present", ["host", "port", "transport", "scope", "authcn"]],
        ],
        supports_check_mode=True)

    pfmodule = PFSenseAuthserverLDAPModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
