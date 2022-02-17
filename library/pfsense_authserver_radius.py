#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018-2022, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_authserver_radius
version_added: 0.5.0
short_description: Manage pfSense RADIUS authentication servers
description:
  >
    Manage pfSense RADIUS authentication servers
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
  auth_port:
    description: RADIUS authentication port
    default: 1812
    type: int
  acct_port:
    description: RADIUS accounting port
    default: 1813
    type: int
  protocol:
    description: RADIUS protocol
    default: MSCHAPv2
    choices: [ "PAP", "CHAP_MD5", "MSCHAPv1", "MSCHAPv2" ]
    type: str
  secret:
    description: RADIUS secret
    type: str
  timeout:
    description: Server timeout in seconds
    default: 5
    type: int
  nasip_attribute:
    description: IP to use for the "NAS-IP-Address" attribute during RADIUS Acccess-Requests, must be an interface name
    default: lan
    type: str
"""

EXAMPLES = """
- name: Add adservers authentication server
  pfsense_authserver_radius:
    name: RADIUS
    host: radius.example.com
    secret: password
    nasip_attribute: lan
    state: present

- name: Remove RADIUS authentication server
  pfsense_authserver_radius:
    name: RADIUS
    state: absent
"""

RETURN = """

"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.pfsense.module_base import PFSenseModuleBase


AUTHSERVER_RADIUS_SPEC = {
    'name': {'required': True, 'type': 'str'},
    'state': {
        'default': 'present',
        'choices': ['present', 'absent'],
    },
    'host': {'type': 'str'},
    'auth_port': {'default': '1812', 'type': 'int'},
    'acct_port': {'default': '1813', 'type': 'int'},
    'protocol': {
        'default': 'MSCHAPv2',
        'choices': ['PAP', 'CHAP_MD5', 'MSCHAPv1', 'MSCHAPv2'],
    },
    'secret': {'type': 'str'},
    'timeout': {'default': '5', 'type': 'int'},
    'nasip_attribute': {'default': 'lan', 'type': 'str'},
}


class PFSenseAuthserverRADIUSModule(PFSenseModuleBase):
    """ module managing pfsense RADIUS authentication """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return AUTHSERVER_RADIUS_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseAuthserverRADIUSModule, self).__init__(module, pfsense)
        self.name = "pfsense_authserver_radius"
        self.root_elt = self.pfsense.get_element('system')
        self.authservers = self.root_elt.findall('authserver')

    ##############################
    # params processing
    #
    def _validate_params(self):
        """ do some extra checks on input parameters """

        if int(self.params['timeout']) < 1:
            self.module.fail_json(msg='timeout {0} must be greater than 1'.format(self.params['timeout']))

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()
        self.obj = obj

        obj['name'] = params['name']
        if params['state'] == 'present':
            obj['type'] = 'radius'
            self._get_ansible_param(obj, 'host')
            self._get_ansible_param(obj, 'auth_port', fname='radius_auth_port')
            self._get_ansible_param(obj, 'acct_port', fname='radius_acct_port')
            self._get_ansible_param(obj, 'protocol', fname='radius_protocol')
            self._get_ansible_param(obj, 'secret', fname='radius_secret')
            self._get_ansible_param(obj, 'timeout', fname='radius_timeout')
            self._get_ansible_param(obj, 'nasip_attribute', fname='radius_nasip_attribute')

        return obj

    ##############################
    # XML processing
    #
    def _find_target(self):
        result = self.root_elt.findall("authserver[name='{0}'][type='radius']".format(self.obj['name']))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple radius authentication servers for name {0}.'.format(self.obj['name']))
        else:
            return None

    def _find_this_index(self):
        return self.authservers.index(self.target_elt)

    def _create_target(self):
        """ create the XML target_elt """
        return self.pfsense.new_element('authserver')

    def _copy_and_add_target(self):
        """ populate the XML target_elt """
        obj = self.obj

        obj['refid'] = self.pfsense.uniqid()
        self.pfsense.copy_dict_to_element(obj, self.target_elt)
        self.diff['after'] = obj
        if len(self.authservers) > 0:
            self.root_elt.insert(list(self.root_elt).index(self.authservers[len(self.authservers) - 1]), self.target_elt)
        else:
            self.root_elt.append(self.target_elt)

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
        return "'{0}'".format(self.obj['name'])

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        return values


def main():
    module = AnsibleModule(
        argument_spec=AUTHSERVER_RADIUS_SPEC,
        required_if=[
            ["state", "present", ["host", "secret"]],
        ],
        supports_check_mode=True)

    pfmodule = PFSenseAuthserverRADIUSModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
