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
module: pfsense_group
version_added: "2.10"
short_description: Manage pfSense groups
description:
  >
    Manage pfSense groups
author: Orion Poplawski (@opoplawski)
notes:
options:
  name:
    description: The name of the group
    required: true
    type: str
  state:
    description: State in which to leave the group
    required: true
    choices: [ "present", "absent" ]
    type: str
  descr:
    description: Description of the group
    type: str
  scope:
    description: Scope of the group
    default: local
    choices: ["local", "remote", "system" ]
    type: str
  gid:
    description:
    - GID of the group.
    - Will use next available GID if not specified.
    type: str
  priv:
    description:
    - A list of privileges to assign.
    - Allowed values include page-all, user-shell-access.
    type: list
    elements: str
"""

EXAMPLES = """
- name: Add adservers group
  pfsense_group:
    name: Domain Admins
    descr: Remote Admins
    scope: remote
    priv: [ 'page-all', 'user-shell-access' ]
    state: present

- name: Remove group
  pfsense_group:
    name: Domain Admins
    state: absent
"""

RETURN = """

"""

import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.pfsense.module_base import PFSenseModuleBase


class PFSenseGroupModule(PFSenseModuleBase):
    """ module managing pfsense user groups """

    def __init__(self, module, pfsense=None):
        super(PFSenseGroupModule, self).__init__(module, pfsense)
        self.name = "pfsense_group"
        self.root_elt = self.pfsense.get_element('system')
        self.groups = self.root_elt.findall('group')

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()
        self.obj = obj

        obj['name'] = params['name']
        state = params['state']

        if state == 'present':
            obj['description'] = params['descr']
            obj['scope'] = params['scope']
            obj['gid'] = params['gid']
            obj['priv'] = params['priv']

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

    def _find_target(self):
        result = self.root_elt.findall("group[name='{0}']".format(self.obj['name']))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple groups for name {0}.'.format(self.obj['name']))
        else:
            return None

    ##############################
    # XML processing
    #
    def _copy_and_add_target(self):
        """ create the XML target_elt """
        self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.diff['after'] = self.pfsense.element_to_dict(self.target_elt)
        i = 0
        for group in self.groups:
            i = list(self.root_elt).index(group)
            if group.find('name').text == self.obj['name']:
                found = group
                break
        self.root_elt.insert(i + 1, self.target_elt)

    def _copy_and_update_target(self):
        """ update the XML target_elt """
        before = self.pfsense.element_to_dict(self.target_elt)
        self.diff['before'] = before
        changed = self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.diff['after'].update(self.pfsense.element_to_dict(self.target_elt))

        return (before, changed)

    def _create_target(self):
        """ create the XML target_elt """
        return self.pfsense.new_element('group')

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
                'required': True,
                'choices': ['present', 'absent']
            },
            'descr': {'required': False, 'type': 'str'},
            'scope': {
                'default': 'local',
                'choices': ['local', 'remote', 'system']
            },
            'gid': {'default': '', 'type': 'str'},
            'priv': {'required': False, 'type': 'list', 'elements': 'str'},
        },
        supports_check_mode=True)

    pfmodule = PFSenseGroupModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
