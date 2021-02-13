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
version_added: 0.1.0
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

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

GROUP_PHP_COMMAND_PREFIX = """
require_once('auth.inc');
init_config_arr(array('system', 'group'));
$a_group = &$config['system']['group'];
"""

GROUP_PHP_COMMAND_SET = GROUP_PHP_COMMAND_PREFIX + """
$groupent = $a_group[{idx}];
local_group_set($groupent);
"""

# This runs after we remove the group from the config so we can't use it
GROUP_PHP_COMMAND_DEL = GROUP_PHP_COMMAND_PREFIX + """
$group['name'] = '{name}';
local_group_del($group);
"""


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
            for option in ['scope', 'gid', 'priv']:
                if option in params and params[option] is not None:
                    obj[option] = params[option]

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """

    def _nextgid(self):
        """ return and update netgid counter """
        nextgid_elt = self.root_elt.find('nextgid')
        nextgid = nextgid_elt.text
        nextgid_elt.text = str(int(nextgid) + 1)
        return nextgid

    ##############################
    # XML processing
    #
    def _copy_and_add_target(self):
        """ create the XML target_elt """
        if 'gid' not in self.obj:
            # Search for an open gid
            while True:
                self.obj['gid'] = self._nextgid()
                if self._find_group_by_gid(self.obj['gid']) is None:
                    break
        else:
            if self._find_group_by_gid(self.obj['gid']) is not None:
                self.module.fail_json(msg='A different group already exists with gid {0}.'.format(self.obj['gid']))
        self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.diff['after'] = self.pfsense.element_to_dict(self.target_elt)
        self.root_elt.insert(self._find_last_group_index(), self.target_elt)
        # Reset groups list
        self.groups = self.root_elt.findall('group')

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

    def _find_target(self):
        return self.pfsense.find_elt('group', self.obj['name'], search_field='name', root_elt=self.root_elt)

    def _find_group_by_gid(self, gid):
        return self.pfsense.find_elt('group', gid, search_field='gid', root_elt=self.root_elt)

    def _find_this_group_index(self):
        return self.groups.index(self.target_elt)

    def _find_last_group_index(self):
        return list(self.root_elt).index(self.groups[len(self.groups) - 1])

    ##############################
    # run
    #
    def _update(self):
        if self.params['state'] == 'present':
            return self.pfsense.phpshell(GROUP_PHP_COMMAND_SET.format(idx=self._find_this_group_index()))
        else:
            return self.pfsense.phpshell(GROUP_PHP_COMMAND_DEL.format(name=self.obj['name']))

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
            'gid': {'required': False, 'type': 'str'},
            'priv': {'required': False, 'type': 'list', 'elements': 'str'},
        },
        supports_check_mode=True)

    pfmodule = PFSenseGroupModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
