#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019-2020, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_user
version_added: 0.1.0
short_description: Manage pfSense users
description:
  >
    Manage pfSense users
author: Orion Poplawski (@opoplawski)
notes:
options:
  name:
    description: The name of the user
    required: true
    type: str
  state:
    description: State in which to leave the user
    default: present
    choices: [ "present", "absent" ]
    type: str
  descr:
    description: Description of the user
    type: str
  scope:
    description: Scope of the user ('user' is a normal user)
    default: user
    choices: [ "user", "system" ]
    type: str
  uid:
    description:
    - UID of the user.
    - Will use next available UID if not specified.
    type: str
  groups:
    description:
    - Groups of the user.
    type: list
    elements: str
  password:
    description:
    - bcrypt encrypted password of the user.
    type: str
  priv:
    description:
    - A list of privileges to assign.
    - Allowed values include page-all, user-shell-access.
    type: list
    elements: str
  authorizedkeys:
    description:
    - Contents of ~/.ssh/authorized_keys.  Can be base64 encoded.
    type: str
"""

EXAMPLES = """
- name: Add operator user
  pfsense_user:
    name: operator
    descr: Operator
    scope: user
    groups: [ 'Operators' ]
    priv: [ 'page-all', 'user-shell-access' ]

- name: Remove user
  pfsense_user:
    name: operator
    state: absent
"""

RETURN = """

"""

import base64
import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

USER_ARGUMENT_SPEC = dict(
    name=dict(required=True, type='str'),
    state=dict(type='str', default='present', choices=['present', 'absent']),
    descr=dict(type='str'),
    scope=dict(type='str', default='user', choices=['user', 'system']),
    uid=dict(type='str'),
    password=dict(type='str', no_log=True),
    groups=dict(type='list', elements='str'),
    priv=dict(type='list', elements='str'),
    authorizedkeys=dict(type='str'),
)

USER_PHP_COMMAND_PREFIX = """
require_once('auth.inc');
init_config_arr(array('system', 'user'));
"""

USER_PHP_COMMAND_SET = USER_PHP_COMMAND_PREFIX + """
$a_user = &$config['system']['user'];
$userent = $a_user[{idx}];
local_user_set($userent);
foreach ({mod_groups} as $groupname) {{
    $group = &$config['system']['group'][$groupindex[$groupname]];
    local_group_set($group);
}}
if (is_dir("/etc/inc/privhooks")) {{
    run_plugins("/etc/inc/privhooks");
}}
"""

# This runs after we remove the group from the config so we can't use $config
USER_PHP_COMMAND_DEL = USER_PHP_COMMAND_PREFIX + """
$userent['name'] = '{name}';
$userent['uid'] = {uid};
foreach ({mod_groups} as $groupname) {{
    $group = &$config['system']['group'][$groupindex[$groupname]];
    local_group_set($group);
}}
local_user_del($userent);
"""


class PFSenseUserModule(PFSenseModuleBase):
    """ module managing pfsense users """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return USER_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseUserModule, self).__init__(module, pfsense)
        self.name = "pfsense_user"
        self.root_elt = self.pfsense.get_element('system')
        self.users = self.root_elt.findall('user')
        self.groups = self.root_elt.findall('group')
        self.mod_groups = []

    ##############################
    # params processing
    #
    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params
        if 'password' in params and params['password'] is not None:
            password = params['password']
            if re.match(r'\$2b\$', str(password)):
                params['bcrypt-hash'] = password
            else:
                self.module.fail_json(msg='Password (%s) does not appear to be a bcrypt hash' % password)
            del params['password']

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()
        self.obj = obj

        obj['name'] = params['name']
        if params['state'] == 'present':
            for option in ['authorizedkeys', 'descr', 'scope', 'uid', 'bcrypt-hash', 'groups', 'priv']:
                if option in params and params[option] is not None:
                    obj[option] = params[option]

            # Allow authorizedkeys to be clear or base64 encoded
            if 'authorizedkeys' in obj and 'ssh-' in obj['authorizedkeys']:
                obj['authorizedkeys'] = base64.b64encode(obj['authorizedkeys'].encode()).decode()

        return obj

    ##############################
    # XML processing
    #
    def _find_target(self):
        result = self.root_elt.findall("user[name='{0}']".format(self.obj['name']))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple users for name {0}.'.format(self.obj['name']))
        else:
            return None

    def _find_group(self, name):
        result = self.root_elt.findall("group[name='{0}']".format(name))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple groups for name {0}.'.format(name))
        else:
            return None

    def _find_groups_for_uid(self, uid):
        groups = []
        for group_elt in self.root_elt.findall("group[member='{0}']".format(uid)):
            groups.append(group_elt.find('name').text)
        return groups

    def _find_this_user_index(self):
        return self.users.index(self.target_elt)

    def _find_last_user_index(self):
        return list(self.root_elt).index(self.users[len(self.users) - 1])

    def _nextuid(self):
        nextuid_elt = self.root_elt.find('nextuid')
        nextuid = nextuid_elt.text
        nextuid_elt.text = str(int(nextuid) + 1)
        return nextuid

    def _format_diff_priv(self, priv):
        if isinstance(priv, str):
            return [priv]
        else:
            return priv

    def _create_target(self):
        """ create the XML target_elt """
        return self.pfsense.new_element('user')

    def _copy_and_add_target(self):
        """ populate the XML target_elt """
        obj = self.obj
        if 'bcrypt-hash' not in obj:
            self.module.fail_json(msg='Password is required when adding a user')
        if 'uid' not in obj:
            obj['uid'] = self._nextuid()

        self.diff['after'] = obj
        self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self._update_groups()
        self.root_elt.insert(self._find_last_user_index(), self.target_elt)
        # Reset users list
        self.users = self.root_elt.findall('user')

    def _copy_and_update_target(self):
        """ update the XML target_elt """
        before = self.pfsense.element_to_dict(self.target_elt)
        self.diff['before'] = before
        if 'priv' in before:
            before['priv'] = self._format_diff_priv(before['priv'])
        changed = self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.diff['after'] = self.pfsense.element_to_dict(self.target_elt)
        if 'priv' in self.diff['after']:
            self.diff['after']['priv'] = self._format_diff_priv(self.diff['after']['priv'])
        if self._update_groups():
            changed = True

        return (before, changed)

    def _update_groups(self):
        user = self.obj
        changed = False

        # Handle group member element - need uid set or retrieved above
        if 'groups' in user:
            uid = self.target_elt.find('uid').text
            # Get current group membership
            self.diff['before']['groups'] = self._find_groups_for_uid(uid)

            # Add user to groups if needed
            for group in self.obj['groups']:
                group_elt = self._find_group(group)
                if group_elt is None:
                    self.module.fail_json(msg='Group (%s) does not exist' % group)
                if len(group_elt.findall("[member='{0}']".format(uid))) == 0:
                    changed = True
                    self.mod_groups.append(group)
                    group_elt.append(self.pfsense.new_element('member', uid))

            # Remove user from groups if needed
            for group in self.diff['before']['groups']:
                if group not in self.obj['groups']:
                    group_elt = self._find_group(group)
                    if group_elt is None:
                        self.module.fail_json(msg='Group (%s) does not exist' % group)
                    for member_elt in group_elt.findall('member'):
                        if member_elt.text == uid:
                            changed = True
                            self.mod_groups.append(group)
                            group_elt.remove(member_elt)
                            break

            # Groups are not stored in the user element
            self.diff['after']['groups'] = user.pop('groups')

        # Decode keys for diff
        for k in self.diff:
            if 'authorizedkeys' in self.diff[k]:
                self.diff[k]['authorizedkeys'] = base64.b64decode(self.diff[k]['authorizedkeys'])

        return changed

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return "'" + self.obj['name'] + "'"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            values += self.format_cli_field(self.params, 'descr')
        else:
            values += self.format_updated_cli_field(self.obj, before, 'descr', add_comma=(values))
        return values

    ##############################
    # run
    #
    def _update(self):
        if self.params['state'] == 'present':
            return self.pfsense.phpshell(USER_PHP_COMMAND_SET.format(idx=self._find_this_user_index(), mod_groups=self.mod_groups))
        else:
            return self.pfsense.phpshell(USER_PHP_COMMAND_DEL.format(name=self.obj['name'], uid=self.obj['uid'], mod_groups=self.mod_groups))

    def _pre_remove_target_elt(self):
        self.diff['after'] = {}
        if self.target_elt is not None:
            self.diff['before'] = self.pfsense.element_to_dict(self.target_elt)
            # Store uid for _update()
            self.obj['uid'] = self.target_elt.find('uid').text

            # Get current group membership
            self.diff['before']['groups'] = self._find_groups_for_uid(self.obj['uid'])

            # Remove user from groups if needed
            for group in self.diff['before']['groups']:
                group_elt = self._find_group(group)
                if group_elt is None:
                    self.module.fail_json(msg='Group (%s) does not exist' % group)
                for member_elt in group_elt.findall('member'):
                    if member_elt.text == self.obj['uid']:
                        self.mod_groups.append(group)
                        group_elt.remove(member_elt)
                        break


def main():
    module = AnsibleModule(
        argument_spec=USER_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseUserModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
