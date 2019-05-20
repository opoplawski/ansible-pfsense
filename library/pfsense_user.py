#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_user
version_added: "2.8"
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
  state:
    description: State in which to leave the user
    default: present
    choices: [ "present", "absent" ]
  descr:
    description: Description of the user
  scope:
    description: Scope of the user ('user' is a normal user)
    default: user
    choices: [ "user", "system" ]
  uid:
    description:
    - UID of the user.
    - Will use next available UID if not specified.
  groupname:
    description:
    - Group of the user.
  password:
    description:
    - bcrypt encrypted password of the user.
  priv:
    description:
    - A list of priveleges to assign.
    - Allowed values include page-all, user-shell-access.
    type: list
  authorizedkeys:
    description:
    - Contents of ~/.ssh/authorized_keys.  Can be base64 encoded.
"""

EXAMPLES = """
- name: Add operator user
  pfsense_user:
    name: operator
    descr: Operator
    scope: user
    groupname: Operators
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
from ansible.module_utils.network.pfsense.pfsense import PFSenseModule

USER_PHP_COMMAND_PREFIX = """
require_once('auth.inc');
init_config_arr(array('system', 'user'));
$a_user = &$config['system']['user'];
$userent = $a_user[{idx}];
"""

# local_user_set_groups($userent, {groups});
USER_PHP_COMMAND_SET = USER_PHP_COMMAND_PREFIX + """
local_user_set($userent);
if (is_dir("/etc/inc/privhooks")) {{
    run_plugins("/etc/inc/privhooks");
}}
"""

USER_PHP_COMMAND_DEL = USER_PHP_COMMAND_PREFIX + """
local_user_del($userent);
"""


class pfSenseUser(object):

    def __init__(self, module):
        self.module = module
        self.pfsense = PFSenseModule(module)
        self.system = self.pfsense.get_element('system')
        self.users = self.system.findall('user')
        self.groups = self.system.findall('group')
        self.diff = {}
        self.change_descr = ''

    def _find_user(self, name):
        found = None
        i = 0
        for user in self.users:
            if user.find('name').text == name:
                found = user
                break
            i += 1
        return (found, i)

    def _find_group(self, name):
        found = None
        i = 0
        for group in self.groups:
            if group.find('name').text == name:
                found = group
                break
            i += 1
        return (found, i)

    def _nextuid(self):
        nextuid_elt = self.system.find('nextuid')
        nextuid = nextuid_elt.text
        nextuid_elt.text = str(int(nextuid) + 1)
        return nextuid

    def _format_diff_priv(self, priv):
        if isinstance(priv, str):
            return [priv]
        else:
            return priv

    def add(self, user):
        changed = False
        stdout = None
        stderr = None
        if re.match(r'\$2b\$', user['password']):
            user['bcrypt-hash'] = user['password']
        else:
            self.module.fail_json(msg='Password (%s) does not appear to be a bcrypt hash' % user['password'])
        del user['password']
        # Allow authorizedkeys to be clear or base64 encoded
        if 'authorizedkeys' in user and 'ssh-' in user['authorizedkeys']:
            user['authorizedkeys'] = base64.b64encode(user['authorizedkeys'])

        if 'groupname' in user:
            group_elt, i = self._find_group(user['groupname'])
            if group_elt is None:
                self.module.fail_json(msg='Group (%s) does not exist' % user['groupname'])

        user_elt, user_idx = self._find_user(user['name'])
        if user_elt is None:
            changed = True
            self.diff['before'] = ''

            if 'uid' not in user:
                user['uid'] = self._nextuid()
            self.diff['after'] = user
            user_elt = self.pfsense.new_element('user')
            self.pfsense.copy_dict_to_element(user, user_elt)
            self.system.insert(i + 1, user_elt)
            self.change_descr = 'ansible pfsense_user added %s' % (user['name'])
        else:
            self.diff['before'] = self.pfsense.element_to_dict(user_elt)
            if 'priv' in self.diff['before']:
                self.diff['before']['priv'] = self._format_diff_priv(self.diff['before']['priv'])
            changed = self.pfsense.copy_dict_to_element(user, user_elt)
            self.diff['after'] = self.pfsense.element_to_dict(user_elt)
            if 'priv' in self.diff['after']:
                self.diff['after']['priv'] = self._format_diff_priv(self.diff['after']['priv'])
            self.change_descr = 'ansible pfsense_user updated "%s"' % (user['name'])

        if changed and not self.module.check_mode:
            self.pfsense.write_config(descr=self.change_descr)
            (dummy, stdout, stderr) = self.pfsense.phpshell(
                USER_PHP_COMMAND_SET.format(idx=user_idx))
        self.module.exit_json(changed=changed, diff=self.diff, stdout=stdout, stderr=stderr)

    def remove(self, user):
        user_elt, user_idx = self._find_user(user['name'])
        changed = False
        stdout = None
        stderr = None
        self.diff['after'] = ''
        if user_elt is not None:
            self.diff['before'] = self.pfsense.element_to_dict(user_elt)
            self.users.remove(user_elt)
            changed = True

        if changed and not self.module.check_mode:
            (dummy, stdout, stderr) = self.pfsense.phpshell(
                USER_PHP_COMMAND_DEL.format(cmd='del', idx=user_idx))
            self.pfsense.write_config(descr='ansible pfsense_user removed "%s"' % (user['name']))
        self.module.exit_json(changed=changed, diff=self.diff, stdout=stdout, stderr=stderr)


def main():
    module = AnsibleModule(
        argument_spec={
            'name': {'required': True, 'type': 'str'},
            'state': {
                'type': 'str',
                'default': 'present',
                'choices': ['present', 'absent']
            },
            'descr': {'type': 'str'},
            'scope': {
                'type': 'str',
                'default': 'user',
                'choices': ['user', 'system']
            },
            'uid': {'type': 'str'},
            'password': {'type': 'str'},
            'groupname': {'type': 'str'},
            'priv': {'type': 'list'},
            'authorizedkeys': {'type': 'str'},
        },
        supports_check_mode=True)

    pfuser = pfSenseUser(module)

    user = dict()
    user['name'] = module.params['name']
    state = module.params['state']
    if state == 'absent':
        pfuser.remove(user)
    elif state == 'present':
        for option in ['authorizedkeys', 'descr', 'scope', 'uid', 'password', 'groupname', 'priv']:
            if module.params[option] is not None:
                user[option] = module.params[option]
        pfuser.add(user)


if __name__ == '__main__':
    main()
