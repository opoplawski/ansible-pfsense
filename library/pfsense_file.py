#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_file
version_added: "2.10"
author: Frederic Bor (@f-bor)
short_description: Manage pfSense files
description:
  - Manage pfSense files
notes:
options:
  name:
    description: filename
    required: true
    type: str
  content:
    description: file content, base64 encoded
    required: false
    type: str
  permissions:
    description: file permissions, in 4 octal format
    required: false
    type: str
  state:
    description: State in which to leave the file
    choices: [ "present", "absent" ]
    default: present
    type: str
"""

EXAMPLES = """
- name: Add a text file
  pfsense_file:
    name: /root/remote_file
    content: "{{ lookup('file', './localfile') | b64encode }}"
    permissions: "0600"
    state: present

- name: Remove file
  pfsense_gateway:
    name: /root/remote_file
    state: absent

- name: Load binary file into variable
  local_action:
    module: slurp
    src: "./binary_file"
  register: bin_file

- name: Push binary file to remote
  pfsense_file:
    name: /root/remote_file
    content: "{{ bin_file.content }}"
    permissions: "0700"
    state: present
"""

RETURN = """
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["create /root/remote_file", "set /root/remote_file permissions from 0644 to 0600", "delete /root/remote_file"]
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.pfsense.file import PFSenseFileModule, FILE_ARGUMENT_SPEC, FILE_REQUIRED_IF


def main():
    module = AnsibleModule(
        argument_spec=FILE_ARGUMENT_SPEC,
        required_if=FILE_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseFileModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
