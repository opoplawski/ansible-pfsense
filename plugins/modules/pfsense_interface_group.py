#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_interface_group
version_added: 0.5.0
author: Orion Poplawski (@opoplawski)
short_description: Manage pfSense interface groups
description:
  - Manage pfSense interface groups.
notes:
options:
  state:
    description: State in which to leave the interface group.
    choices: [ "present", "absent" ]
    default: present
    type: str
  name:
    description: The name of the interface group.
    type: str
    required: yes
  descr:
    description: Description of the interface group.
    type: str
  members:
    description: The members of the interface group.
    type: list
    required: yes
    elements: str
"""

EXAMPLES = """
- name: Add interface group
  pfsense_interface_group:
    name: VPN
    members:
      - VPN1
      - VPN2
    descr: All VPN interfaces

- name: Remove interface group
  pfsense_interface_group:
    state: absent
    name: VPN
"""

RETURN = """
commands:
    description: The set of commands that would be pushed to the remote device (if pfSense had a CLI).
    returned: always
    type: list
    sample: [
        "create interface-group 'VPN'",
        "delete interface-group 'VPN'"
    ]
member_ifnames:
    description: The pseudo-device interface names of all of the members.
    returned: always
    type: list
    sample: [
        "opt1",
        "opt2"
    ]
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.interface_group import PFSenseInterfaceGroupModule, INTERFACE_GROUP_ARGUMENT_SPEC


def main():
    module = AnsibleModule(
        argument_spec=INTERFACE_GROUP_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseInterfaceGroupModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
