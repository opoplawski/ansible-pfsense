#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020-2022, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2020, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_openvpn_override
version_added: 0.5.0
author: Orion Poplawski (@opoplawski)
short_description: Manage pfSense OpenVPN Client Specific Overrides
description:
  - Manage pfSense OpenVPN Client Specific Overrides
notes:
options:
  name:
    description:
      - The name of the override. The X.509 common name for the client certificate, or the username for VPNs utilizing password authentication.
      - This match is case sensitive.
    required: true
    type: str
  state:
    description: State in which to leave the override
    choices: ["present", "absent"]
    default: present
    type: str
  disable:
    description: Disable this override.
    default: false
    type: bool
  descr:
    description: The description of the override.
    default: null
    type: str
  server_list:
    description: A list of OpenVPN servers this applies to.
    type: list
    elements: str
  block:
    description: Block this client connection based on its common name.
    default: false
    type: bool
  tunnel_network:
    description: IPv4 virtual network used for private communications between this server and client hosts expressed using CIDR notation.
    default: null
    type: str
  tunnel_networkv6:
    description: IPv6 virtual network used for private communications between this server and client hosts expressed using CIDR notation.
    default: null
    type: str
  local_network:
    description: IPv4 networks that will be accessible from the remote endpoint.
    default: null
    type: str
  local_networkv6:
    description: IPv6 networks that will be accessible from the remote endpoint.
    default: null
    type: str
  remote_network:
    description: IPv4 networks that will be routed through the tunnel.
    default: null
    type: str
  remote_networkv6:
    description: IPv6 networks that will be routed through the tunnel.
    default: null
    type: str
  gwredir:
    description: Redirect IPv4 gateway.
    default: no
    type: bool
  push_reset:
    description: Prevent this client from receiving any server-defined client settings.
    default: no
    type: bool
  netbios_enable:
    description: Enable NetBIOS over TCP/IP.
    default: no
    type: bool
  netbios_ntype:
    description:
      - 'NetBIOS Node Type. Possible options: b-node (broadcasts), p-node (point-to-point name queries to a WINS server),'
      - m-node (broadcast then query name server), and h-node (query name server, then broadcast). Default is 'none'.
    type: str
    choices: ['none', 'b-node', 'p-node', 'm-node', 'h-node']
  netbios_scope:
    description:
      - A NetBIOS Scope ID provides an extended naming service for NetBIOS over TCP/IP. The NetBIOS scope ID isolates NetBIOS traffic on a single network to
      - only those nodes with the same NetBIOS scope ID.
    type: str
  wins_server_enable:
    description: Provide a WINS server list to clients,
    type: bool
    default: no
  custom_options:
    description: Additional options to add for this client specific override, separated by a semicolon.
    type: str
"""

EXAMPLES = """
- name: Set IP address for user
  pfsense_openvpn_override:
    name: username
    custom_options: ifconfig-push 10.8.0.2 255.255.255.0
    state: present

- name: Remove override for user
  pfsense_opevpn_override:
    name: username
    state: absent
"""

RETURN = """
commands:
    description: The set of commands that would be pushed to the remote device (if pfSense had a CLI).
    returned: always
    type: list
    sample: ["create OpenVPN override 'username'"]
vpnids:
    description: A list of VPN IDs that the override applies to.
    returned: always
    type: list
    sample: [1,2]
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.openvpn_override import (
    PFSenseOpenVPNOverrideModule,
    OPENVPN_OVERRIDE_ARGUMENT_SPEC,
    OPENVPN_OVERRIDE_REQUIRED_IF
)


def main():
    module = AnsibleModule(
        argument_spec=OPENVPN_OVERRIDE_ARGUMENT_SPEC,
        required_if=OPENVPN_OVERRIDE_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseOpenVPNOverrideModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
