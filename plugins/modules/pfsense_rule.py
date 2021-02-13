#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_rule
version_added: 0.1.0
author: Orion Poplawski (@opoplawski), Frederic Bor (@f-bor)
short_description: Manage pfSense rules
description:
  - Manage pfSense rules
notes:
options:
  name:
    description: The name the rule
    required: true
    default: null
    type: str
  action:
    description: The action of the rule
    default: pass
    choices: [ "pass", "block", "match", "reject" ]
    type: str
  state:
    description: State in which to leave the rule
    default: present
    choices: [ "present", "absent" ]
    type: str
  disabled:
    description: Is the rule disabled
    default: false
    type: bool
  interface:
    description: The interface for the rule
    required: true
    type: str
  floating:
    description: Is the rule floating
    type: bool
  direction:
    description: Direction floating rule applies to
    choices: [ "any", "in", "out" ]
    type: str
  ipprotocol:
    description: The IP protocol
    default: inet
    choices: [ "inet", "inet46", "inet6" ]
    type: str
  protocol:
    description: The protocol
    default: any
    choices: [ "any", "tcp", "udp", "tcp/udp", "icmp", "igmp", "ospf", "esp", "ah", "gre", "pim", "sctp", "pfsync", "carp" ]
    type: str
  source:
    description: The source address, in [!]{IP,HOST,ALIAS,any,(self),IP:INTERFACE,NET:INTERFACE} format.
    default: null
    type: str
  source_port:
    description:
      - Source port or port range specification.
      - This can either be a alias or a port number.
      - An inclusive range can also be specified, using the format C(first-last)..
    default: null
    type: str
  destination:
    description: The destination address, in [!]{IP,HOST,ALIAS,any,(self),IP:INTERFACE,NET:INTERFACE} format.
    default: null
    type: str
  destination_port:
    description:
      - Destination port or port range specification.
      - This can either be a alias or a port number.
      - An inclusive range can also be specified, using the format C(first-last)..
    default: null
    type: str
  log:
    description: Log packets matched by rule
    type: bool
  after:
    description: Rule to go after, or C(top)
    type: str
  before:
    description: Rule to go before, or C(bottom)
    type: str
  tcpflags_any:
    description: Allow TCP packets with any flags set.
    type: bool
  statetype:
    description: State type
    default: keep state
    choices: ["keep state", "sloppy state", "synproxy state", "none"]
    type: str
  queue:
    description: QOS default queue
    type: str
  ackqueue:
    description: QOS acknowledge queue
    type: str
  in_queue:
    description: Limiter queue for traffic coming into the chosen interface
    type: str
  out_queue:
    description: Limiter queue for traffic leaving the chosen interface
    type: str
  gateway:
    description: Leave as C(default) to use the system routing table or choose a gateway to utilize policy based routing.
    type: str
    default: default
  tracker:
    description: Rule tracking ID. Defaults to timestamp of rule creation.
    type: int
  icmptype:
    description:
      - One or more of these ICMP subtypes may be specified, separated by comma, or C(any) for all of them.
      - The types must match ip protocol.
      - althost, dataconv, echorep, echoreq, fqdnrep, fqdnreq, groupqry, grouprep, groupterm, inforep, inforeq, ipv6-here,
      - ipv6-where, listendone, listenrep, listqry, maskrep, maskreq, mobredir, mobregrep, mobregreq, mtrace, mtraceresp,
      - neighbradv, neighbrsol, niqry, nirep, paramprob, photuris, redir, routeradv, routersol, routrrenum, skip, squench,
      - timerep, timereq, timex, toobig, trace, unreach, wrurep, wrureq
    default: any
    type: str
  sched:
    description: Schedule day/time when the rule must be active
    required: False
    type: str
  quick:
    description: Set this option to apply this action to traffic that matches this rule immediately
    type: bool
    default: False
"""

EXAMPLES = """
- name: "Add Internal DNS out rule"
  pfsense_rule:
    name: 'Allow Internal DNS traffic out'
    action: pass
    interface: lan
    ipprotocol: inet
    protocol: udp
    source: dns_int
    destination: any
    destination_port: 53
    after: 'Allow proxies out'
    state: present
- name: "Allow inbound port range"
  pfsense_rule:
    name: 'Allow inbound port range'
    action: pass
    interface: wan
    ipprotocol: inet
    protocol: tcp
    source: any
    destination: NET:lan
    destination_port: 4000-5000
    after: 'Allow Internal DNS traffic out'
    state: present
"""

RETURN = """

"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.rule import PFSenseRuleModule, RULE_ARGUMENT_SPEC, RULE_REQUIRED_IF


def main():
    module = AnsibleModule(
        argument_spec=RULE_ARGUMENT_SPEC,
        required_if=RULE_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseRuleModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
