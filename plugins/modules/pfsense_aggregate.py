#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_aggregate
version_added: 0.1.0
author: Frederic Bor (@f-bor)
short_description: Manage multiple pfSense aliases, rules, rule separators, interfaces and vlans
description:
  - Manage multiple pfSense aliases, rules, rule separators, interfaces and vlans
notes:
  - aggregated_* use the same options definitions than pfsense corresponding module
options:
  aggregated_aliases:
    description: Dict of aliases to apply on the target
    required: False
    type: list
    elements: dict
    suboptions:
      name:
        description: The name of the alias
        required: true
        type: str
      state:
        description: State in which to leave the alias
        choices: [ "present", "absent" ]
        default: present
        type: str
      type:
        description: The type of the alias
        choices: [ "host", "network", "port", "urltable", "urltable_ports" ]
        default: null
        type: str
      address:
        description: The address of the alias. Use a space separator for multiple values
        default: null
        type: str
      descr:
        description: The description of the alias
        default: null
        type: str
      detail:
        description: The descriptions of the items. Use || separator between items
        default: null
        type: str
      updatefreq:
        description: Update frequency in days for urltable
        default: null
        type: int
  aggregated_interfaces:
    description: Dict of interfaces to apply on the target
    required: False
    type: list
    elements: dict
    suboptions:
      state:
        description: State in which to leave the interface.
        choices: [ "present", "absent" ]
        default: present
        type: str
      descr:
        description: Description (name) for the interface.
        required: true
        type: str
      interface:
        description: Network port to which assign the interface.
        type: str
      interface_descr:
        description: Network port descr to which assign the interface.
        type: str
      enable:
        description: Enable interface.
        type: bool
      ipv4_type:
        description: IPv4 Configuration Type.
        choices: [ "none", "static", "dhcp" ]
        default: 'none'
        type: str
      ipv6_type:
        description: IPv4 Configuration Type.
        choices: [ "none", "static", "slaac" ]
        default: 'none'
        type: str
      mac:
        description: Used to modify ("spoof") the MAC address of this interface.
        required: false
        type: str
      mtu:
        description: Maximum transmission unit
        required: false
        type: int
      mss:
        description: MSS clamping for TCP connections.
        required: false
        type: int
      speed_duplex:
        description: Set speed and duplex mode for this interface.
        required: false
        default: autoselect
        type: str
      ipv4_address:
        description: IPv4 Address.
        required: false
        type: str
      ipv4_prefixlen:
        description: IPv4 subnet prefix length.
        required: false
        default: 24
        type: int
      ipv4_gateway:
        description: IPv4 gateway for this interface.
        required: false
        type: str
      ipv6_address:
        description: IPv6 Address.
        required: false
        type: str
      ipv6_prefixlen:
        description: IPv6 subnet prefix length.
        required: false
        default: 128
        type: int
      ipv6_gateway:
        description: IPv6 gateway for this interface.
        required: false
        type: str
      blockpriv:
        description: Blocks traffic from IP addresses that are reserved for private networks.
        required: false
        type: bool
      blockbogons:
        description: Blocks traffic from reserved IP addresses (but not RFC 1918) or not yet assigned by IANA.
        required: false
        type: bool
  aggregated_nat_outbounds:
    description: Dict of nat_outbound rules to apply on the target
    required: False
    type: list
    elements: dict
    suboptions:
      descr:
        description: The name of the nat rule
        required: true
        default: null
        type: str
      disabled:
        description: Is the rule disabled
        default: false
        type: bool
      nonat:
        description: This option will disable NAT for traffic matching this rule and stop processing Outbound NAT rules
        default: false
        type: bool
      interface:
        description: The interface for the rule
        required: false
        type: str
      ipprotocol:
        description: The Internet Protocol version this rule applies to.
        default: inet46
        choices: [ "inet", "inet46", "inet6" ]
        type: str
      protocol:
        description: Which protocol this rule should match.
        default: any
        choices: [ "any", "tcp", "udp", "tcp/udp", "icmp", "esp", "ah", "gre", "ipv6", "igmp", "carp", "pfsync" ]
        type: str
      source:
        description: The matching source address, in {any,(self),ALIAS,NETWORK}[:port] format.
        required: false
        default: null
        type: str
      destination:
        description: The matching destination address, in {any,ALIAS,NETWORK}[:port] format.
        required: false
        default: null
        type: str
      invert:
        description: Invert the sense of the destination match.
        default: false
        type: bool
      address:
        description: The translated to address, in {ALIAS,NETWORK}[:port] format. Leave address part empty to use interface address.
        required: false
        default: null
        type: str
      poolopts:
        description: When an address pool is used, there are several options available that control how NAT translations happen on the pool.
        default: ""
        choices: [ "", "round-robin", "round-robin sticky-address", "random", "random sticky-address", "source-hash", "bitmask" ]
        type: str
      source_hash_key:
        description: >
            The key that is fed to the hashing algorithm in hex format, preceeded by "0x", or any string.
            A non-hex string is hashed using md5 to a hexadecimal key. Defaults to a randomly generated value.
        required: false
        default: ''
        type: str
      staticnatport:
        description: Do not randomize source port
        default: false
        type: bool
      nosync:
        description: >
            Prevents the rule on Master from automatically syncing to other CARP members.
            This does NOT prevent the rule from being overwritten on Slave.
        default: false
        type: bool
      state:
        description: State in which to leave the rule
        default: present
        choices: [ "present", "absent" ]
        type: str
      after:
        description: Rule to go after, or "top"
        type: str
      before:
        description: Rule to go before, or "bottom"
        type: str
  aggregated_nat_port_forwards:
    description: Dict of nat_port_forward rules to apply on the target
    required: False
    type: list
    elements: dict
    suboptions:
      descr:
        description: The name of the nat rule
        required: true
        default: null
        type: str
      disabled:
        description: Is the rule disabled
        default: false
        type: bool
      nordr:
        description: Disable redirection for traffic matching this rule
        default: false
        type: bool
      interface:
        description: The interface for the rule
        required: false
        type: str
      protocol:
        description: Which protocol this rule should match.
        default: tcp
        choices: [ "tcp", "udp", "tcp/udp", "icmp", "esp", "ah", "gre", "ipv6", "igmp", "pim", "ospf" ]
        type: str
      source:
        description: The source address, in [!]{IP,HOST,ALIAS,any,IP:INTERFACE,NET:INTERFACE}[:port] format.
        default: null
        type: str
      destination:
        description: The destination address, in [!]{IP,HOST,ALIAS,any,IP:INTERFACE,NET:INTERFACE}[:port] format.
        default: null
        type: str
      target:
        description: The translated to address, in {ALIAS,IP}[:port] format.
        required: false
        default: null
        type: str
      natreflection:
        description: Allows NAT reflection to be enabled or disabled on a per-port forward basis.
        default: system-default
        choices: [ "system-default", "enable", "purenat", "disable" ]
        type: str
      associated_rule:
        description: >
          Choose one of Add an associated filter rule gets updated when the port forward is updated,
          or Add an unassociated filter rule, or pass which passes all traffic that matches the entry without having a firewall rule at all.
        default: associated
        choices: [ "associated", "unassociated", "pass", "none" ]
        type: str
      nosync:
        description: >
            Prevents the rule on Master from automatically syncing to other CARP members.
            This does NOT prevent the rule from being overwritten on Slave.
        default: false
        type: bool
      state:
        description: State in which to leave the rule
        default: present
        choices: [ "present", "absent" ]
        type: str
      after:
        description: Rule to go after, or "top"
        type: str
      before:
        description: Rule to go before, or "bottom"
        type: str
  aggregated_rules:
    description: Dict of rules to apply on the target
    required: False
    type: list
    elements: dict
    suboptions:
      name:
        description: The name the rule
        required: true
        default: null
        type: str
      action:
        description: The action of the rule
        default: pass
        choices: [ 'pass', 'block', 'match', 'reject' ]
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
        choices: [ 'any', 'tcp', 'udp', 'tcp/udp', 'icmp', 'igmp', 'ospf', 'esp', 'ah', 'gre', 'pim', 'sctp', 'pfsync', 'carp' ]
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
  aggregated_rule_separators:
    description: Dict of rule separators to apply on the target
    required: False
    type: list
    elements: dict
    suboptions:
      name:
        description: The name of the separator
        required: true
        type: str
      state:
        description: State in which to leave the separator
        choices: [ "present", "absent" ]
        default: present
        type: str
      interface:
        description: The interface for the separator
        type: str
      floating:
        description: Is the rule on floating tab
        type: bool
      after:
        description: Rule to go after, or "top"
        type: str
      before:
        description: Rule to go before, or "bottom"
        type: str
      color:
        description: The separator's color
        default: info
        choices: [ 'info', 'warning', 'danger', 'success' ]
        type: str
  aggregated_vlans:
    description: Dict of vlans to apply on the target
    required: False
    type: list
    elements: dict
    suboptions:
      vlan_id:
        description: The vlan tag. Must be between 1 and 4094.
        required: true
        type: int
      interface:
        description: The interface on which to declare the vlan. Friendly name (assignments) can be used.
        required: true
        type: str
      priority:
        description: 802.1Q VLAN Priority code point. Must be between 0 and 7.
        required: false
        type: int
      descr:
        description: The description of the vlan
        default: null
        type: str
      state:
        description: State in which to leave the vlan
        choices: [ "present", "absent" ]
        default: present
        type: str
  order_rules:
    description: rules will be generated following the playbook order
    required: False
    default: False
    type: bool
  purge_aliases:
    description: delete all the aliases that are not defined into aggregated_aliases
    required: False
    default: False
    type: bool
  purge_interfaces:
    description: delete all the interfaces that are not defined into aggregated_interfaces
    required: False
    default: False
    type: bool
  purge_nat_outbounds:
    description: delete all the nat_outbound rules that are not defined into aggregated_nat_outbounds
    required: False
    default: False
    type: bool
  purge_nat_port_forwards:
    description: delete all the nat_port_forward rules that are not defined into aggregated_nat_port_forwards
    required: False
    default: False
    type: bool
  purge_rules:
    description: delete all the rules that are not defined into aggregated_rules
    required: False
    default: False
    type: bool
  purge_rule_separators:
    description: delete all the rule separators that are not defined into aggregated_rule_separators
    required: False
    default: False
    type: bool
  purge_vlans:
    description: delete all the vlans that are not defined into aggregated_vlans
    required: False
    default: False
    type: bool
  interface_filter:
    description: only apply rules and rules separators on those interfaces (separated by space)
    required: False
    type: str
"""

EXAMPLES = """
- name: "Setup two vlans, three aliases, six rules, four separators, and delete everything else"
  pfsense_aggregate:
    purge_aliases: true
    purge_rules: true
    purge_rule_separators: true
    purge_vlans: true
    aggregated_aliases:
      - { name: port_ssh, type: port, address: 22, state: present }
      - { name: port_http, type: port, address: 80, state: present }
      - { name: port_https, type: port, address: 443, state: present }
    aggregated_rules:
      - { name: "allow_all_ssh", source: any, destination: "any:port_ssh", protocol: tcp, interface: lan, state: present }
      - { name: "allow_all_http", source: any, destination: "any:port_http", protocol: tcp, interface: lan, state: present }
      - { name: "allow_all_https", source: any, destination: "any:port_https", protocol: tcp, interface: lan, state: present }
      - { name: "allow_all_ssh", source: any, destination: "any:port_ssh", protocol: tcp, interface: wan, state: present }
      - { name: "allow_all_http", source: any, destination: "any:port_http", protocol: tcp, interface: wan, state: present }
      - { name: "allow_all_https", source: any, destination: "any:port_https", protocol: tcp, interface: wan, state: present }
    aggregated_rule_separators:
      - { name: "SSH", interface: lan, state: present, before: allow_all_ssh }
      - { name: "HTTP", interface: lan, state: present, before: allow_all_http }
      - { name: "SSH", interface: wan, state: present, before: allow_all_ssh }
      - { name: "HTTP", interface: wan, state: present, before: allow_all_http }
    aggregated_vlans:
      - { descr: voice, vlan_id: 100, interface: mvneta0, state: present }
      - { descr: video, vlan_id: 200, interface: mvneta0, state: present }
"""

RETURN = """
result_aliases:
    description: the set of aliases commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: success
    type: list
    sample: ["create alias 'adservers', type='host', address='10.0.0.1 10.0.0.2'", "update alias 'one_host' set address='10.9.8.7'", "delete alias 'one_alias'"]
result_interfaces:
    description: the set of interfaces commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: success
    type: list
    sample: ["create interface 'VOICE', port='mvneta1.100'", "create interface 'VIDEO', port='mvneta1.200'"]
aggregated_rules:
    description: final set of rules
    returned: success
    type: list
    sample: []
result_separators:
    description: the set of separators commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: success
    type: list
    sample: ["create rule_separator 'SSH', interface='lan', color='info'", "update rule_separator 'SSH' set color='warning'", "delete rule_separator 'SSH'"]
result_vlans:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: success
    type: list
    sample: ["create vlan 'mvneta.100', descr='voice', priority='5'", "update vlan 'mvneta.100', set priority='6'", "delete vlan 'mvneta.100'"]
"""

from ansible_collections.pfsensible.core.plugins.module_utils.pfsense import PFSenseModule
from ansible_collections.pfsensible.core.plugins.module_utils.alias import PFSenseAliasModule, ALIAS_ARGUMENT_SPEC, ALIAS_REQUIRED_IF
from ansible_collections.pfsensible.core.plugins.module_utils.interface import (
    PFSenseInterfaceModule,
    INTERFACE_ARGUMENT_SPEC,
    INTERFACE_REQUIRED_IF,
    INTERFACE_MUTUALLY_EXCLUSIVE,
)
from ansible_collections.pfsensible.core.plugins.module_utils.nat_outbound import PFSenseNatOutboundModule, NAT_OUTBOUND_ARGUMENT_SPEC, NAT_OUTBOUD_REQUIRED_IF
from ansible_collections.pfsensible.core.plugins.module_utils.nat_port_forward import (
    PFSenseNatPortForwardModule,
    NAT_PORT_FORWARD_ARGUMENT_SPEC,
    NAT_PORT_FORWARD_REQUIRED_IF
)
from ansible_collections.pfsensible.core.plugins.module_utils.rule import PFSenseRuleModule, RULE_ARGUMENT_SPEC, RULE_REQUIRED_IF
from ansible_collections.pfsensible.core.plugins.module_utils.rule_separator import (
    PFSenseRuleSeparatorModule,
    RULE_SEPARATOR_ARGUMENT_SPEC,
    RULE_SEPARATOR_REQUIRED_ONE_OF,
    RULE_SEPARATOR_MUTUALLY_EXCLUSIVE,
)
from ansible_collections.pfsensible.core.plugins.module_utils.vlan import PFSenseVlanModule, VLAN_ARGUMENT_SPEC

from ansible.module_utils.basic import AnsibleModule


class PFSenseModuleAggregate(object):
    """ module managing pfsense aggregated aliases, rules, rule separators, interfaces and vlans """

    def __init__(self, module):
        self.module = module
        self.pfsense = PFSenseModule(module)
        self.pfsense_aliases = PFSenseAliasModule(module, self.pfsense)
        self.pfsense_interfaces = PFSenseInterfaceModule(module, self.pfsense)
        self.pfsense_nat_outbounds = PFSenseNatOutboundModule(module, self.pfsense)
        self.pfsense_nat_port_forwards = PFSenseNatPortForwardModule(module, self.pfsense)
        self.pfsense_rules = PFSenseRuleModule(module, self.pfsense)
        self.pfsense_rule_separators = PFSenseRuleSeparatorModule(module, self.pfsense)
        self.pfsense_vlans = PFSenseVlanModule(module, self.pfsense)

    def _update(self):
        run = False
        cmd = 'require_once("filter.inc");\n'
        # TODO: manage one global list of commands as ordering can be important between modules
        if self.pfsense_vlans.result['changed']:
            run = True
            cmd += self.pfsense_vlans.get_update_cmds()

        if self.pfsense_interfaces.result['changed']:
            run = True
            cmd += self.pfsense_interfaces.get_update_cmds()

        cmd += 'if (filter_configure() == 0) { \n'
        if self.pfsense_aliases.result['changed']:
            run = True
            cmd += 'clear_subsystem_dirty(\'aliases\');\n'

        if self.pfsense_nat_port_forwards.result['changed'] or self.pfsense_nat_outbounds.result['changed']:
            run = True
            cmd += 'clear_subsystem_dirty(\'natconf\');\n'

        if (self.pfsense_rules.result['changed'] or self.pfsense_rule_separators.result['changed'] or
                self.pfsense_nat_port_forwards.result['changed'] or self.pfsense_nat_outbounds.result['changed']):
            run = True
            cmd += 'clear_subsystem_dirty(\'filter\');\n'
        cmd += '}'
        if run:
            return self.pfsense.phpshell(cmd)

        return ('', '', '')

    def _parse_floating_interfaces(self, interfaces):
        """ parse interfaces """
        res = set()
        for interface in interfaces.split(','):
            res.add(self.pfsense.parse_interface(interface))
        return res

    def want_rule(self, rule_elt, rules, name_field='name'):
        """ return True if we want to keep rule_elt """
        descr = rule_elt.find('descr')
        interface = rule_elt.find('interface')
        floating = rule_elt.find('floating') is not None

        # probably not a rule
        if descr is None or interface is None:
            return True

        for rule in rules:
            if rule['state'] == 'absent':
                continue
            if rule[name_field] != descr.text:
                continue

            rule_floating = (rule.get('floating') is not None and
                             (isinstance(rule['floating'], bool) and
                             rule['floating'] or rule['floating'].lower() in ['yes', 'true']))
            if floating != rule_floating:
                continue

            if floating or self.pfsense.parse_interface(rule['interface']) == interface.text:
                return True
        return False

    def want_rule_separator(self, separator_elt, rule_separators):
        """ return True if we want to keep separator_elt """
        name = separator_elt.find('text').text
        interface = separator_elt.find('if').text

        for separator in rule_separators:
            if separator['state'] == 'absent':
                continue
            if separator['name'] != name:
                continue
            if separator.get('floating'):
                if interface == 'floatingrules':
                    return True
            elif self.pfsense.parse_interface(separator['interface']) == interface:
                return True
        return False

    @staticmethod
    def want_alias(alias_elt, aliases):
        """ return True if we want to keep alias_elt """
        name = alias_elt.find('name')
        alias_type = alias_elt.find('type')

        # probably not an alias
        if name is None or type is None:
            return True

        for alias in aliases:
            if alias['state'] == 'absent':
                continue
            if alias['name'] == name.text and alias['type'] == alias_type.text:
                return True
        return False

    @staticmethod
    def want_interface(interface_elt, interfaces):
        """ return True if we want to keep interface_elt """
        descr_elt = interface_elt.find('descr')
        if descr_elt is not None and descr_elt.text:
            name = descr_elt.text
        else:
            name = interface_elt.tag

        for interface in interfaces:
            if interface['state'] == 'absent':
                continue
            if interface['descr'] == name:
                return True
        return False

    @staticmethod
    def want_vlan(vlan_elt, vlans):
        """ return True if we want to keep vlan_elt """
        tag = int(vlan_elt.find('tag').text)
        interface = vlan_elt.find('if')

        for vlan in vlans:
            if vlan['state'] == 'absent':
                continue
            if vlan['vlan_id'] == tag and vlan['interface'] == interface.text:
                return True
        return False

    @staticmethod
    def is_filtered(interface_filter, params):
        if interface_filter is None:
            return False

        if 'floating' in params:
            if isinstance(params['floating'], str):
                floating = params['floating'].lower()
            else:
                floating = 'true' if params['floating'] else 'false'

            if floating != 'false' and floating != 'no':
                return 'floating' not in interface_filter

        return params['interface'].lower() not in interface_filter

    def run_rules(self):
        """ process input params to add/update/delete all rules """

        want = self.module.params['aggregated_rules']
        interface_filter = self.module.params['interface_filter'].lower().split(' ') if self.module.params.get('interface_filter') is not None else None

        if want is None:
            return

        # delete every other rule if required
        if self.module.params['purge_rules']:
            todel = []
            for rule_elt in self.pfsense_rules.root_elt:
                if not self.want_rule(rule_elt, want):
                    params = {}
                    params['state'] = 'absent'
                    params['name'] = rule_elt.find('descr').text

                    if rule_elt.find('floating') is not None:
                        params['floating'] = True
                        interfaces = rule_elt.find('interface').text.split(',')
                        params['interface'] = list()
                        for interface in interfaces:
                            target = self.pfsense.get_interface_display_name(interface, return_none=True)
                            if target is not None:
                                params['interface'].append(target)
                            else:
                                params['interface'].append(interface)
                        params['interface'] = ','.join(params['interface'])
                    else:
                        params['interface'] = self.pfsense.get_interface_display_name(rule_elt.find('interface').text, return_none=True)

                    if params['interface'] is None:
                        continue

                    todel.append(params)

            for params in todel:
                if self.is_filtered(interface_filter, params):
                    continue
                self.pfsense_rules.run(params)

        # generating order if required
        if self.module.params.get('order_rules'):
            last_rules = dict()
            for params in want:
                if params.get('before') is not None or params.get('after') is not None:
                    self.module.fail_json(msg="You can't use after or before parameters on rules when using order_rules (see {0})".format(params['name']))

                if params.get('state') == 'absent':
                    continue

                if params.get('floating'):
                    key = 'floating'
                else:
                    key = params['interface']

                # first rule on interface
                if key not in last_rules:
                    params['after'] = 'top'
                    last_rules[key] = params['name']
                    continue

                params['after'] = last_rules[key]
                last_rules[key] = params['name']

        # processing aggregated parameters
        for params in want:
            if self.is_filtered(interface_filter, params):
                continue
            self.pfsense_rules.run(params)

    def run_nat_outbounds_rules(self):
        """ process input params to add/update/delete all nat_outbound rules """

        want = self.module.params['aggregated_nat_outbounds']
        interface_filter = self.module.params['interface_filter'].lower().split(' ') if self.module.params.get('interface_filter') is not None else None

        if want is None:
            return

        # delete every other rule if required
        if self.module.params['purge_nat_outbounds']:
            todel = []
            for rule_elt in self.pfsense_nat_outbounds.root_elt:
                if not self.want_rule(rule_elt, want, name_field='descr'):
                    params = {}
                    params['state'] = 'absent'
                    params['descr'] = rule_elt.find('descr').text
                    params['interface'] = self.pfsense.get_interface_display_name(rule_elt.find('interface').text, return_none=True)

                    if params['interface'] is None:
                        continue

                    todel.append(params)

            for params in todel:
                if self.is_filtered(interface_filter, params):
                    continue
                self.pfsense_nat_outbounds.run(params)

        # processing aggregated parameters
        for params in want:
            if self.is_filtered(interface_filter, params):
                continue
            self.pfsense_nat_outbounds.run(params)

    def run_nat_port_forwards_rules(self):
        """ process input params to add/update/delete all nat_port_forwards_rule rules """

        want = self.module.params['aggregated_nat_port_forwards']
        interface_filter = self.module.params['interface_filter'].lower().split(' ') if self.module.params.get('interface_filter') is not None else None

        if want is None:
            return

        # delete every other rule if required
        if self.module.params['purge_nat_port_forwards']:
            todel = []
            for rule_elt in self.pfsense_nat_port_forwards.root_elt:
                if not self.want_rule(rule_elt, want, name_field='descr'):
                    params = {}
                    params['state'] = 'absent'
                    params['descr'] = rule_elt.find('descr').text
                    params['interface'] = self.pfsense.get_interface_display_name(rule_elt.find('interface').text, return_none=True)

                    if params['interface'] is None:
                        continue

                    todel.append(params)

            for params in todel:
                if self.is_filtered(interface_filter, params):
                    continue
                self.pfsense_nat_port_forwards.run(params)

        # processing aggregated parameters
        for params in want:
            if self.is_filtered(interface_filter, params):
                continue
            self.pfsense_nat_port_forwards.run(params)

    def run_aliases(self):
        """ process input params to add/update/delete all aliases """
        want = self.module.params['aggregated_aliases']

        if want is None:
            return

        # processing aggregated parameter
        for param in want:
            self.pfsense_aliases.run(param)

        # delete every other alias if required
        if self.module.params['purge_aliases']:
            todel = []
            for alias_elt in self.pfsense_aliases.root_elt:
                if not self.want_alias(alias_elt, want):
                    params = {}
                    params['state'] = 'absent'
                    params['name'] = alias_elt.find('name').text
                    todel.append(params)

            for params in todel:
                self.pfsense_aliases.run(params)

    def run_interfaces(self):
        """ process input params to add/update/delete all interfaces """
        want = self.module.params['aggregated_interfaces']

        if want is None:
            return

        # processing aggregated parameter
        for param in want:
            self.pfsense_interfaces.run(param)

        # delete every other if required
        if self.module.params['purge_interfaces']:
            todel = []
            for interface_elt in self.pfsense_interfaces.root_elt:
                if not self.want_interface(interface_elt, want):
                    params = {}
                    params['state'] = 'absent'
                    descr_elt = interface_elt.find('descr')
                    if descr_elt is not None and descr_elt.text:
                        params['descr'] = descr_elt.text
                        todel.append(params)

            for params in todel:
                self.pfsense_interfaces.run(params)

    def run_rule_separators(self):
        """ process input params to add/update/delete all separators """
        want = self.module.params['aggregated_rule_separators']
        interface_filter = self.module.params['interface_filter'].lower().split(' ') if self.module.params.get('interface_filter') is not None else None

        if want is None:
            return

        # processing aggregated parameter
        for params in want:
            if self.is_filtered(interface_filter, params):
                continue
            self.pfsense_rule_separators.run(params)

        # delete every other if required
        if self.module.params['purge_rule_separators']:
            todel = []
            for interface_elt in self.pfsense_rule_separators.separators:
                for separator_elt in interface_elt:
                    if not self.want_rule_separator(separator_elt, want):
                        params = {}
                        params['state'] = 'absent'
                        params['name'] = separator_elt.find('text').text
                        if interface_elt.tag == 'floatingrules':
                            params['floating'] = True
                        else:
                            params['interface'] = self.pfsense.get_interface_display_name(interface_elt.tag, return_none=True)
                            if params['interface'] is None:
                                continue
                        todel.append(params)

            for params in todel:
                if self.is_filtered(interface_filter, params):
                    continue
                self.pfsense_rule_separators.run(params)

    def run_vlans(self):
        """ process input params to add/update/delete all vlans """
        want = self.module.params['aggregated_vlans']

        if want is None:
            return

        # processing aggregated parameter
        for param in want:
            self.pfsense_vlans.run(param)

        # delete every other if required
        if self.module.params['purge_vlans']:
            todel = []
            for vlan_elt in self.pfsense_vlans.root_elt:
                if not self.want_vlan(vlan_elt, want):
                    params = {}
                    params['state'] = 'absent'
                    params['interface'] = vlan_elt.find('if').text
                    params['vlan_id'] = int(vlan_elt.find('tag').text)
                    todel.append(params)

            for params in todel:
                self.pfsense_vlans.run(params)

    def commit_changes(self):
        """ apply changes and exit module """
        stdout = ''
        stderr = ''
        changed = (
            self.pfsense_aliases.result['changed'] or self.pfsense_interfaces.result['changed'] or self.pfsense_nat_outbounds.result['changed']
            or self.pfsense_nat_port_forwards.result['changed'] or self.pfsense_rules.result['changed']
            or self.pfsense_rule_separators.result['changed'] or self.pfsense_vlans.result['changed']
        )

        if changed and not self.module.check_mode:
            self.pfsense.write_config(descr='aggregated change')
            (dummy, stdout, stderr) = self._update()

        result = {}
        result['result_aliases'] = self.pfsense_aliases.result['commands']
        result['result_interfaces'] = self.pfsense_interfaces.result['commands']
        result['result_nat_outbounds'] = self.pfsense_nat_outbounds.result['commands']
        result['result_nat_port_forwards'] = self.pfsense_nat_port_forwards.result['commands']
        result['result_rules'] = self.pfsense_rules.result['commands']
        result['result_rule_separators'] = self.pfsense_rule_separators.result['commands']
        result['result_vlans'] = self.pfsense_vlans.result['commands']
        result['changed'] = changed
        result['stdout'] = stdout
        result['stderr'] = stderr
        self.module.exit_json(**result)


def main():
    argument_spec = dict(
        aggregated_aliases=dict(type='list', elements='dict', options=ALIAS_ARGUMENT_SPEC, required_if=ALIAS_REQUIRED_IF),
        aggregated_interfaces=dict(
            type='list', elements='dict',
            options=INTERFACE_ARGUMENT_SPEC, required_if=INTERFACE_REQUIRED_IF, mutually_exclusive=INTERFACE_MUTUALLY_EXCLUSIVE),
        aggregated_rules=dict(type='list', elements='dict', options=RULE_ARGUMENT_SPEC, required_if=RULE_REQUIRED_IF),
        aggregated_nat_outbounds=dict(type='list', elements='dict', options=NAT_OUTBOUND_ARGUMENT_SPEC, required_if=NAT_OUTBOUD_REQUIRED_IF),
        aggregated_nat_port_forwards=dict(type='list', elements='dict', options=NAT_PORT_FORWARD_ARGUMENT_SPEC, required_if=NAT_PORT_FORWARD_REQUIRED_IF),
        aggregated_rule_separators=dict(
            type='list', elements='dict',
            options=RULE_SEPARATOR_ARGUMENT_SPEC, required_one_of=RULE_SEPARATOR_REQUIRED_ONE_OF, mutually_exclusive=RULE_SEPARATOR_MUTUALLY_EXCLUSIVE),
        aggregated_vlans=dict(type='list', elements='dict', options=VLAN_ARGUMENT_SPEC),
        order_rules=dict(default=False, type='bool'),
        purge_aliases=dict(default=False, type='bool'),
        purge_interfaces=dict(default=False, type='bool'),
        purge_nat_outbounds=dict(default=False, type='bool'),
        purge_nat_port_forwards=dict(default=False, type='bool'),
        purge_rules=dict(default=False, type='bool'),
        purge_rule_separators=dict(default=False, type='bool'),
        purge_vlans=dict(default=False, type='bool'),
        interface_filter=dict(required=False, type='str'),
    )

    required_one_of = [[
        'aggregated_aliases',
        'aggregated_interfaces',
        'aggregated_nat_outbounds',
        'aggregated_nat_port_forwards',
        'aggregated_rules',
        'aggregated_rule_separators',
        'aggregated_vlans'
    ]]

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=required_one_of,
        supports_check_mode=True)

    pfmodule = PFSenseModuleAggregate(module)

    pfmodule.run_vlans()
    pfmodule.run_interfaces()

    pfmodule.run_aliases()
    pfmodule.run_nat_outbounds_rules()
    pfmodule.run_nat_port_forwards_rules()
    pfmodule.run_rules()
    pfmodule.run_rule_separators()

    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
