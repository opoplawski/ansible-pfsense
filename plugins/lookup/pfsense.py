# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
lookup: pfsense
author: Frederic Bor (@f-bor)
version_added: 0.1.0
short_description: Generate pfSense aliases, rules and rule_separators
description:
- This lookup plugin is designed to be used with pfsense_aggregate module.
  It takes a yaml file and generate list of aliases and rules definitions.
  The aim is to be able to easily manage a fleet of pfSenses and avoiding any
  redundant work, like defining the sames hosts/ports aliases or rules
  on multiples pfSenses. The plugin determine what is required to be defined
  on each pfsense, leaving to the network administrator only the task of updating
  the yaml definition file.
options:
  file:
    description: The yaml file defining the network
  type:
    description: What to generate
    choices:
      - aliases
      - rules
      - rule_separators
"""

EXAMPLES = """
- name: Get all aliases to be defined
  debug:
    aliases: "{{ lookup('pfsense', 'all_pf_defs.yml', 'aliases') }}"

- name: Get all rules to be defined
  debug:
    rules: "{{ lookup('pfsense', 'all_pf_defs.yml', 'rules') }}"

- name: Get all rule_separators to be defined
  debug:
    rule_separators: "{{ lookup('pfsense', 'all_pf_defs.yml', 'rule_separators') }}"

"""

RETURN = """
  _list:
    description:
      - list of dictionaries with aliases, rules or rule_separators
    type: list
"""

"""
To determine if a rule and corresponding aliases has to be declared on a pfsense
and on which interfaces, the plugin check if rule source or destination is
matching any local or routed network on the pfsense. To avoid having every rule
declared on a wan interface, if a rule can be declared on multiple interfaces
it is not on the ones routing 0.0.0.0/0 if there is another which is not routing it.
If a network is declared as remote (routed thru) on an interface and is also defined
as the local network on an interface of the target pfsense, the local network is preffered.
The same apply to adjacent networks, which indicates neighbor networks that are routed thru a pfSense.

Following pfSense rule definition (one host/alias per source/destination,
one port/alias per source/destination), each rule declared in the yaml is breaked
into smaller rules until having rules than can be declared.

The generated rules order follows the yaml file rules order.

Rule separators name are taken from parent rules' groups (see 'ADMIN', 'VOIP',
'MISC' or 'ACTIVE DIRECTORY' in the example below). Nested groups generate separators
names in the form 'GROUP1 - GROUP2 - ...'

You can define a default value for all rules and subrules of a separator using
the name 'options'. The parameters supported this way are gateway, log, queue, ackqueue,
in_queue, out_queue and sched. You can override those default values setting other values
on a deeper options set or inside the rule definition.

You can use an extra parameter in rules and options, filter, to restrict the rule
generation only to the pfsenses set in this parameter. Same goes for ifilter and interfaces.

The yaml file must include the following definitions to describe the network topology:
- pfsenses
- rules
- hosts_aliases
- ports_aliases

You can run the plugin alone to debug rules and aliases generation, for example:
- ./lookup_plugins/pfsense.py defs.yml pf1
- ./lookup_plugins/pfsense.py defs.yml pf1 ping_from_poc3

A typical pfsense_aggregate task using the lookup plugin will look like this:
  tasks:
    - name: "setup aliases & rules"
      pfsense_aggregate:
        purge_aliases: true
        purge_rules: true
        purge_rule_separators: true
        aggregated_aliases: |
          {{ lookup('pfsense', 'defs.yml', 'aliases') }}
        aggregated_rules: |
          {{ lookup('pfsense', 'defs.yml', 'rules') }}
        aggregated_rule_separators: |
          {{ lookup('pfsense', 'defs.yml', 'rule_separators') }}


Here is an example of yaml file:
---

pfsenses:
  pf1:          {
    interfaces: {
      lan: { ip: 192.168.1.1/24, adjacent_networks: lan_data_poc4 },
      lan_100: { ip: 172.16.1.1/24 },
      vpn: { remote_networks: lan_data_all lan_voip_all},
      }
    }

  pf2:          {
    interfaces: {
      lan: { ip: 192.168.2.1/24 },
      lan_100: { ip: 172.16.2.1/24 },
      vpn: { remote_networks: lan_data_all lan_voip_all},
      }
    }

  pf3:          {
    interfaces: {
      bridge_lan: { ip: 192.168.3.1/24, remote_networks: lan_data_all, bridge: True },
      bridge_lan_100: { ip: 172.16.3.1/24, remote_networks: lan_voip_all, bridge: True },
      wan: { remote_networks: 0.0.0.0/0 }
      }
    }

rules:
  options: { log: yes }

  ADMIN:
    antilock_out: { src: any, dst: any, protocol: tcp, dst_port: port_ssh port_http 443 }
    admin_bypass: { src: srv_admin, dst: any }
    MISC:
      ping_from_poc3: { src: lan_poc3_all, dst: srv_admin, protocol: icmp }

  VOIP:
    voip_conf_tftp: { src: all_ipbx, dst: lan_voip_all, dst_port: 69, protocol: udp }

  ACTIVE DIRECTORY:
    ads_to_ads_tcp: { src: all_ads, dst: all_ads, dst_port: port_dns port_ldap port_ldap_ssl, protocol: tcp }
    ads_to_ads_udp: { src: all_ads, dst: all_ads, dst_port: port_dns port_ldap, protocol: udp }

  DNS:
    options: { log: no }
    any_to_local_dns: {src: any, dst: all_ads, dst_port: port_dns, protocol: udp }

hosts_aliases:
  # hosts
  ipbx_poc1: { ip: 172.16.1.3 }
  ipbx_poc2: { ip: 172.16.2.3 }
  ipbx_poc3: { ip: 172.16.3.3 }
  all_ipbx: { ip: ipbx_poc1 ipbx_poc2 ipbx_poc3 }

  ad_poc1: { ip: 192.168.1.3 }
  ad_poc2: { ip: 192.168.2.3 }
  ad_poc3: { ip: 192.168.3.3 }
  all_ads: { ip: ad_poc1 ad_poc2 ad_poc3 }

  # networks
  lan_voip_poc1: { ip: 172.16.1.0/24 }
  lan_voip_poc2: { ip: 172.16.2.0/24 }
  lan_voip_poc3: { ip: 172.16.3.0/24 }
  lan_voip_all : { ip: lan_voip_poc1 lan_voip_poc2 lan_voip_poc3 }

  lan_data_poc1: { ip: 192.168.1.0/24 }
  lan_data_poc2: { ip: 192.168.2.0/24 }
  lan_data_poc3: { ip: 192.168.3.0/24 }
  lan_data_poc4: { ip: 192.168.4.0/24 }
  lan_data_all : { ip: lan_data_poc1 lan_data_poc2 lan_data_poc3 lan_data_poc4 }

  lan_poc3_all : { ip: lan_voip_poc3 lan_data_poc3 }

  srv_admin: { ip: 192.168.1.165 }

ports_aliases:
  port_ssh: { port: 22 }
  port_telnet: { port: 23 }
  port_dns: { port: 51 }
  port_http: { port: 80 }
  port_ldap: { port: 389 }
  port_ldap_ssl: { port: 636 }

 """

from copy import copy, deepcopy
from collections import OrderedDict
from ansible.utils.display import Display
from dns import resolver, exception

import argparse
import json
import re
import socket
import sys
import yaml
import traceback
import os

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible_collections.pfsensible.core.plugins.module_utils.compat import ipaddress

OPTION_FIELDS = [
    'gateway', 'log', 'queue', 'ackqueue', 'in_queue', 'out_queue', 'icmptype', 'filter', 'efilter', 'ifilter', 'sched', 'quick', 'direction',
    'staticnatport', 'ipprotocol',
    'associated_rule', 'natreflection',
]
OUTPUT_OPTION_FIELDS = ['gateway', 'log', 'queue', 'ackqueue', 'in_queue', 'out_queue', 'icmptype', 'sched', 'quick', 'direction']
OUTPUT_SRC_NAT_OPTION_FIELDS = ['staticnatport', 'ipprotocol']
OUTPUT_DST_NAT_OPTION_FIELDS = ['associated_rule', 'natreflection']

display = Display()


def to_unicode(string):
    """ return a unicode representation of string if required """
    if sys.version_info[0] >= 3:
        return string
    return string.decode("utf-8")


def ordered_load(stream, loader_cls=yaml.Loader, object_pairs_hook=OrderedDict):
    """ load and return yaml data from stream using ordered dicts """

    class OrderedLoader(loader_cls):
        def __init__(self, stream):
            self._root = os.path.split(stream.name)[0]
            super(OrderedLoader, self).__init__(stream)

        def include(self, node):
            filename = os.path.join(self._root, self.construct_scalar(node))
            with open(filename, 'r') as f:
                return yaml.load(f, OrderedLoader)

    def construct_mapping(loader, node):
        loader.flatten_mapping(node)
        return object_pairs_hook(loader.construct_pairs(node))

    OrderedLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping)
    OrderedLoader.add_constructor(
        '!include',
        OrderedLoader.include)
    return yaml.load(stream, OrderedLoader)


def static_vars(**kwargs):
    """ static decorator to declare static vars """

    def decorate(func):
        """ static decorator func """
        for k in kwargs:
            setattr(func, k, kwargs[k])
        return func
    return decorate


@static_vars(res_cache=dict())
def to_ip_address(address):
    """ convert address to IPv4Address or IPv6Address """
    res = to_ip_address.res_cache.get(address)
    if res is None:
        res = ipaddress.ip_address(to_unicode(address))
        to_ip_address.res_cache[address] = res
    return res


@static_vars(res_cache=dict())
def to_ip_network(address, strict=True):
    """ convert address to IPv4Network or IPv6Network """
    key = address + str(strict)
    res = to_ip_network.res_cache.get(key)
    if res is None:
        res = ipaddress.ip_network(to_unicode(address), strict=strict)
        to_ip_network.res_cache[key] = res
    return res


@static_vars(
    classA=ipaddress.IPv4Network((u"10.0.0.0", u"255.0.0.0")),
    classB=ipaddress.IPv4Network((u"172.16.0.0", u"255.240.0.0")),
    classC=ipaddress.IPv4Network((u"192.168.0.0", u"255.255.0.0")),
    res_cache=dict())
def is_private_ip(address):
    """ check if ip address is class A, B or C """
    res = is_private_ip.res_cache.get(address)
    if res is None:
        if not isinstance(address, ipaddress.IPv4Address):
            ip_address = to_ip_address(to_unicode(address))
        else:
            ip_address = address
        res = ip_address in is_private_ip.classA or ip_address in is_private_ip.classB or ip_address in is_private_ip.classC
        is_private_ip.res_cache[address] = res
    return res


@static_vars(
    classA=ipaddress.IPv4Network((u"10.0.0.0", u"255.0.0.0")),
    classB=ipaddress.IPv4Network((u"172.16.0.0", u"255.240.0.0")),
    classC=ipaddress.IPv4Network((u"192.168.0.0", u"255.255.0.0")),
    res_cache=dict())
def is_private_network(address):
    """ check if network is class A, B or C """
    res = is_private_network.res_cache.get(address)
    if res is None:
        if not isinstance(address, ipaddress.IPv4Network):
            net = to_ip_network(to_unicode(address))
        else:
            net = address
        res = net.subnet_of(is_private_network.classA) or net.subnet_of(is_private_network.classB) or net.subnet_of(is_private_network.classC)
        is_private_network.res_cache[address] = res
    return res


@static_vars(
    ip_broadcast=ipaddress.IPv4Address((u"255.255.255.255")),
    net_multicast=ipaddress.IPv4Network((u"224.0.0.0", u"255.255.255.0")),
    res_cache=dict())
def is_ip_broadcast(address):
    """ check if ip address is ip broadcast address """
    res = is_ip_broadcast.res_cache.get(address)
    if res is None:
        if not isinstance(address, ipaddress.IPv4Address):
            ip_address = to_ip_address(to_unicode(address))
        else:
            ip_address = address
        res = ip_address == is_ip_broadcast.ip_broadcast or ip_address in is_ip_broadcast.net_multicast
        is_ip_broadcast.res_cache[address] = res
    return res


@static_vars(re_cache=None)
def is_fqdn(address):
    """ check if address is a fqdn address """
    if is_fqdn.re_cache is None:
        is_fqdn.re_cache = re.compile(r'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]\.)+[a-zA-Z]{2,63}$)')
    return is_fqdn.re_cache.match(address) is not None


def resolve_hostname(address, dns_servers=None):
    """ get ip for hostname """
    if dns_servers is None:
        try:
            resolved_ip = socket.gethostbyname(address)
            return resolved_ip
        except socket.gaierror:
            pass
        msg = "Unable to resolve: {0}".format(address)
    else:
        error = None
        try:
            res = resolver.Resolver()
            res.timeout = 15
            res.lifetime = 15
            res.nameservers = dns_servers
            answers = res.query(address)
            if answers:
                return answers[0].address
        except exception.Timeout:
            error = 'timeout'

        msg = "Unable to resolve: {0} using {1} dns servers".format(address, ','.join(dns_servers))
        if error is not None:
            msg += ' ({0})'.format(error)

    raise AssertionError(msg)


def is_valid_ip(address):
    """ validate ip address format """
    try:
        to_ip_address(to_unicode(address))
        return True
    except ValueError:
        return False
    return False


def is_valid_port(port):
    """ validate port format """
    if not port.isdigit():
        return False

    nport = int(port)
    return nport >= 0 and nport <= 65535


def is_valid_port_range(port_range):
    """ validate port range format """
    group = re.match(r'^(\d+)-(\d+)$', port_range)
    if not group:
        return False
    nport1 = int(group.group(1))
    nport2 = int(group.group(2))

    return nport1 >= 0 and nport1 <= 65535 and nport2 >= 0 and nport2 <= 65535


def is_valid_network(address):
    """ validate network address format """
    try:
        to_ip_network(to_unicode(address))
        return True
    except ValueError:
        return False
    return False


def rule_product_dict(tab, rule, field, out_field=None):
    """ Return cartesian product between rule[field] and tab as dicts """
    if field not in rule:
        return tab
    if not out_field:
        out_field = field
    out = []
    for new_val in rule[field].split():
        for existing_val in tab:
            obj = deepcopy(existing_val)
            obj[out_field] = new_val
            out.append(obj)

    return out


def rule_product_ports(rule, field, field_port):
    """ Return cartesian product between rule[field] and field_port as string """
    if field_port not in rule:
        return rule[field]

    aliases = rule[field].split()
    ports = rule[field_port].split()
    ret = []
    for alias in aliases:
        added = False
        for port in ports:
            if port:
                ret.append(alias + ":" + port)
                added = True
        if not added:
            ret.append(alias)

    return ' '.join(list(ret))


class PFSenseHostAlias(object):
    """ Class holding structured pfsense host alias definition """
    def __init__(self):
        self.name = None
        self.descr = None
        self.definition = []
        self.ips = []
        self.networks = []
        self.dns = None
        self.fake = False

        # define all interfaces on which the alias may be defined as a local source
        # interfaces['gw_poc1_1'] = ['lan', 'obs']
        self.local_interfaces = {}

        # define all interfaces on which the alias may be defined as a routed source
        self.routed_interfaces = {}

        self._computed = False

    def __str__(self):
        return "name={0}, descr={1}, definition={2}, ips={3}, networks={4}, local_interfaces={5}, routed_interfaces={6}, fake={7}".format(
            self.name, self.descr, self.definition, self.ips, self.networks, self.local_interfaces, self.routed_interfaces, self.fake)

    def compute_any(self, data):
        """ Do all computations for object 'any' """
        # we add all interfaces of all pfsenses
        for pfsense in data.pfsenses_obj.values():
            for interface in pfsense.interfaces.values():
                self.local_interfaces[pfsense.name].append(interface.name)
                self.routed_interfaces[pfsense.name].append(interface.name)

    def compute_all(self, data):
        """ Do all computations """
        if not self._computed:
            self._computed = True
            if self.name != 'any':
                self.compute_addresses(data)
                self.compute_local_interfaces(data)
                self.compute_routed_interfaces(data)

    def compute_addresses(self, data):
        """ Convert all aliases to structured ip addresses or networks """

        todo = []
        todo.extend(self.definition)

        while todo:
            address = todo.pop()

            # special case when (self) is used in nat rules
            if address == '':
                continue

            # it's an ip address
            try:
                host_ip = to_ip_address(to_unicode(address))
                self.ips.append(host_ip)
                continue
            except ValueError:
                pass

            # it's an ip network
            try:
                net = to_ip_network(to_unicode(address))
                self.networks.append(net)
                continue
            except ValueError:
                pass

            # it's a fqdn
            if address not in data.all_aliases:
                if is_fqdn(address):
                    resolved_ip = resolve_hostname(address, self.dns)
                    host_ip = to_ip_address(to_unicode(resolved_ip))
                    self.ips.append(host_ip)
                    continue

                raise AssertionError("Invalid address: " + address + " for " + self.name)

            # it's another alias
            alias = data.hosts_aliases_obj.get(address)
            if alias is not None:
                if not alias._computed:
                    alias.compute_all(data)
                self.ips += alias.ips
                self.networks += alias.networks
                continue

            todo.extend(data.all_aliases[address]['ip'].split())

    def _is_in_networks(self, interface, fcheckname):
        """ check if an alias is in a network of an interface """
        fcheck = getattr(interface, fcheckname)
        for alias_ip in self.ips:
            if is_ip_broadcast(alias_ip):
                continue

            if not fcheck(alias_ip):
                return False

        for alias_net in self.networks:
            if not fcheck(alias_net):
                return False
        return True

    def is_in_local_network(self, interface):
        """ check if an alias is in the local network of an interface """
        return self._is_in_networks(interface, 'local_network_contains')

    def is_in_remote_networks(self, interface):
        """ check if an alias is in the remote networks of an interface """
        return self._is_in_networks(interface, 'remote_networks_contains')

    def is_in_adjacent_networks(self, interface):
        """ check if an alias is in the adjacent networks of an interface """
        return self._is_in_networks(interface, 'adjacent_networks_contains')

    def compute_routed_interfaces(self, data):
        """ Find all interfaces on all pfsense where the alias may be used as a routed source """
        for pfsense in data.pfsenses_obj.values():
            # if the target alias is local, we does not consider the other interfaces
            self.routed_interfaces[pfsense.name] = set()

            if pfsense.name in self.local_interfaces:
                continue

            for alias_ip in self.ips:
                interfaces = pfsense.interfaces_remote_networks_contains(alias_ip)
                self.routed_interfaces[pfsense.name].update(interfaces)

            for alias_net in self.networks:
                interfaces = pfsense.interfaces_remote_networks_contains(alias_net)
                self.routed_interfaces[pfsense.name].update(interfaces)

    def compute_local_interfaces(self, data):
        """ Find all interfaces on all pfsense where the alias may be used as a local source """
        for pfsense in data.pfsenses_obj.values():
            self.local_interfaces[pfsense.name] = set()
            for alias_ip in self.ips:
                interfaces = pfsense.interfaces_local_networks_contains(alias_ip)
                self.local_interfaces[pfsense.name].update(interfaces)

            for alias_net in self.networks:
                interfaces = pfsense.interfaces_local_networks_contains(alias_net)
                self.local_interfaces[pfsense.name].update(interfaces)

    def is_whole_local(self, pfsense):
        """ check if all ips/networks match a local network interface in pfense """
        for alias_ip in self.ips:
            if is_ip_broadcast(alias_ip):
                continue

            if not pfsense.any_local_network_contains(alias_ip):
                return False

        for alias_net in self.networks:
            if not pfsense.any_local_network_contains(alias_net):
                return False

        return True

    def routed_by_interfaces(self, pfsense, use_remote_networks=True):
        """ return all interfaces for which all ips/networks match a adjacent/remote network in pfense """

        all_interfaces = set()

        # we always search threw all interfaces to handle cases with internet
        for alias_ip in self.ips:
            interfaces = pfsense.interfaces_adjacent_or_remote_networks_contains(alias_ip, use_remote_networks=True)
            interfaces = pfsense.hack_internet_routing(interfaces, alias_ip, use_remote_networks=True)
            all_interfaces.update(interfaces)

        for alias_net in self.networks:
            interfaces = pfsense.interfaces_adjacent_or_remote_networks_contains(alias_net, use_remote_networks=True)
            interfaces = pfsense.hack_internet_routing(interfaces, alias_net, use_remote_networks=True)
            all_interfaces.update(interfaces)

        # if we didn't want the remote interfaces, we only keep the adjacents
        if not use_remote_networks:
            interfaces = set()
            for interface in all_interfaces:
                if self.is_in_adjacent_networks(pfsense.interfaces[interface]):
                    interfaces.add(interface)
            all_interfaces = interfaces

        return all_interfaces

    def is_adjacent_or_remote(self, pfsense):
        """ check if all ips/networks are in a adjacent/remote network in pfense """
        return len(self.routed_by_interfaces(pfsense, use_remote_networks=True)) > 0

    def is_adjacent(self, pfsense):
        """ check if all ips/networks are in a adjacent network in pfense """
        return len(self.routed_by_interfaces(pfsense, use_remote_networks=False)) > 0

    def is_ip_broadcast(self):
        """ check if an alias is the ip_broadcast """
        if len(self.ips) != 1 or self.networks:
            return False
        return is_ip_broadcast(self.ips[0])

    def is_whole_in_pfsense(self, pfsense):
        """ check if all ips/networks have as least one interface in pfense """
        if self.name in pfsense.is_whole_in_pfsense_cache:
            return pfsense.is_whole_in_pfsense_cache[self.name]

        for alias_ip in self.ips:
            if is_ip_broadcast(alias_ip):
                pfsense.is_whole_in_pfsense_cache[self.name] = False
                return False

            if not pfsense.any_network_contains(alias_ip):
                pfsense.is_whole_in_pfsense_cache[self.name] = False
                return False

        for alias_net in self.networks:
            if not pfsense.any_network_contains(alias_net):
                pfsense.is_whole_in_pfsense_cache[self.name] = False
                return False

        pfsense.is_whole_in_pfsense_cache[self.name] = True
        return True

    def is_whole_not_in_pfsense(self, pfsense):
        """ check if all ips/networks have as least one interface in pfense """
        if self.name in pfsense.is_whole_not_in_pfsense_cache:
            return pfsense.is_whole_not_in_pfsense_cache[self.name]

        for alias_ip in self.ips:
            if is_ip_broadcast(alias_ip):
                pfsense.is_whole_not_in_pfsense_cache[self.name] = False
                return False
            if pfsense.any_network_contains(alias_ip):
                pfsense.is_whole_not_in_pfsense_cache[self.name] = False
                return False

        for alias_net in self.networks:
            if pfsense.any_network_contains(alias_net):
                pfsense.is_whole_not_in_pfsense_cache[self.name] = False
                return False

        pfsense.is_whole_not_in_pfsense_cache[self.name] = True
        return True

    def is_whole_in_same_routing_ifaces(self, pfsense):
        """ check if all ips/networks have the same interfaces in pfense """
        if self.name in pfsense.is_whole_in_same_routing_ifaces_cache:
            return pfsense.is_whole_in_same_routing_ifaces_cache[self.name]

        # we loop threw all ips/networks in the alias
        # if there is any difference in the interfaces where the address need to be defined
        # then we return False so the parent function split the alias
        target_ar_interfaces = None
        target_local_interfaces = None

        for alias_ip in self.ips:
            interfaces = pfsense.interfaces_adjacent_or_remote_networks_contains(alias_ip)
            interfaces = pfsense.hack_internet_routing(interfaces, alias_ip)
            if target_ar_interfaces is None:
                target_ar_interfaces = interfaces
            elif target_ar_interfaces ^ interfaces:
                pfsense.is_whole_in_same_routing_ifaces_cache[self.name] = False
                return False

            interfaces = pfsense.interfaces_local_networks_contains(alias_ip)
            interfaces = pfsense.hack_internet_routing(interfaces, alias_ip)
            if target_local_interfaces is None:
                target_local_interfaces = interfaces
            elif target_local_interfaces ^ interfaces:
                pfsense.is_whole_in_same_routing_ifaces_cache[self.name] = False
                return False

        for alias_net in self.networks:
            interfaces = pfsense.interfaces_adjacent_or_remote_networks_contains(alias_net)
            interfaces = pfsense.hack_internet_routing(interfaces, alias_net)
            if target_ar_interfaces is None:
                target_ar_interfaces = interfaces
            elif target_ar_interfaces ^ interfaces:
                pfsense.is_whole_in_same_routing_ifaces_cache[self.name] = False
                return False

            interfaces = pfsense.interfaces_local_networks_contains(alias_net)
            interfaces = pfsense.hack_internet_routing(interfaces, alias_net)
            if target_local_interfaces is None:
                target_local_interfaces = interfaces
            elif target_local_interfaces ^ interfaces:
                pfsense.is_whole_in_same_routing_ifaces_cache[self.name] = False
                return False

        pfsense.is_whole_in_same_routing_ifaces_cache[self.name] = True
        return True

    def match_local_interface_ip(self, pfsense):
        """ Return True if the alias ip match one interface on the pfsense """
        for alias_ip in self.ips:
            for iface in pfsense.interfaces.values():
                for local_ip in iface.local_ips:
                    if alias_ip == local_ip:
                        return True
        return False


class PFSenseRule(object):
    """ Class holding structured pfsense rule declaration """
    def __init__(self):
        self.name = None
        self.separator = None
        self.src = []
        self.src_port = []
        self.dst = []
        self.dst_port = []
        self.src_nat = []
        self.dst_nat = []
        self.dst_nat_port = []
        self.protocol = []
        self.action = "pass"
        self.options = dict()
        self.floating = False
        self.force = False
        self.asymmetric = False
        self.invert_dst = False
        self.invert_src = False

        self.sub_rules = []
        self.interfaces = None
        self.generated_names = {}

    def get_option(self, name):
        """ return option value for name """
        if name in self.options:
            return self.options[name]
        separator = self.separator
        while separator is not None:
            if separator.options is not None and name in separator.options:
                return separator.options[name]
            separator = separator.parent
        return None

    def to_json(self):
        """ return JSON String containing rule """
        srcs = []
        for src in self.src:
            srcs.append(src.name)

        dsts = []
        for dst in self.dst:
            dsts.append(dst.name)

        res = self.name + ": { src: " + " ".join(srcs) + ", dst: " + " ".join(dsts)

        if self.src_port:
            res += ", src_port: " + " ".join(self.src_port)

        if self.dst_port:
            res += ", dst_port: " + " ".join(self.dst_port)

        if self.protocol:
            res += ", protocol: " + " ".join(self.protocol)

        if self.action != "pass":
            res += ", action: " + " ".join(self.action)

        for field in OUTPUT_OPTION_FIELDS:
            value = self.get_option(field)
            if value is not None:
                res += ', {0}: {1}'.format(field, value)

        res += " }"
        return res


class PFSenseRuleSeparator(object):
    """ Class holding structured pfsense rule separator declaration """
    def __init__(self):
        self.name = None
        self.interface = None
        self.parent = None
        self.options = None

    def __hash__(self):
        return hash(self.name + self.interface)

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.name == other.name and self.interface == other.interface


class PFSenseInterface(object):
    """ Class holding structured pfsense interface definition """
    def __init__(self):
        self.name = None
        self.local_ip = None        # first ip defined
        self.local_network = None   # first network defined
        self.local_ips = set()
        self.local_networks = set()
        self.remote_networks = set()
        self.adjacent_networks = set()
        self.tags = set()
        self.bridge = False
        self._remote_networks_contains_cache = dict()
        self._adjacent_networks_contains_cache = dict()

    @staticmethod
    def _networks_contains(address, networks):
        """ return true if address is into networks """
        if isinstance(address, ipaddress.IPv4Address):
            private_address = is_private_ip(address)
            for snet in networks:
                private_net = is_private_network(snet)
                if private_address and private_net or not private_address and not private_net:
                    if address in snet:
                        return True
        elif isinstance(address, ipaddress.IPv4Network):
            private_address = is_private_network(address)
            for snet in networks:
                private_net = is_private_network(snet)
                if private_address and private_net or not private_address and not private_net:
                    if address.subnet_of(snet):
                        return True
        else:
            raise AssertionError('wrong type in remote_networks_contains:' + type(address))
        return False

    def remote_networks_contains(self, address):
        """ return true if address is defined in remote_networks of this interface """
        res = self._remote_networks_contains_cache.get(address)
        if res is None:
            res = self._networks_contains(address, self.remote_networks)
            self._remote_networks_contains_cache[address] = res
        return res

    def adjacent_networks_contains(self, address):
        """ return true if address is defined in adjacent_networks of this interface """
        res = self._adjacent_networks_contains_cache.get(address)
        if res is None:
            res = self._networks_contains(address, self.adjacent_networks)
            self._adjacent_networks_contains_cache[address] = res
        return res

    def local_network_contains(self, address):
        """ return true if address is in the local network of this interface """
        if self.local_networks:
            for local_network in self.local_networks:
                if isinstance(address, ipaddress.IPv4Address):
                    private_address = is_private_ip(address)
                    private_net = is_private_network(local_network)
                    if private_address and private_net or not private_address and not private_net:
                        if address in local_network:
                            return True
                elif isinstance(address, ipaddress.IPv4Network):
                    private_address = is_private_network(address)
                    private_net = is_private_network(local_network)
                    if private_address and private_net or not private_address and not private_net:
                        if address.subnet_of(local_network):
                            return True
                else:
                    raise AssertionError('wrong type in local_network_contains:' + type(address))
        return False

    def are_in_same_network(self, src, dst):
        """ return true if both the aliases are in the same network on the interface """
        def _match(snet, alias):
            for ip in alias.ips:
                if ip not in snet:
                    return False
            for net in alias.networks:
                if not net.subnet_of(snet):
                    return False
            return True

        for snet in self.local_networks:
            if _match(snet, src) and _match(snet, dst):
                return True
        return False


class PFSense(object):
    """ Class holding structured pfsense definition """
    def __init__(self, name, interfaces):
        self.name = name
        self.interfaces = interfaces
        self.is_whole_in_pfsense_cache = dict()
        self.is_whole_not_in_pfsense_cache = dict()
        self.is_whole_in_same_routing_ifaces_cache = dict()
        self._interfaces_local_networks_contains_cache = dict()
        self._interfaces_remote_networks_contains_cache = dict()
        self._interfaces_adjacent_networks_contains_cache = dict()
        self._hack_internet_routing_cache = dict()

    def any_adjacent_networks_contains(self, address):
        """ return true if address is defined in adjacent_networks of any interface """
        return len(self.interfaces_adjacent_networks_contains(address)) != 0

    def any_remote_networks_contains(self, address):
        """ return true if address is defined in remote_networks of any interface """
        return len(self.interfaces_remote_networks_contains(address)) != 0

    def any_local_network_contains(self, address):
        """ return true if address is defined in local network of any interface """
        return len(self.interfaces_local_networks_contains(address)) != 0

    def any_network_contains(self, address):
        """ return true if address is defined in the local, remote or adjacent networks of any interface """
        return self.any_local_network_contains(address) or self.any_remote_networks_contains(address) or self.any_adjacent_networks_contains(address)

    def _interfaces_network_contains(self, address, networks_name):
        """ return interfaces names where address is in the interface network  """
        res = set()
        if isinstance(address, ipaddress.IPv4Address):
            private_address = is_private_ip(address)
            for interface in self.interfaces.values():
                networks = getattr(interface, networks_name)
                if networks is not None:
                    if not isinstance(networks, set):
                        networks = [networks]
                    for snet in networks:
                        private_net = is_private_network(snet)
                        if private_address and private_net or not private_address and not private_net:
                            if address in snet:
                                res.add(interface.name)
        elif isinstance(address, ipaddress.IPv4Network):
            private_address = is_private_network(address)
            for interface in self.interfaces.values():
                networks = getattr(interface, networks_name)
                if networks is not None:
                    if not isinstance(networks, set):
                        networks = [networks]
                    for snet in networks:
                        private_net = is_private_network(snet)
                        if private_address and private_net or not private_address and not private_net:
                            if address.subnet_of(snet):
                                res.add(interface.name)
        else:
            raise AssertionError('wrong type in _interfaces_network_contains:' + type(address))
        return res

    def interfaces_local_networks_contains(self, address):
        """ return interfaces names where address is in the interface local network  """
        res = self._interfaces_local_networks_contains_cache.get(address)
        if res is None:
            res = self._interfaces_network_contains(address, 'local_networks')
            self._interfaces_local_networks_contains_cache[address] = res
        return copy(res)

    def interfaces_remote_networks_contains(self, address):
        """ return interfaces names where address is in the interface remote networks  """
        res = self._interfaces_remote_networks_contains_cache.get(address)
        if res is None:
            res = self._interfaces_network_contains(address, 'remote_networks')
            self._interfaces_remote_networks_contains_cache[address] = res
        return copy(res)

    def interfaces_adjacent_networks_contains(self, address):
        """ return interfaces names where address is in the interface adjacent networks  """
        res = self._interfaces_adjacent_networks_contains_cache.get(address)
        if res is None:
            res = self._interfaces_network_contains(address, 'adjacent_networks')
            self._interfaces_adjacent_networks_contains_cache[address] = res
        return copy(res)

    def interfaces_adjacent_or_remote_networks_contains(self, address, use_remote_networks=True):
        """ return interfaces names where address are in the interface local or remote networks """
        res = self.interfaces_adjacent_networks_contains(address)
        if use_remote_networks:
            res.update(self.interfaces_remote_networks_contains(address))
        return res

    @static_vars(internet=ipaddress.IPv4Network((u"0.0.0.0", u"0.0.0.0")))
    def hack_internet_routing(self, interfaces, address, use_remote_networks=True):
        """ internet (defined as route to 0.0.0.0/0) is an issue to automaticly detect interfaces on which routing is done because every host or network match.
            if multiple interfaces can be used and there is at least one specific route which match the address,
            we consider the internet ones as mistakes and remove them """
        key = str(interfaces) + str(address) + str(use_remote_networks)
        res = self._hack_internet_routing_cache.get(key)
        if res is None:
            has_non_internet = False
            internet_interfaces = set()
            is_net = isinstance(address, ipaddress.IPv4Network)
            for interface in interfaces:
                route_found = False
                internet_found = False
                if use_remote_networks:
                    for network in self.interfaces[interface].remote_networks:
                        if network == self.hack_internet_routing.internet:
                            internet_found = True
                        elif is_net and address.overlaps(network) or not is_net and address in network:
                            route_found = True

                for network in self.interfaces[interface].adjacent_networks:
                    if network == self.hack_internet_routing.internet:
                        internet_found = True
                    elif is_net and address.overlaps(network) or not is_net and address in network:
                        route_found = True

                if route_found:
                    has_non_internet = True
                elif internet_found:
                    internet_interfaces.add(interface)

            if has_non_internet:
                interfaces -= internet_interfaces
            self._hack_internet_routing_cache[key] = interfaces
            res = interfaces

        return copy(res)


class PFSenseData(object):
    """ Class holding all data """

    def __init__(self, hosts_aliases, ports_aliases, pfsenses, rules, target_name, gendiff=False, debug=None, aggregate=True):
        self._hosts_aliases = hosts_aliases
        self._ports_aliases = ports_aliases
        self._pfsenses = pfsenses
        self._rules = rules
        self._rules_separators = list()
        self._target_name = target_name
        self._rules_obj = OrderedDict()
        self._pfsenses_obj = {}
        self._hosts_aliases_obj = OrderedDict()
        self._target = None
        self._errors = []
        self.log_errors = False
        self.gendiff = gendiff
        self.debug = debug
        self.aggregate = aggregate
        self._all_aliases = copy(self._hosts_aliases)
        self._all_aliases.update(self._ports_aliases)

    @property
    def all_aliases(self):
        """ all_aliases getter """
        return self._all_aliases

    @property
    def hosts_aliases(self):
        """ hosts_aliases getter """
        return self._hosts_aliases

    @property
    def hosts_aliases_obj(self):
        """ hosts_aliases_obj getter """
        return self._hosts_aliases_obj

    @property
    def ports_aliases(self):
        """ ports_aliases getter """
        return self._ports_aliases

    @property
    def pfsenses(self):
        """ pfsenses getter """
        return self._pfsenses

    @property
    def pfsenses_obj(self):
        """ pfsenses_obj getter """
        return self._pfsenses_obj

    @property
    def rules_obj(self):
        """ rules_obj getter """
        return self._rules_obj

    @property
    def rules(self):
        """ rules getter """
        return self._rules

    @property
    def rules_separators(self):
        """ rules_separators getter """
        return self._rules_separators

    @property
    def target_name(self):
        """ target_name getter """
        return self._target_name

    @property
    def target(self):
        """ target getter """
        return self._target

    @target.setter
    def target(self, target):
        """ target setter """
        self._target = target

    @property
    def errors(self):
        """ errors getter """
        return self._errors

    def set_error(self, error):
        """ add an error """
        display.error(error)
        self._errors.append(error)

    @staticmethod
    def is_child_def(values):
        """ check if values contains more definitions """
        for value in values.values():
            if isinstance(value, (OrderedDict, dict, list)):
                return False
        return True

    def unalias_ip(self, alias):
        """ expand alias to it's ip definition """
        ret = []
        todo = []
        todo.extend(alias.split())

        while todo:
            elts = todo.pop()
            if elts in self._all_aliases:
                todo.extend(self._all_aliases[elts]['ip'].split())
            else:
                ret.append(elts)

        return ret

    def get_hosts_alias(self, hosts, ips, networks, _basename):
        """ return an alias with all the hosts
            create it if required """

        searched = ips.union(networks)
        for alias in self._hosts_aliases_obj.values():
            alias_ips = set(alias.ips).union(set(alias.networks))
            if not alias_ips ^ searched:
                return alias

        obj = PFSenseHostAlias()
        obj.definition = list(hosts)
        obj.definition.sort()
        obj.ips = list(ips)
        obj.networks = list(networks)
        obj.fake = False

        # alias can only be 32 chars long so we truncate a bit if required
        basename = _basename[0:26]
        idx = 1
        while True:
            obj.name = 'h_{0}_{1}'.format(basename, idx)
            if obj.name not in self._all_aliases:
                break
            idx = idx + 1

        self._hosts_aliases_obj[obj.name] = obj

        alias = dict()
        alias['ip'] = ' '.join(obj.definition)
        alias['type'] = 'network'
        self._all_aliases[obj.name] = alias

        return obj

    def get_ports_alias(self, ports, _basename):
        """ return an alias with all the ports
            create it if required """

        for name, alias in self._ports_aliases.items():
            alias_ports = set(alias['port'].split())
            if not alias_ports ^ ports:
                return name

        # alias can only be 32 chars long so we truncate a bit if required
        basename = _basename[0:26]
        idx = 1
        while True:
            name = 'p_{0}_{1}'.format(basename, idx)
            if name not in self._all_aliases:
                break
            idx = idx + 1

        alias = dict()
        alias['descr'] = name
        sorted_ports = list(ports)
        sorted_ports.sort()
        alias['port'] = ' '.join(sorted_ports)
        self._all_aliases[name] = alias
        self._ports_aliases[name] = alias

        return name


class PFSenseDataParser(object):
    """ Class doing all data checks and pfsense objects generation """

    def __init__(self, data):
        self._data = data

    @staticmethod
    def check_alias_name(name):
        """ check an alias name """
        # todo: check reserved keywords (any, self, ...)
        if re.match('^[a-zA-Z0-9_]+$', name) is None:
            raise AnsibleError(name + ': the name of the alias may only consist of the characters "a-z, A-Z, 0-9 and _"')

    def parse_host_alias(self, obj, src_name, type_name, name, allow_any, dns_servers=None):
        """ Parse an host alias definition """
        ret = True
        value = obj[src_name]
        values = str(value).split()
        if not values:
            self._data.set_error("Empty " + src_name + " field for " + type_name + " " + name)
            return False

        # we check that all exists
        ip_defs = 0
        net_defs = 0
        fqdn_defs = 0
        other_defs = 0
        for value in values:
            if is_valid_ip(value):
                if value not in self._data.hosts_aliases_obj:
                    self._data.hosts_aliases_obj[value] = self.create_obj_host_alias(value)
                ip_defs = ip_defs + 1
                continue

            if is_valid_network(value):
                if value not in self._data.hosts_aliases_obj:
                    self._data.hosts_aliases_obj[value] = self.create_obj_host_alias(value)
                net_defs = net_defs + 1
                continue

            if value not in self._data.hosts_aliases and (value != 'any' or not allow_any):
                if is_fqdn(value):
                    if value not in self._data.hosts_aliases_obj:
                        self._data.hosts_aliases_obj[value] = self.create_obj_host_alias(value, dns_servers)
                    fqdn_defs = fqdn_defs + 1
                    continue

                self._data.set_error(value + " is not a valid alias, ip address or network in " + type_name + " " + name)
                ret = False
            other_defs = other_defs + 1

        if fqdn_defs and (ip_defs + net_defs + other_defs) > 0:
            self._data.set_error("fqdn definitions can't be mixed with aliases, IP or networks addresses (in " + type_name + " " + name + ")")
            ret = False

        # if it's a real alias, we must check for mixed network definitions
        if not allow_any:
            if net_defs > 0:
                if net_defs != len(values):
                    self._data.set_error("mixed network definitions and aliases or IP addresses in " + type_name + " " + name)
                    ret = False
                else:
                    obj['type'] = 'network'
            else:
                obj['type'] = 'host'

        return ret

    def parse_hosts_aliases(self):
        """ Parse all hosts aliases definitions """
        dups = {}
        ret = True
        for name, alias in self._data.hosts_aliases.items():
            self.check_alias_name(name)

            # ip field is mandatory
            if 'ip' not in alias and 'host' not in alias:
                self._data.set_error("No ip or host field for alias " + name)
                ret = False
                continue

            # we check that all fields are valid
            for field in alias:
                if field not in ['ip', 'host', 'descr', 'dns', 'ignore_dup']:
                    self._data.set_error(field + " is not a valid field name in alias " + name)
                    ret = False

            dns_servers = None
            if 'dns' in alias:
                dns_servers = alias['dns'].split()

            # we check that all ip exist and are not empty
            if not self.parse_host_alias(alias, 'ip', 'alias', name, False, dns_servers):
                ret = False
                continue

            # we check for duplicates
            _alias = deepcopy(alias)
            if 'descr' in _alias:
                del _alias['descr']
            dup = json.dumps(_alias)
            if dup in dups:
                display.warning("duplicate alias definition for ip " + alias['ip'] + " (" + dups[dup] + ", " + name + ")")
            elif 'ignore_dup' not in alias:
                dups[dup] = name

            obj = PFSenseHostAlias()
            obj.name = name
            obj.definition = alias['ip'].split()
            if 'descr' in alias:
                obj.descr = alias['descr']
            obj.dns = dns_servers
            self._data.hosts_aliases_obj[obj.name] = obj

        return ret

    def check_port_alias(self, ports, src_name, type_name, name):
        """ Checking a port alias definition """
        ret = True
        values = str(ports).split()
        if src_name == 'dst_nat_port':
            if '-' in ports:
                self._data.set_error("There must be only one port in dst_nat_port of " + name)
                return False

            if len(values) > 1:
                self._data.set_error("There must be only one port in {0} of {1}".format(src_name, name))
                return False

        if not values:
            self._data.set_error("Empty " + src_name + " field for " + type_name + " " + name)
            return False

        # we check that all exists
        for value in values:
            if not is_valid_port(value) and not is_valid_port_range(value) and value not in self._data.ports_aliases:
                self._data.set_error(value + " is not a valid alias, port or port range in " + type_name + " " + name)
                ret = False

        return ret

    def parse_ports_aliases(self):
        """ Checking all ports alias definitions """
        dups = {}
        ret = True
        for name, alias in self._data.ports_aliases.items():
            self.check_alias_name(name)

            # port field is mandatory
            if 'port' not in alias:
                self._data.set_error("No port field for alias " + name)
                ret = False
                continue

            if not isinstance(alias['port'], str):
                alias['port'] = str(alias['port'])

            # we check that all ip exist and are not empty
            if not self.check_port_alias(alias['port'], 'port', 'alias', name):
                ret = False
                continue

            # we check that all fields are valid
            for field in alias:
                if field != 'port' and field != 'descr':
                    self._data.set_error(field + " is not a valid field name in alias " + name)
                    ret = False

            # we check for duplicates
            _alias = deepcopy(alias)
            if 'descr' in _alias:
                del _alias['descr']
            dup = json.dumps(_alias)
            if dup in dups:
                display.warning("duplicate alias definition for port " + alias['port'] + " (" + dups[dup] + ", " + name + ")")
            else:
                dups[dup] = name

        return ret

    def create_obj_any_alias(self):
        """ Create a PFSenseHostAlias object for address any (for easier processing later) """
        obj = PFSenseHostAlias()
        obj.name = 'any'
        obj.definition = ['any']
        obj.fake = True
        obj.compute_any(self._data)

        self._data.all_aliases['any'] = {}
        self._data.all_aliases['any']['ip'] = '0.0.0.0/0'
        self._data.all_aliases['any']['type'] = 'network'

        return obj

    def create_obj_host_alias(self, src, dns_servers=None):
        """ Create a PFSenseHostAlias object from address (for easier processing later) """
        obj = PFSenseHostAlias()
        obj.name = src
        obj.definition = [src]
        obj.fake = True
        obj.dns = dns_servers
        if src == 'any':
            return self.create_obj_any_alias()

        return obj

    def create_obj_rule_from_def(self, name, rule, separator):
        """ Create a PFSenseRule object from yaml definition """
        def _get_bool(field):
            field_value = False
            if isinstance(rule[field], bool):
                field_value = rule[field]
            elif isinstance(rule[field], str):
                if rule[field].lower() in ['yes', 'true']:
                    field_value = True
                elif rule[field].lower() not in ['no', 'false']:
                    self._data.set_error('{0} must be yes/no or true/false (got "{1}")'.format(field, rule[field]))
            return field_value

        obj = PFSenseRule()
        obj.name = name
        obj.separator = separator

        if 'src_port' in rule:
            if not isinstance(rule['src_port'], str):
                obj.src_port = str(rule['src_port'])
            else:
                obj.src_port = rule['src_port'].split()

        if 'dst_port' in rule:
            if not isinstance(rule['dst_port'], str):
                obj.dst_port = str(rule['dst_port'])
            else:
                obj.dst_port = rule['dst_port'].split()

        if 'dst_nat_port' in rule:
            if not isinstance(rule['dst_nat_port'], str):
                obj.dst_nat_port = str(rule['dst_nat_port'])
            else:
                obj.dst_nat_port = rule['dst_nat_port'].split()

        if 'protocol' in rule:
            obj.protocol = rule['protocol'].split()

        if 'action' in rule:
            obj.action = rule['action']

        for field in OPTION_FIELDS:
            if field in rule:
                obj.options[field] = rule[field]

        if 'force' in rule:
            obj.force = _get_bool('force')
            if obj.force and not (obj.get_option('filter') and obj.get_option('ifilter')):
                self._data.set_error('force must not be used without filter and ifilter')

        if 'floating' in rule:
            obj.floating = _get_bool('floating')

        if 'quick' in rule and not obj.floating:
            self._data.set_error('Quick must only be used with floating rules')

        for src in rule['src'].split():
            if src not in self._data.hosts_aliases_obj:
                self._data.hosts_aliases_obj[src] = self.create_obj_host_alias(src)
            target = self._data.hosts_aliases_obj[src]
            obj.src.append(target)

        for dst in rule['dst'].split():
            if dst not in self._data.hosts_aliases_obj:
                self._data.hosts_aliases_obj[dst] = self.create_obj_host_alias(dst)
            target = self._data.hosts_aliases_obj[dst]
            obj.dst.append(target)

        if 'src_nat' in rule:
            src = rule['src_nat']
            if src not in self._data.hosts_aliases_obj:
                self._data.hosts_aliases_obj[src] = self.create_obj_host_alias(src)
            target = self._data.hosts_aliases_obj[src]
            obj.src_nat.append(target)

        if 'dst_nat' in rule:
            dst = rule['dst_nat']
            if dst not in self._data.hosts_aliases_obj:
                self._data.hosts_aliases_obj[dst] = self.create_obj_host_alias(dst)
            target = self._data.hosts_aliases_obj[dst]
            obj.dst_nat.append(target)

        if 'asymmetric' in rule:
            obj.asymmetric = _get_bool('asymmetric')

        if 'invert_src' in rule:
            obj.invert_src = _get_bool('invert_src')
            if not obj.force:
                self._data.set_error('invert_src must be used with force (for now)')

        if 'invert_dst' in rule:
            obj.invert_dst = _get_bool('invert_dst')
            if not obj.force:
                self._data.set_error('invert_dst must be used with force (for now)')

        return obj

    def parse_rules(self, parent=None, parent_separator=None):
        """ Parse all rules definitions """
        ret = True
        if parent is None:
            parent = self._data.rules
        if parent_separator is None:
            parent_separator = PFSenseRuleSeparator()

        for name, rule in parent.items():
            # not a rule
            if rule is None:
                continue
            if not self._data.is_child_def(rule):
                separator = PFSenseRuleSeparator()
                separator.parent = parent_separator
                if parent_separator.name is None or not parent_separator.name:
                    separator.name = name
                else:
                    separator.name = parent_separator.name + ' - ' + name
                self._data.rules_separators.append(separator)
                if not self.parse_rules(rule, separator):
                    ret = False
                continue
            if name == 'options':
                parent_separator.options = rule
                if parent_separator.options and parent_separator.options.get('invisible'):
                    if parent_separator.name is None or not parent_separator.name:
                        parent_separator.name = ''
                    else:
                        parent_separator.name = parent_separator.parent.name
                continue

            for field in ['src', 'dst']:
                # src and dst field are mandatory
                if field not in rule:
                    self._data.set_error("No {0} field for rule {1}".format(field, name))
                    ret = False
                    continue

                # we check that all exist and are not empty
                if not self.parse_host_alias(rule, field, 'rule', name, True):
                    ret = False

            for field in ['src_nat', 'dst_nat']:
                if field not in rule:
                    continue
                if len(rule[field].split()) > 1:
                    self._data.set_error('There must be only one address in {0} field of {1}'.format(field, name))
                    ret = False
                    continue

                if field == 'src_nat' and rule['src_nat'] == '(self)':
                    rule['src_nat'] = ''
                    continue

                # we check that all exist and are not empty
                if not self.parse_host_alias(rule, field, 'rule', name, True):
                    ret = False

            # checking ports
            for field in ['src_port', 'dst_port', 'dst_nat_port']:
                if field in rule:
                    if not isinstance(rule[field], str):
                        rule[field] = str(rule[field])

                    if not self.check_port_alias(rule[field], field, 'rule', name) or not self.check_tcp_udp(rule, name):
                        ret = False

            if 'dst_nat_port' in rule and 'dst_nat' not in rule:
                self._data.set_error('dst_nat_port field is set on {0} without any dst_nat target'.format(name))
                ret = False
                continue

            if 'dst_nat' in rule and 'dst_nat_port' not in rule:
                self._data.set_error('dst_nat field is set on {0} without any dst_nat_port target'.format(name))
                ret = False
                continue

            # we check that all fields are valid
            valid_fields = ['src', 'dst', 'src_port', 'dst_port', 'protocol', 'action', 'floating', 'force']
            valid_fields.extend(['src_nat', 'dst_nat', 'dst_nat_port', 'asymmetric', 'invert_dst', 'invert_src'])
            valid_fields.extend(OPTION_FIELDS)
            for field in rule:
                if field not in valid_fields:
                    self._data.set_error(field + " is not a valid field name in rule " + name)
                    ret = False

            if name in self._data.rules_obj:
                display.warning("Rule already defined: {0}".format(name))

            self._data.rules_obj[name] = self.create_obj_rule_from_def(name, rule, parent_separator)

        if self._data.errors:
            return False

        return ret

    def parse_target_name(self):
        """ Parse target's name definition """
        if self._data.target_name not in self._data.pfsenses:
            self._data.set_error(self._data.target_name + " does not exist in pfsenses section")
            return False
        self._data.target = self._data.pfsenses_obj[self._data.target_name]
        return True

    def check_tcp_udp(self, rule, name):
        """ check if protocol is valid when ports are sets """
        if 'protocol' not in rule:
            return True
        protocols = str(rule['protocol']).split()
        for protocol in protocols:
            if protocol != 'udp' and protocol != 'tcp' and protocol != 'tcp/udp':
                self._data.set_error(protocol + " protocol used with src_port or dst_port in rule " + name)
                return False
        return True

    def check_pfsense_interfaces_objs(self, interfaces, name):
        """ Checking all interfaces networks between them """
        for src_name, src in interfaces.items():
            for dst_name, dst in interfaces.items():
                if src_name != dst_name and src.local_networks and dst.local_networks:
                    for src_network in src.local_networks:
                        for dst_network in dst.local_networks:
                            if src_network.overlaps(dst_network):
                                self._data.set_error("Local networks of " + src_name + " and " + dst_name + " overlap in " + name)
                                return False

        return True

    def create_pfsenses_aliases(self):
        """ Generate usefull aliases for pfsenses """
        def _warn_alias(alias):
            if len(alias) >= 32:
                display.warning("Autogenerated alias {0} is too long and will trigger an error if used".format(alias))

        # if pf_paris has lan and wan interfaces declared, we will generate
        # - pf_paris_ips with all its ips
        # - pf_paris_nets with all its subnets

        # - pf_paris_lan_ips and pf_paris_wan_ips containing pf_paris lan and wan ips (respectivly)
        # - pf_paris_lan_nets and pf_paris_wan_nets containing pf_paris lan and wan subnets (respectivly)

        # - all_lan_ips and all_wan_ips containing all pfsenses lan and wan ips (respectivly)
        # - all_lan_nets and all_wan_nets containing all pfsenses lan and wan subnets (respectivly)

        # if lan has a tag named 'voip':
        # - pf_paris_voip_ips containing pf_paris lan ips
        # - pf_paris_voip_nets containing pf_paris lan subnets
        # - all_voip_ips containing all pfsenses ips of interfaces with tag voip
        # - all_voip_nets containing all pfsenses subnets of interfaces with tag voip

        # - all_pfsenses_ips containing all pfsenses ips
        # - all_pfsenses_nets containing all pfsenses subnets

        # all_pfsenses
        all_pfsenses_definition = list()

        # all_lan, all_wan
        all_pfsenses_interfaces_definition = dict()

        # all_pfsenses_nets
        net_all_pfsenses_definition = list()

        # all_lan_nets, all_wan_nets
        net_all_pfsenses_interfaces_definition = dict()

        for name, pfsense in self._data.pfsenses.items():

            # maybe do some options for this
            ipext = '_ips'
            netext = '_nets'

            # interfaces field is mandatory
            if 'interfaces' not in pfsense:
                continue

            # pf_paris_ips
            pfsense_definition = list()

            # pf_paris_nets
            net_pfsense_definition = list()

            # pf_paris_lan_ips, pf_paris_tag_ips
            interfaces_definition = dict()

            # pf_paris_lan_nets, pf_paris_tag_nets
            net_interfaces_definition = dict()

            for iname, interface in pfsense['interfaces'].items():
                if 'ip' not in interface:
                    continue

                if 'id' in interface and interface.get('id'):
                    interface_id = str(interface['id'])
                else:
                    interface_id = iname

                # get the tags
                tags = list()
                tags.append(interface_id)
                if 'tags' in interface:
                    for tag in sorted(interface['tags'].split()):
                        if tag not in tags:
                            tags.append(tag)

                # pf_paris_lan_ips, pf_paris_wan_ips
                interface_definition = list()

                # pf_paris_lan_nets, pf_paris_wan_nets
                net_interface_definition = list()

                # get the ips and networks
                for ip in interface['ip'].split():
                    try:
                        local_network = to_ip_network(to_unicode(ip), False)
                        str_net = str(local_network)
                        net_interface_definition.append(str_net)
                    except ValueError:
                        # we will fail later
                        pass

                    group = re.match(r'([^\/]*)\/(\d+)', ip)
                    try:
                        if group:
                            ip = to_ip_address(to_unicode(group.group(1)))
                            str_ip = str(ip)
                            interface_definition.append(str_ip)
                    except ValueError:
                        # we will fail later
                        pass

                # interface ip alias
                if interface_definition:
                    for idx, tag in enumerate(tags):
                        interface_definition_name = name + '_' + tag + ipext

                        ikey = 'all_' + tag + ipext
                        if ikey not in all_pfsenses_interfaces_definition:
                            all_pfsenses_interfaces_definition[ikey] = list()
                        if interface_definition_name not in all_pfsenses_interfaces_definition[ikey]:
                            all_pfsenses_interfaces_definition[ikey].append(interface_definition_name)

                        if idx == 0:
                            # we only add the interface and not all the tags in the pfsense_definition
                            pfsense_definition.append(interface_definition_name)
                            interface_definition.sort()

                        if interface_definition_name not in interfaces_definition:
                            interfaces_definition[interface_definition_name] = list()
                        interfaces_definition[interface_definition_name].extend(interface_definition)

                # interface network alias
                if net_interface_definition:
                    for idx, tag in enumerate(tags):
                        interface_definition_name = name + '_' + tag + netext

                        ikey_net = 'all_' + tag + netext
                        if ikey_net not in net_all_pfsenses_interfaces_definition:
                            net_all_pfsenses_interfaces_definition[ikey_net] = list()
                        if interface_definition_name not in net_all_pfsenses_interfaces_definition[ikey_net]:
                            net_all_pfsenses_interfaces_definition[ikey_net].append(interface_definition_name)

                        if idx == 0:
                            # we only add the interface and not all the tags in the pfsense_definition
                            net_pfsense_definition.append(interface_definition_name)
                            net_interface_definition.sort()

                        if interface_definition_name not in net_interfaces_definition:
                            net_interfaces_definition[interface_definition_name] = list()
                        net_interfaces_definition[interface_definition_name].extend(net_interface_definition)

            # pf_paris_lan_ips, pf_paris_tag_ips
            for interface_definition_name in sorted(interfaces_definition.keys()):
                interface_definition = interfaces_definition[interface_definition_name]
                interface_definition = list(dict.fromkeys(interface_definition))
                interface_definition.sort()

                alias = dict()
                alias['ip'] = ' '.join(interface_definition)
                alias['ignore_dup'] = True
                self._data.all_aliases[interface_definition_name] = alias
                self._data.hosts_aliases[interface_definition_name] = alias
                _warn_alias(interface_definition_name)

            # pf_paris_lan_nets, pf_paris_tag_nets
            for interface_definition_name in sorted(net_interfaces_definition.keys()):
                net_interface_definition = net_interfaces_definition[interface_definition_name]
                net_interface_definition = list(dict.fromkeys(net_interface_definition))
                net_interface_definition.sort()

                alias = dict()
                alias['ip'] = ' '.join(net_interface_definition)
                alias['ignore_dup'] = True
                self._data.all_aliases[interface_definition_name] = alias
                self._data.hosts_aliases[interface_definition_name] = alias
                _warn_alias(interface_definition_name)

            # pfsense ip alias
            if pfsense_definition:
                pfsense_definition.sort()
                all_pfsenses_definition.append(name + ipext)

                alias = dict()
                alias['ip'] = ' '.join(pfsense_definition)
                alias['ignore_dup'] = True
                self._data.all_aliases[name + ipext] = alias
                self._data.hosts_aliases[name + ipext] = alias
                _warn_alias(name + ipext)

            # pfsense network alias
            if net_pfsense_definition:
                net_pfsense_definition.sort()
                net_all_pfsenses_definition.append(name + netext)

                alias = dict()
                alias['ip'] = ' '.join(net_pfsense_definition)
                alias['ignore_dup'] = True
                self._data.all_aliases[name + netext] = alias
                self._data.hosts_aliases[name + netext] = alias
                _warn_alias(name + netext)

        # generate interfaces groups ip aliases
        for name in sorted(all_pfsenses_interfaces_definition.keys()):
            definition = all_pfsenses_interfaces_definition[name]
            definition.sort()

            alias = dict()
            alias['ip'] = ' '.join(definition)
            alias['ignore_dup'] = True
            self._data.all_aliases[name] = alias
            self._data.hosts_aliases[name] = alias
            _warn_alias(name)

        # generate interfaces groups network aliases
        for name in sorted(net_all_pfsenses_interfaces_definition.keys()):
            definition = net_all_pfsenses_interfaces_definition[name]
            definition.sort()

            alias = dict()
            alias['ip'] = ' '.join(definition)
            alias['ignore_dup'] = True
            self._data.all_aliases[name] = alias
            self._data.hosts_aliases[name] = alias
            _warn_alias(name)

        # generate all ip aliases
        all_pfsenses_definition.sort()

        alias = dict()
        alias['ip'] = ' '.join(all_pfsenses_definition)
        alias['ignore_dup'] = True
        self._data.all_aliases['all_pfsenses' + ipext] = alias
        self._data.hosts_aliases['all_pfsenses' + ipext] = alias

        # generate all network aliases
        net_all_pfsenses_definition.sort()

        alias = dict()
        alias['ip'] = ' '.join(net_all_pfsenses_definition)
        alias['ignore_dup'] = True
        self._data.all_aliases['all_pfsenses' + netext] = alias
        self._data.hosts_aliases['all_pfsenses' + netext] = alias

    def parse_pfsense_interfaces(self, pfsense, name):
        """ Parse all pfsense interfaces definitions """
        ret = {}
        ids = set()
        for iname, interface in pfsense['interfaces'].items():
            # extracting & checking local network
            local_ips = set()
            local_networks = set()
            first_local_ip = None
            first_local_network = None

            tags = set()
            tags.add(iname)
            if 'tags' in interface:
                for tag in interface['tags'].split():
                    tags.add(tag)

            for key in interface:
                if key not in ['adjacent_networks', 'remote_networks', 'ip', 'tags', 'id']:
                    self._data.set_error("Invalid field " + key + " in " + iname + " of " + name)
                    return {}

            if 'id' in interface and interface.get('id'):
                interface_id = str(interface['id'])
            else:
                interface_id = iname

            if interface_id in ids:
                self._data.set_error("Duplicate interface id " + interface_id + " in " + iname + " of " + name)
                return {}
            ids.add(interface_id)

            if 'ip' in interface:
                for ip in interface['ip'].split():
                    try:
                        local_network = to_ip_network(to_unicode(ip), False)
                        if first_local_network is None:
                            first_local_network = local_network
                    except ValueError:
                        self._data.set_error("Invalid network " + ip + " in " + name)
                        return {}

                    if local_network.prefixlen == 32:
                        self._data.set_error("Invalid network prefix length for network " + ip + " in " + name)
                        return {}

                    # extracting & checking ip
                    group = re.match(r'([^\/]*)\/(\d+)', ip)
                    try:
                        local_ip = to_ip_address(to_unicode(group.group(1)))
                        if first_local_ip is None:
                            first_local_ip = local_ip
                    except ValueError:
                        self._data.set_error("Invalid ip " + ip + " in " + name)
                        return {}
                    local_ips.add(local_ip)
                    local_networks.add(local_network)

            # extracting & checking remote networks
            remote_networks = set()
            if 'remote_networks' in interface:
                networks = self._data.unalias_ip(interface['remote_networks'])
                for network in networks:
                    try:
                        remote_networks.add(to_ip_network(to_unicode(network)))
                    except ValueError:
                        self._data.set_error("Invalid network " + network + " in remote_networks of " + name)
                        return {}

            # extracting & checking adjacent networks
            adjacent_networks = set()
            if 'adjacent_networks' in interface:
                networks = self._data.unalias_ip(interface['adjacent_networks'])
                for network in networks:
                    try:
                        adjacent_networks.add(to_ip_network(to_unicode(network)))
                    except ValueError:
                        self._data.set_error("Invalid network " + network + " in adjacent_networks of " + name)
                        return {}

            obj = PFSenseInterface()
            obj.name = iname
            obj.local_ip = first_local_ip
            obj.local_network = first_local_network
            obj.local_ips = local_ips
            obj.local_networks = local_networks
            obj.bridge = (interface.get('bridge'))
            obj.remote_networks = remote_networks
            obj.adjacent_networks = adjacent_networks
            obj.tags = tags
            ret[iname] = obj

        if not self.check_pfsense_interfaces_objs(ret, name):
            ret = {}

        return ret

    def parse_pfsenses(self):
        """ Checking all pfsenses definitions """
        dups = {}
        ret = True
        for name, pfsense in self._data.pfsenses.items():
            # interfaces field is mandatory
            if 'interfaces' not in pfsense:
                self._data.set_error("No interfaces field for pfsense " + name)
                ret = False
                continue

            if not pfsense['interfaces']:
                self._data.set_error("Empty interfaces field for pfsense " + name)
                ret = False
                continue

            interfaces = self.parse_pfsense_interfaces(pfsense, name)
            # checking interfaces
            if not interfaces:
                ret = False
                continue

            # we check that all fields are valid
            for field in pfsense:
                if field != 'interfaces':
                    self._data.set_error(field + " is not a valid field name in pfsense " + name)
                    ret = False

            # we check for duplicates
            _pfsense = deepcopy(pfsense)
            if 'descr' in _pfsense:
                del _pfsense['descr']
            dup = json.dumps(_pfsense)
            if dup in dups:
                display.warning("duplicate pfsense definition for ip " + pfsense['ip'] + " (" + dups[dup] + ", " + name + ")")
            else:
                dups[dup] = name

            obj = PFSense(name, interfaces)
            self._data.pfsenses_obj[obj.name] = obj

        return ret

    def parse_hosts_aliases_objs(self):
        """ Checking all host alias objs, addresses and finding pfsenses interfaces """
        for obj in self._data.hosts_aliases_obj.values():
            obj.compute_all(self._data)

        return True

    def parse(self):
        """ Check and parse everything """
        ret = True
        self.create_pfsenses_aliases()
        ret = ret and self.parse_hosts_aliases()
        ret = ret and self.parse_ports_aliases()
        ret = ret and self.parse_rules()
        ret = ret and self.parse_pfsenses()
        ret = ret and self.parse_target_name()
        ret = ret and self.parse_hosts_aliases_objs()

        return ret


class PFSenseRuleDecomposer(object):
    """ Class decomposing rules into smaller rules (more suited to pfsense logic ) """

    def __init__(self, data):
        self._data = data

    def host_separate(self, host):
        """ separate aliases to remove mixed configuration
        where there is a local and remote network/ip is the host
        host is expanded to sub-aliases if required """
        ret = []
        if host.is_whole_not_in_pfsense(self._data.target):
            if self._data.debug is not None and self._data.debug == host.name:
                display.warning('{0}: is_whole_not_in_pfsense {1}'.format(host.name, self._data.target.name))

            ret.append(host)
        elif host.is_whole_in_pfsense(self._data.target):
            if self._data.debug is not None and self._data.debug == host.name:
                display.warning('{0}: is_whole_in_pfsense {1}'.format(host.name, self._data.target.name))

            ret.append(host)
        elif host.is_ip_broadcast():
            if self._data.debug is not None and self._data.debug == host.name:
                display.warning('{0}: is_ip_broadcast'.format(host.name))
            ret.append(host)
        else:
            alias = self._data.all_aliases[host.name]
            if 'ip' in alias:
                for alias_ip in alias['ip'].split():
                    ret_n = self.host_separate(self._data.hosts_aliases_obj[alias_ip])
                    if self._data.debug is not None and self._data.debug == host.name:
                        display.warning('{0}: host_separate: {1}'.format(host.name, ret_n))
                    ret.extend(ret_n)

        return ret

    def host_separate_by_iface(self, host):
        """ separate aliases to remove mixed configuration
        where there is a local and remote network/ip is the host
        host is expanded to sub-aliases if required """
        ret = []
        if host.is_whole_in_same_routing_ifaces(self._data.target):
            if self._data.debug is not None and self._data.debug == host.name:
                display.warning('{0}: is_whole_in_same_routing_ifaces {1}'.format(host.name, self._data.target.name))
            ret.append(host)
        else:
            alias = self._data.all_aliases[host.name]
            if 'ip' in alias:
                for alias_ip in alias['ip'].split():
                    ret_n = self.host_separate_by_iface(self._data.hosts_aliases_obj[alias_ip])
                    if self._data.debug is not None and self._data.debug == host.name:
                        display.warning('{0}: host_separate_by_iface: {1}'.format(host.name, ret_n))
                    ret.extend(ret_n)

        return ret

    def separate_aliases(self, rule, field, attr, func):
        """ Separate aliases from field using func, setting new aliases in attr """
        sub_rules = []
        function = getattr(self, func)
        src_sep = function(field)
        if len(src_sep) > 1:
            for src in src_sep:
                new_rule = deepcopy(rule)
                setattr(new_rule, attr, [src])
                sub_rules.append(new_rule)

        return sub_rules

    def decompose_rule(self, rule):
        """ Returns smaller rules from rule """
        # A PFSense rule can have only one src or dst
        blocking = rule.action != 'pass'

        sub_rules = []
        if len(rule.src) > 1 or len(rule.dst) > 1:
            for src in rule.src:
                for dst in rule.dst:
                    new_rule = deepcopy(rule)
                    new_rule.src = [src]
                    new_rule.dst = [dst]
                    sub_rules.append(new_rule)

            return sub_rules

        if len(rule.src) != 1 or len(rule.dst) != 1:
            raise AssertionError()

        # forced rules are generated
        if rule.force:
            return []

        src = rule.src[0]
        dst = rule.dst[0]

        # if it's blocking or reject rule, we don't split the destination
        # since only we only need the source to know how to define the rule
        sub_rules = self.separate_aliases(rule, src, 'src', 'host_separate')
        if not blocking and not sub_rules:
            sub_rules = self.separate_aliases(rule, dst, 'dst', 'host_separate')
        if not sub_rules:
            sub_rules = self.separate_aliases(rule, src, 'src', 'host_separate_by_iface')
        if not blocking and not sub_rules:
            sub_rules = self.separate_aliases(rule, dst, 'dst', 'host_separate_by_iface')

        return sub_rules

    def decompose_rules(self):
        """ Returns smaller rules (more suited to pfsense logic ) """
        for rule in self._data.rules_obj.values():
            todo = []
            todo.append(rule)
            while todo:
                obj = todo.pop()
                res = self.decompose_rule(obj)
                if not res:
                    rule.sub_rules.append(obj)
                else:
                    todo.extend(res)


class PFSenseAliasFactory(object):
    """ Class generating aliases definitions """

    def __init__(self, data):
        self._data = data

    def add_host_alias_rec(self, alias, aliases):
        """ set aliases hosts names to define (recursive) """
        if ':' in alias.name:
            return

        name = alias.name
        aliases[name] = self._data.all_aliases[name]
        for target in alias.definition:
            obj = self._data.hosts_aliases_obj[target]
            if obj.fake:
                continue
            self.add_host_alias_rec(obj, aliases)

    def add_port_alias_rec(self, alias, aliases):
        """ Return aliases ports names to define (recursive) """
        if alias in self._data.all_aliases:
            if alias not in aliases:
                aliases[alias] = self._data.all_aliases[alias]

            if 'port' in aliases[alias]:
                for port in aliases[alias]['port'].split():
                    self.add_port_alias_rec(port, aliases)

    def add_hosts_aliases(self, rule, aliases):
        """ Return aliases hosts names to define """
        for rule_aliases in [rule.src, rule.dst, rule.src_nat, rule.dst_nat]:
            for alias in rule_aliases:
                if alias.fake:
                    continue
                self.add_host_alias_rec(alias, aliases)

    def add_ports_aliases(self, rule, aliases):
        """ Return aliases ports names to define """
        for alias in rule.src_port:
            self.add_port_alias_rec(alias, aliases)

        for alias in rule.dst_port:
            self.add_port_alias_rec(alias, aliases)

    def generate_aliases(self, rule_filter=None):
        """ Return aliases definitions for pfsense_aggregate """

        hosts_aliases = {}
        ports_aliases = {}

        for name, rule in self._data.rules_obj.items():
            if rule_filter is not None and name != rule_filter:
                continue
            for subrule in rule.sub_rules:
                if not subrule.interfaces:
                    continue
                self.add_hosts_aliases(subrule, hosts_aliases)
                self.add_ports_aliases(subrule, ports_aliases)

        ret = []
        for name, alias in hosts_aliases.items():
            definition = {}
            definition['name'] = name
            definition['type'] = alias['type']
            definition['address'] = ' '.join(alias['ip'].split())
            definition['state'] = 'present'
            if 'descr' in alias:
                definition['descr'] = alias['descr']
            else:
                definition['descr'] = ''
            definition['detail'] = ''
            ret.append(definition)

        for name, alias in ports_aliases.items():
            definition = {}
            definition['name'] = name
            definition['type'] = 'port'
            definition['address'] = ' '.join(alias['port'].replace('-', ':').split())
            definition['state'] = 'present'
            if 'descr' in alias:
                definition['descr'] = alias['descr']
            else:
                definition['descr'] = ''
            definition['detail'] = ''
            ret.append(definition)

        return ret

    @staticmethod
    def output_aliases(aliases):
        """ Output aliases definitions for pfsense_aggregate """
        print("          #===========================")
        print("          # Hosts & network aliases")
        print("          # ")
        definitions = list()
        for alias in aliases:
            if alias['type'] == 'port':
                continue
            definition = "          - { name: \"" + alias['name'] + "\", type: \"" + alias['type'] + "\", address: \""
            definition += ' '.join(alias['address'].split()) + "\""
            if 'descr' in alias:
                definition = definition + ", descr: \"" + alias['descr'] + "\""
            definition = definition + ", state: \"present\" }"
            definitions.append(definition)
        definitions.sort()
        print('\n'.join(definitions))

        print("          #===========================")
        print("          # ports aliases")
        print("          # ")
        definitions = list()
        for alias in aliases:
            if alias['type'] != 'port':
                continue
            definition = "          - { name: \"" + alias['name'] + "\", type: \"port\", address: \"" + ' '.join(alias['address'].split()) + "\""
            if 'descr' in alias:
                definition = definition + ", descr: \"" + alias['descr'] + "\""
            definition = definition + ", state: \"present\" }"
            definitions.append(definition)
        definitions.sort()
        print('\n'.join(definitions))


class PFSenseRuleFactory(object):
    """ Class generating rules definitions """

    def __init__(self, data, display_warnings=True):
        self._data = data
        self._decomposer = PFSenseRuleDecomposer(data)
        self._display_warnings = display_warnings

    def rule_interfaces_any(self, rule_obj):
        """ Return interfaces set on which the rule is needed to be defined
            Manage rules with any src or dst """

        src = rule_obj.src[0]
        dst = rule_obj.dst[0]

        # if rule is forced, we return the interface defined
        if rule_obj.force:
            return set(rule_obj.get_option('ifilter').split())

        if src.name == 'any' and dst.name == 'any':
            # we return all interfaces of target
            return set(self._data.target.interfaces.keys())
        elif src.name == 'any':
            # if the destination is local, we return all interfaces of target
            if dst.is_whole_local(self._data.target):
                return set(self._data.target.interfaces.keys())

            # otherwise we return all interfaces of target if the destination is adjacent/remote
            # (we must be able to reach the destination to allow any src to access it)
            for iface, interface in self._data.target.interfaces.items():
                if dst.is_in_adjacent_networks(interface) or dst.is_in_remote_networks(interface):
                    return set(self._data.target.interfaces.keys())
            return set()

        elif rule_obj.dst[0].name == 'any':
            # we allow the interfaces matching the source ip/networks
            # or the adjacent/remote networks
            interfaces = set()
            for iface, interface in self._data.target.interfaces.items():
                if src.is_in_local_network(interface) or src.is_in_adjacent_networks(interface) or src.is_in_remote_networks(interface):
                    interfaces.add(iface)
            if self._data.debug is not None and self._data.debug == rule_obj.name:
                display.warning('{0}: to_any_dst interfaces={1}'.format(rule_obj.name, interfaces))

            return interfaces
        return None

    def rule_interfaces_ip_broadcast(self, rule_obj):
        """ Return interfaces set on which the rule is needed to be defined
            Manage rules with src or dst ip broadcast """
        src = rule_obj.src[0]
        dst = rule_obj.dst[0]
        src_is_bcast = src.is_ip_broadcast()
        dst_is_bcast = dst.is_ip_broadcast()
        if not src_is_bcast and not dst_is_bcast:
            return None

        if src_is_bcast and rule_obj.dst[0].is_whole_local(self._data.target):
            return rule_obj.dst[0].local_interfaces[self._data.target.name] | rule_obj.dst[0].routed_interfaces[self._data.target.name]

        if dst_is_bcast and rule_obj.src[0].is_whole_local(self._data.target):
            return rule_obj.src[0].local_interfaces[self._data.target.name] | rule_obj.src[0].routed_interfaces[self._data.target.name]

        # we return no rules for:
        # - broadcast to broadcast
        # - broadcast to remote
        # - remote to broadcast
        return []

    def bridged_by_interfaces(self, routing_interfaces, dst):
        """ if all the routing_interfaces are bridged and the destinations are on local bridges too
            return the destination bridges """
        for iface in routing_interfaces:
            if not self._data.target.interfaces[iface].bridge:
                return None

        if self._data.target.name in dst.local_interfaces:
            for iface in dst.local_interfaces[self._data.target.name]:
                if not self._data.target.interfaces[iface].bridge:
                    return None
        else:
            return None

        return dst.local_interfaces[self._data.target.name]

    def rule_interfaces(self, rule_obj):
        """ Return interfaces list on which the rule is needed to be defined """
        def filter_interfaces(interfaces):
            if interface_filter is not None:
                return interface_filter & interfaces
            return interfaces

        # if the rule has a filter, apply it
        rule_filter = rule_obj.get_option('filter')
        if rule_filter and self._data.target.name not in rule_filter.split():
            return set()

        # if the rule has a efilter, apply it
        rule_efilter = rule_obj.get_option('efilter')
        if rule_efilter and self._data.target.name in rule_efilter.split():
            return set()

        interface_filter = rule_obj.get_option('ifilter')
        if interface_filter is not None:
            interface_filter = set(interface_filter.split())

        if len(rule_obj.src) != 1 or len(rule_obj.dst) != 1:
            raise AssertionError()

        if self._data.debug is not None and self._data.debug == rule_obj.name:
            display.warning('{0}: src={1} dst={2}'.format(rule_obj.name, rule_obj.src[0].name, rule_obj.dst[0].name))

        # if the rule uses 'any'
        interfaces = self.rule_interfaces_any(rule_obj)
        if interfaces is not None:
            return filter_interfaces(interfaces)

        # if the rule uses broadcasts
        interfaces = self.rule_interfaces_ip_broadcast(rule_obj)
        if interfaces is not None:
            return filter_interfaces(interfaces)

        interfaces = set()
        src_is_local = rule_obj.src[0].is_whole_local(self._data.target)
        dst_is_local = rule_obj.dst[0].is_whole_local(self._data.target)

        if self._data.debug is not None and self._data.debug == rule_obj.name:
            display.warning('{0}: src_is_local={1} dst_is_local={2}'.format(rule_obj.name, src_is_local, dst_is_local))

        # if it's a blocking or reject rule, we only use the src
        if rule_obj.action != 'pass':
            if src_is_local:
                interfaces = rule_obj.src[0].local_interfaces[self._data.target.name]
            else:
                interfaces = rule_obj.src[0].routed_by_interfaces(self._data.target, True)

            return filter_interfaces(interfaces)

        # if source and dst are local, return the local interface
        if src_is_local and dst_is_local:
            if len(rule_obj.src[0].local_interfaces[self._data.target.name]) != 1:
                raise AssertionError(
                    'Invalid local interfaces count for {0}: {1}'
                    .format(rule_obj.name, len(rule_obj.src[0].local_interfaces[self._data.target.name])))
            if len(rule_obj.dst[0].local_interfaces[self._data.target.name]) != 1:
                raise AssertionError(
                    'Invalid local interfaces count for {0}: {1}'
                    .format(rule_obj.name, len(rule_obj.dst[0].local_interfaces[self._data.target.name])))

            # if they are both on the same interface, we dont need any rule when:
            # - the interface is not a bridge
            # - src and dst are in the same network on the interface
            # - the pfsense is not the source/destination of the rule
            src_interface = ''.join(rule_obj.src[0].local_interfaces[self._data.target.name])
            dst_interface = ''.join(rule_obj.dst[0].local_interfaces[self._data.target.name])
            if (src_interface == dst_interface and
                    not self._data.target.interfaces[src_interface].bridge and
                    self._data.target.interfaces[src_interface].are_in_same_network(rule_obj.src[0], rule_obj.dst[0])):
                if not rule_obj.src[0].match_local_interface_ip(self._data.target) and not rule_obj.dst[0].match_local_interface_ip(self._data.target):
                    return set()

            return filter_interfaces(rule_obj.src[0].local_interfaces[self._data.target.name])

        # if the destination is unreachable
        if not dst_is_local and src_is_local and not rule_obj.dst[0].is_adjacent_or_remote(self._data.target):
            if self._display_warnings:
                display.warning(
                    'Destination {0} is not accessible from this pfSense for {1}.Please add the right adjacent/remote network if it\'s not an error'
                    .format(rule_obj.dst[0].name, rule_obj.name))
            return set()

        # if the source is unreachable
        if not src_is_local and dst_is_local and not rule_obj.src[0].is_adjacent_or_remote(self._data.target):
            if self._display_warnings:
                display.warning(
                    'Source {0} can not access to this pfSense for {1}. Please add the right adjacent/remote network if it\'s not an error'
                    .format(rule_obj.src[0].name, rule_obj.name))
            return set()

        # we add all the interfaces the source can use to go out
        if self._data.target.name in rule_obj.src[0].local_interfaces:
            interfaces.update(rule_obj.src[0].local_interfaces[self._data.target.name])

        # we add interfaces the source can use to get in
        if not src_is_local:
            src_is_adjacent = rule_obj.src[0].is_adjacent(self._data.target)
            routing_interfaces = rule_obj.src[0].routed_by_interfaces(self._data.target, not src_is_adjacent)

            if self._data.debug is not None and self._data.debug == rule_obj.name:
                display.warning('{0}: src_is_adjacent={1}, routing_interfaces={2}, src={3}'.format(
                    rule_obj.name, src_is_adjacent, routing_interfaces, rule_obj.src[0].name))

            # if they are both not local and on the same interfaces or with an unreachable destination
            # we return nothing
            if not dst_is_local:
                dst_is_adjacent = rule_obj.dst[0].is_adjacent(self._data.target)

                # if the source is remote and the destination is adjacent, we return the source interfaces
                if not src_is_adjacent and dst_is_adjacent:
                    if self._data.debug is not None and self._data.debug == rule_obj.name:
                        display.warning(
                            '{0}: dst_is_adjacent={1}, routing_interfaces={2}, dst={3}'.format(
                                rule_obj.name, dst_is_adjacent, filter_interfaces(routing_interfaces), rule_obj.dst[0].name))
                    return filter_interfaces(routing_interfaces)

                # if the source is an adjacent networks, it can get out to reach remote networks
                dst_routing_interfaces = rule_obj.dst[0].routed_by_interfaces(self._data.target, src_is_adjacent)
                if self._data.debug is not None and self._data.debug == rule_obj.name:
                    display.warning('{0}: dst_is_adjacent={1}, dst_routing_interfaces={2}, dst={3}'.format(
                        rule_obj.name, dst_is_adjacent, dst_routing_interfaces, rule_obj.dst[0].name))

                # if the source is adjacent and the destination is remote, we return the source interfaces
                if src_is_adjacent and len(dst_routing_interfaces):
                    return filter_interfaces(routing_interfaces)

                routing_interfaces = routing_interfaces.difference(dst_routing_interfaces)
                if not routing_interfaces or not dst_routing_interfaces:
                    return set()

            # if the interfaces we would use are bridged, and the destinations are on local bridges too
            # we declare the rule on the destination bridges since packets would come from there
            bridge_interfaces = self.bridged_by_interfaces(routing_interfaces, rule_obj.dst[0])
            if bridge_interfaces:
                interfaces.update(bridge_interfaces)
            else:
                interfaces.update(routing_interfaces)

        if not interfaces and (src_is_local or dst_is_local):
            msg = 'Invalid sub-rule interfaces count ({0}), src={1}, dst={2}'.format(len(interfaces), rule_obj.src[0].name, rule_obj.dst[0].name)
            raise AssertionError(msg)
        return filter_interfaces(interfaces)

    def generate_rule(self, name, rule_obj, interfaces, last_name):
        """ Generate rules definitions for rule """
        def _gen_rule_dict(rule_def, name, interface=None):
            if interface is None:
                interface = 'floating'
                floating = True
            else:
                floating = False
            definition = {}
            definition['name'] = name
            definition['action'] = rule_obj.action
            for field in OUTPUT_OPTION_FIELDS:
                value = rule_obj.get_option(field)
                if value is not None:
                    definition[field] = value

            if floating:
                definition['floating'] = 'yes'
                if 'direction' not in definition:
                    definition['direction'] = 'any'
                definition['interface'] = ','.join(rule_interfaces)
            else:
                definition['interface'] = interface

            definition['state'] = 'present'
            if interface in last_name and last_name[interface]:
                definition['after'] = last_name[interface]
            else:
                definition['after'] = 'top'

            if rule_obj.asymmetric:
                definition['statetype'] = 'sloppy state'
                definition['tcpflags_any'] = True

            definition.update(rule_def)
            interfaces[interface].append(definition)
            last_name[interface] = name

            if rule_obj.invert_src and 'source' in definition:
                definition['source'] = '!' + definition['source']

            if rule_obj.invert_dst and 'destination' in definition:
                definition['destination'] = '!' + definition['destination']

            if interface not in rule_obj.generated_names:
                rule_obj.generated_names[interface] = name

        def _gen_src_nat_rule_dict(rule_def, name, interface, src_nat):
            definition = {}
            definition['descr'] = '{0}_{1}'.format(name, interface)
            definition['interface'] = interface
            definition['state'] = 'present'
            definition['address'] = '{0}'.format(src_nat.name)
            definition.update(rule_def)
            for field in OUTPUT_SRC_NAT_OPTION_FIELDS:
                value = rule_obj.get_option(field)
                if value is not None:
                    definition[field] = value

            for field in ['source', 'destination']:
                key = field + '_port'
                if key in definition:
                    definition[field] = '{0}:{1}'.format(definition[field], definition[key])
                    del definition[key]

            interfaces[interface].append(definition)

        def _gen_dst_nat_rule_dict(rule_def, name, interface, dst_nat, dst_nat_port):
            definition = {}
            definition['descr'] = '{0}_{1}'.format(name, interface)
            definition['interface'] = interface
            definition['state'] = 'present'
            definition['target'] = '{0}:{1}'.format(dst_nat.name, dst_nat_port)
            definition.update(rule_def)
            for field in OUTPUT_DST_NAT_OPTION_FIELDS:
                value = rule_obj.get_option(field)
                if value is not None:
                    definition[field] = value

            if 'associated_rule' not in definition:
                definition['associated_rule'] = 'pass'

            for field in ['source', 'destination']:
                key = field + '_port'
                if key in definition:
                    definition[field] = '{0}:{1}'.format(definition[field], definition[key])
                    del definition[key]

            interfaces[interface].append(definition)

        base = []
        base.append({})

        if len(rule_obj.src) != 1 or len(rule_obj.dst) != 1:
            raise AssertionError()

        rule = {}
        rule['src'] = rule_obj.src[0].name
        rule['dst'] = rule_obj.dst[0].name
        if rule_obj.protocol:
            rule['protocol'] = ' '.join(rule_obj.protocol)

        if self._data.aggregate:
            if rule_obj.src_port:
                if len(rule_obj.src_port) == 1:
                    rule['src_port'] = ' '.join(rule_obj.src_port)
                else:
                    rule['src_port'] = self._data.get_ports_alias(set(rule_obj.src_port), name)
                    rule_obj.src_port = [rule['src_port']]

            if rule_obj.dst_port:
                if len(rule_obj.dst_port) == 1:
                    rule['dst_port'] = ' '.join(rule_obj.dst_port)
                else:
                    rule['dst_port'] = self._data.get_ports_alias(set(rule_obj.dst_port), name)
                    rule_obj.dst_port = [rule['dst_port']]

        else:
            if rule_obj.src_port:
                rule['src_port'] = ' '.join(rule_obj.src_port)
            if rule_obj.dst_port:
                rule['dst_port'] = ' '.join(rule_obj.dst_port)

        base = rule_product_dict(base, rule, 'src', 'source')
        base = rule_product_dict(base, rule, 'dst', 'destination')
        base = rule_product_dict(base, rule, 'protocol')
        base = rule_product_dict(base, rule, 'src_port', 'source_port')
        base = rule_product_dict(base, rule, 'dst_port', 'destination_port')

        if rule_obj.floating:
            rule_interfaces = list(rule_obj.interfaces)
            rule_interfaces.sort()
            if len(base) == 1:
                _gen_rule_dict(base[0], name)
            else:
                rule_idx = 1
                for rule_def in base:
                    rule_name = name + "_" + str(rule_idx)
                    _gen_rule_dict(rule_def, rule_name)
                    rule_idx = rule_idx + 1
        else:
            for interface in rule_obj.interfaces:
                if len(base) == 1:
                    if rule_obj.src_nat:
                        _gen_src_nat_rule_dict(base[0], name, interface, rule_obj.src_nat[0])

                    if rule_obj.dst_nat:
                        _gen_dst_nat_rule_dict(base[0], name, interface, rule_obj.dst_nat[0], rule_obj.dst_nat_port[0])

                    if not rule_obj.src_nat and not rule_obj.dst_nat:
                        _gen_rule_dict(base[0], name, interface)
                else:
                    rule_idx = 1
                    for rule_def in base:
                        rule_name = name + "_" + str(rule_idx)
                        if rule_obj.src_nat:
                            _gen_src_nat_rule_dict(rule_def, rule_name, interface, rule_obj.src_nat[0])

                        if rule_obj.dst_nat:
                            _gen_dst_nat_rule_dict(rule_def, rule_name, interface, rule_obj.dst_nat[0], rule_obj.dst_nat_port[0])

                        if not rule_obj.src_nat and not rule_obj.dst_nat:
                            _gen_rule_dict(rule_def, rule_name, interface)
                        rule_idx = rule_idx + 1

    def aggregate_subrules(self, rule, interfaces, subrules, sub_interfaces):
        """ aggregate generated subrules """
        def _get_same_rule(new_rules, src, dst):
            for rule in new_rules:
                if rule.src[0].name == src.name and rule.dst[0].name == dst.name:
                    return rule
            return None

        def _add_list(group, objs):
            for obj in objs:
                group.add(obj)

        def _aggregate_job(interface=None):
            # we create fake alias when required
            # we also use interfaces IP and NET when possible
            src = subrule.src[0]
            dst = subrule.dst[0]
            if len(src_group_name) != 1:
                src = self._data.get_hosts_alias(src_group_name, src_group_ip, src_group_net, rule.name)
            elif (not rule.src_nat and not rule.floating and len(subrule.src[0].networks) == 1 and
                  len(subrule.src[0].ips) == 0 and
                  subrule.src[0].networks[0] == self._data.target.interfaces[interface].local_network):
                src = deepcopy(subrule.src[0])
                src.name = "NET:{0}".format(interface)
            elif (not rule.src_nat and not rule.floating and len(subrule.src[0].networks) == 0 and
                  len(subrule.src[0].ips) == 1 and
                  subrule.src[0].ips[0] == self._data.target.interfaces[interface].local_ip):
                src = deepcopy(subrule.src[0])
                src.name = "IP:{0}".format(interface)

            if len(dst_group_name) != 1:
                dst = self._data.get_hosts_alias(dst_group_name, dst_group_ip, dst_group_net, rule.name)
            elif (not rule.src_nat and not rule.floating and len(subrule.dst[0].networks) == 1 and
                  len(subrule.dst[0].ips) == 0 and
                  subrule.dst[0].networks[0] == self._data.target.interfaces[interface].local_network):
                dst = deepcopy(subrule.dst[0])
                dst.name = "NET:{0}".format(interface)
            elif (not rule.src_nat and not rule.floating and len(subrule.dst[0].networks) == 0 and
                  len(subrule.dst[0].ips) == 1 and
                  subrule.dst[0].ips[0] == self._data.target.interfaces[interface].local_ip):
                dst = deepcopy(subrule.dst[0])
                dst.name = "IP:{0}".format(interface)

            # when aggregating, we merge rules with same src/dst
            existing_rule = _get_same_rule(new_rules, src, dst)
            if existing_rule is None:
                existing_rule = copy(subrule)
                existing_rule.src[0] = src
                existing_rule.dst[0] = dst
                existing_rule.interfaces = set()
                new_rules.append(existing_rule)

            if rule.floating:
                for sub_interface in sub_interfaces:
                    existing_rule.interfaces.add(sub_interface)
                    if sub_interface not in interfaces:
                        interfaces[sub_interface] = []
            else:
                existing_rule.interfaces.add(interface)

                if interface not in interfaces:
                    interfaces[interface] = []

        new_rules = list()
        if rule.floating:
            src_group_name = set()
            dst_group_name = set()
            src_group_ip = set()
            dst_group_ip = set()
            src_group_net = set()
            dst_group_net = set()
            subrule = None
            for interface in sorted(sub_interfaces):
                for subrule in sub_interfaces[interface]:
                    src_group_name.add(subrule.src[0].name)
                    dst_group_name.add(subrule.dst[0].name)
                    _add_list(src_group_ip, subrule.src[0].ips)
                    _add_list(src_group_net, subrule.src[0].networks)
                    _add_list(dst_group_ip, subrule.dst[0].ips)
                    _add_list(dst_group_net, subrule.dst[0].networks)
            _aggregate_job()
        else:
            for interface in sorted(sub_interfaces):
                src_group_name = set()
                dst_group_name = set()
                src_group_ip = set()
                dst_group_ip = set()
                src_group_net = set()
                dst_group_net = set()
                subrule = None
                for subrule in sub_interfaces[interface]:
                    src_group_name.add(subrule.src[0].name)
                    dst_group_name.add(subrule.dst[0].name)
                    _add_list(src_group_ip, subrule.src[0].ips)
                    _add_list(src_group_net, subrule.src[0].networks)
                    _add_list(dst_group_ip, subrule.dst[0].ips)
                    _add_list(dst_group_net, subrule.dst[0].networks)
                _aggregate_job(interface)

        if rule.floating and 'floating' not in interfaces:
            interfaces['floating'] = []

        subrules.extend(new_rules)

    def guess_rules(self, rule_filter):
        """ Return interfaces, rules and rules names """
        interfaces = {}
        rules = list()

        for name, rule in self._data.rules_obj.items():
            subrules = []
            sub_interfaces = dict()

            # for each subrule, we guess on which interfaces the subrule needs to be generated, if any
            for subrule in sorted(rule.sub_rules, key=lambda x: x.src[0].name + x.dst[0].name):
                subrule.interfaces = self.rule_interfaces(subrule)
                if rule_filter is not None and name != rule_filter:
                    continue
                if not subrule.interfaces:
                    continue

                # when aggregating, we group the rules by interface for later
                # otherwise, we add the subrule
                if self._data.aggregate:
                    for interface in subrule.interfaces:
                        if interface not in sub_interfaces:
                            sub_interfaces[interface] = []
                        sub_interfaces[interface].append(subrule)
                else:
                    subrules.append(subrule)
                    for interface in subrule.interfaces:
                        if interface not in interfaces:
                            interfaces[interface] = []

            # let's aggregate
            if self._data.aggregate and sub_interfaces:
                self.aggregate_subrules(rule, interfaces, subrules, sub_interfaces)

            if self._data.gendiff:
                rules.extend(subrules)
            else:
                for subrule in subrules:
                    rules.append((name, subrule))

            # we only keep the subrules having interfaces
            rule.sub_rules = subrules

        return (interfaces, rules)

    def generate_rules(self, rule_filter=None):
        """ Return rules definitions for pfsense_aggregate
            if rule_filter, process only rules matching rule_filter
        """

        filter_rules = []
        src_nat_rules = []
        dst_nat_rules = []

        # first, we break rules in small parts (one src, one dst)
        self._decomposer.decompose_rules()

        # then, we guess the rules which are required on the target
        (interfaces, rules) = self.guess_rules(rule_filter)

        # last, we generate each required rule
        last_name = dict()
        if self._data.gendiff:
            for rule in rules:
                self.generate_rule(rule.name, rule, interfaces, last_name)
        else:
            for (name, rule) in rules:
                self.generate_rule(name, rule, interfaces, last_name)

        # since nat is not separated by interface, we manage the order here
        last_src_nat = 'top'
        last_dst_nat = 'top'
        for name in sorted(interfaces.keys()):
            interface = interfaces[name]
            for rule in interface:
                if 'address' in rule:
                    rule['after'] = last_src_nat
                    last_src_nat = rule['descr']
                    src_nat_rules.append(rule)
                elif 'target' in rule:
                    rule['after'] = last_dst_nat
                    last_dst_nat = rule['descr']
                    dst_nat_rules.append(rule)
                else:
                    filter_rules.append(rule)

        return (filter_rules, src_nat_rules, dst_nat_rules)

    def output_rules(self, rules):
        """ Output rules definitions for pfsense_aggregate """
        print("          #===========================")
        print("          # Rules")
        print("          # ")
        interfaces = list(self._data.target.interfaces.keys())
        interfaces.append('floating')
        definitions = list()
        for interface in interfaces:
            for rule in rules:
                if interface == rule['interface'] or interface == 'floating' and rule.get('floating'):
                    definition = '          - { name: "%s", source: "%s", ' % (rule['name'], rule['source'])
                    if 'source_port' in rule:
                        definition += 'source_port: "{0}", '.format(rule['source_port'])

                    definition += 'destination: "{0}", '.format(rule['destination'])
                    if 'destination_port' in rule:
                        definition += 'destination_port: "{0}", '.format(rule['destination_port'])

                    definition += 'interface: "{0}", action: "{1}"'.format(rule['interface'], rule['action'])

                    if rule.get('protocol'):
                        definition += ", protocol: \"" + rule['protocol'] + "\""
                    if rule.get('descr'):
                        definition += ", descr: \"" + rule['descr'] + "\""
                    for field in OUTPUT_OPTION_FIELDS:
                        value = rule.get(field)
                        if value is not None:
                            definition += ', {0}: {1}'.format(field, value)

                    if rule.get('floating'):
                        definition += ", floating: True"

                    if rule.get('statetype') is not None:
                        definition += ", statetype: '{0}'".format(rule.get('statetype'))

                    if rule.get('tcpflags_any'):
                        definition += ", tcpflags_any: True"

                    if rule.get('after') and not self._data.gendiff:
                        definition += ", after: \"" + rule['after'] + "\""
                    definition += ", state: \"present\" }"
                    if self._data.gendiff:
                        definitions.append(definition)
                    else:
                        print(definition)
        definitions.sort()
        print('\n'.join(definitions))

    def output_src_nat_rules(self, rules):
        """ Output outbound definitions for pfsense_aggregate """
        print("          #===========================")
        print("          # Nat outbound rules")
        print("          # ")
        interfaces = list(self._data.target.interfaces.keys())
        interfaces.append('floating')
        definitions = list()
        for interface in sorted(interfaces):
            for rule in rules:
                if interface == rule['interface']:
                    definition = '          - { descr: "%s", source: "%s", ' % (rule['descr'], rule['source'])
                    if 'source_port' in rule:
                        definition += 'source_port: "{0}", '.format(rule['source_port'])

                    definition += 'destination: "{0}", '.format(rule['destination'])
                    if 'destination_port' in rule:
                        definition += 'destination_port: "{0}", '.format(rule['destination_port'])

                    definition += 'interface: "{0}", address: "{1}"'.format(rule['interface'], rule['address'])

                    for field in OUTPUT_SRC_NAT_OPTION_FIELDS:
                        value = rule.get(field)
                        if value is not None:
                            definition += ', {0}: {1}'.format(field, value)

                    if rule.get('protocol'):
                        definition += ", protocol: \"" + rule['protocol'] + "\""
                    if rule.get('descr'):
                        definition += ", descr: \"" + rule['descr'] + "\""

                    if rule.get('after') and not self._data.gendiff:
                        definition += ", after: \"" + rule['after'] + "\""
                    definition += ", state: \"present\" }"
                    if self._data.gendiff:
                        definitions.append(definition)
                    else:
                        print(definition)
        definitions.sort()
        print('\n'.join(definitions))

    def output_dst_nat_rules(self, rules):
        """ Output outbound definitions for pfsense_aggregate """
        print("          #===========================")
        print("          # Nat port forward rules")
        print("          # ")
        interfaces = list(self._data.target.interfaces.keys())
        interfaces.append('floating')
        definitions = list()
        for interface in sorted(interfaces):
            for rule in rules:
                if interface == rule['interface']:
                    definition = '          - { descr: "%s", source: "%s", ' % (rule['descr'], rule['source'])
                    definition += 'destination: "{0}", '.format(rule['destination'])
                    definition += 'interface: "{0}", target: "{1}"'.format(rule['interface'], rule['target'])

                    for field in OUTPUT_SRC_NAT_OPTION_FIELDS:
                        value = rule.get(field)
                        if value is not None:
                            definition += ', {0}: {1}'.format(field, value)

                    if rule.get('descr'):
                        definition += ", descr: \"" + rule['descr'] + "\""

                    if rule.get('after') and not self._data.gendiff:
                        definition += ", after: \"" + rule['after'] + "\""
                    definition += ", state: \"present\" }"
                    if self._data.gendiff:
                        definitions.append(definition)
                    else:
                        print(definition)
        definitions.sort()
        print('\n'.join(definitions))


class PFSenseRuleSeparatorFactory(object):
    """ Class generating rule separators definitions """

    def __init__(self, data):
        self._data = data

    def _find_first_separator_rule(self, separator):
        """ return the name of the first rule in the separator """
        for rule in self._data.rules_obj.values():
            for subrule in rule.sub_rules:
                if subrule.separator.name == separator.name and separator.interface in subrule.generated_names:
                    return subrule.generated_names[separator.interface]
        return None

    def generate_rule_separators(self, rule_filter=None):
        """ Return rule_separators definitions for pfsense_aggregate """

        separators = OrderedDict()

        for name, rule in self._data.rules_obj.items():
            if rule_filter is not None and name != rule_filter:
                continue
            for subrule in rule.sub_rules:
                if subrule.separator is None or subrule.separator.name is None:
                    continue
                for interface in subrule.interfaces:
                    separator = PFSenseRuleSeparator()
                    separator.name = subrule.separator.name
                    if rule.floating:
                        separator.interface = 'floating'
                    else:
                        separator.interface = interface
                    if separator not in separators:
                        separators[separator] = separator

        ret = []
        for separator in separators.values():
            definition = {}
            definition['name'] = separator.name
            if separator.interface == 'floating':
                definition['floating'] = True
            else:
                definition['interface'] = separator.interface
            definition['before'] = self._find_first_separator_rule(separator)
            if definition['before'] is None:
                # for now we don't manage empty separators
                continue
            definition['state'] = 'present'
            ret.append(definition)

        return ret

    def output_rule_separators(self, separators):
        """ Output rule separators definitions for pfsense_aggregate """
        print("          #===========================")
        print("          # Rule separators")
        print("          # ")
        interfaces = list(self._data.target.interfaces.keys())
        interfaces.append('floating')
        definitions = list()
        for interface in interfaces:
            for separator in separators:
                if 'interface' in separator and interface == separator['interface'] or interface == 'floating' and 'floating' in separator:
                    definition = "          - { name: \"" + separator['name'] + "\", "
                    if interface == 'floating':
                        definition += "floating: True, "
                    else:
                        definition += "interface: \"" + separator['interface'] + "\", "
                    definition += "before: \"" + separator['before'] + "\", state: \"present\" }"
                    definitions.append(definition)
        definitions.sort()
        print('\n'.join(definitions))


class LookupModule(LookupBase):
    """ Lookup module generating pfsense definitions """

    def get_hostname(self):
        """ Just for easier mock """
        myvars = getattr(self._templar, '_available_variables', {})
        return myvars['inventory_hostname']

    @staticmethod
    def get_definitions(from_file):
        """ Just for easier mock """
        return ordered_load(open(from_file), yaml.SafeLoader)

    def load_data(self, from_file):
        """ Load and return pfsense data """
        fvars = self.get_definitions(from_file)
        if fvars is None:
            raise AnsibleError("No usable data found in {0}".format(from_file))

        for section in ['hosts_aliases', 'ports_aliases', 'pfsenses', 'rules']:
            if section not in fvars:
                raise AnsibleError("Missing {0} section in {1}".format(section, from_file))

        data = PFSenseData(
            hosts_aliases=fvars['hosts_aliases'],
            ports_aliases=fvars['ports_aliases'],
            pfsenses=fvars['pfsenses'],
            rules=fvars['rules'],
            target_name=self.get_hostname()
        )
        return data

    def _run(self, terms, variables, **kwargs):
        """ Main function """
        if len(terms) != 2:
            raise AnsibleError("pfsense lookup requires a filename and another parameter in [aliases, rules, rule_separators, all_definitions]")

        data = self.load_data(terms[0])

        parser = PFSenseDataParser(data)
        if not parser.parse():
            raise AnsibleError("Error checking pfsense data")

        alias_factory = PFSenseAliasFactory(data)
        rule_factory = PFSenseRuleFactory(data, display_warnings=(terms[1] == 'rules'))
        rule_separator_factory = PFSenseRuleSeparatorFactory(data)

        (rules, src_nat_rules, dst_nat_rules) = rule_factory.generate_rules()
        rule_separators = rule_separator_factory.generate_rule_separators()
        aliases = alias_factory.generate_aliases()

        if terms[1] == 'aliases':
            return [aliases]
        elif terms[1] == 'rules':
            return [rules]
        elif terms[1] == 'nat_outbounds':
            return [src_nat_rules]
        elif terms[1] == 'nat_port_forwards':
            return [dst_nat_rules]
        elif terms[1] == 'rule_separators':
            return [rule_separators]
        elif terms[1] == 'all_definitions':
            res = {}
            res['aggregated_aliases'] = aliases
            res['aggregated_rules'] = rules
            res['aggregated_rule_separators'] = rule_separators
            res['aggregated_nat_outbounds'] = src_nat_rules
            res['aggregated_nat_port_forwards'] = dst_nat_rules
            return [res]

        return []

    def run(self, terms, variables, **kwargs):
        """ Entry point for main function (to properly catch & display exceptions stacktrace)"""
        trace = None
        res = []

        try:
            res = self._run(terms, variables, **kwargs)
        except AnsibleError:
            raise
        except AssertionError:
            raise
        except Exception:
            trace = traceback.format_exc()
        finally:
            if trace is not None:
                raise AnsibleError(trace)

        return res


def unit_test_helper(filename, pfname):
    """ Unit test helper """
    rule_filter = None
    fvars = ordered_load(open(filename), yaml.SafeLoader)

    data = PFSenseData(
        hosts_aliases=fvars['hosts_aliases'],
        ports_aliases=fvars['ports_aliases'],
        pfsenses=fvars['pfsenses'],
        rules=fvars['rules'],
        target_name=pfname,
    )

    parser = PFSenseDataParser(data)

    if not parser.parse():
        return False
    alias_factory = PFSenseAliasFactory(data)
    rule_factory = PFSenseRuleFactory(data)
    rule_separator_factory = PFSenseRuleSeparatorFactory(data)

    (rules, src_nat_rules, dst_nat_rules) = rule_factory.generate_rules(rule_filter)
    rule_separators = rule_separator_factory.generate_rule_separators()
    aliases = alias_factory.generate_aliases(rule_filter)

    alias_factory.output_aliases(aliases)
    rule_factory.output_rules(rules)
    rule_factory.output_src_nat_rules(src_nat_rules)
    rule_factory.output_dst_nat_rules(dst_nat_rules)
    rule_separator_factory.output_rule_separators(rule_separators)

    return (aliases, rules)


def main():
    """ Output debug helper """
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="input file")
    parser.add_argument("pfsense", help="target_fw")
    parser.add_argument('filter', help="rule_name", nargs='?')
    parser.add_argument("-a", "--dont-aggregate", action="store_false", help="dont generate aliases to aggregate rules")
    parser.add_argument("-g", "--gendiff", action="store_true", help="output more suitable for diffs (debbuging)")
    parser.add_argument("-d", "--debug-rule", action="store", help="debug rule")
    args = parser.parse_args()

    rule_filter = None
    if args.filter:
        rule_filter = args.filter

    print('Loading data...')
    fvars = ordered_load(open(args.file), yaml.SafeLoader)

    data = PFSenseData(
        hosts_aliases=fvars['hosts_aliases'],
        ports_aliases=fvars['ports_aliases'],
        pfsenses=fvars['pfsenses'],
        rules=fvars['rules'],
        target_name=args.pfsense,
        gendiff=args.gendiff,
        debug=args.debug_rule,
        aggregate=args.dont_aggregate,
    )

    parser = PFSenseDataParser(data)
    print('Parsing data...')
    if not parser.parse():
        return

    alias_factory = PFSenseAliasFactory(data)
    rule_factory = PFSenseRuleFactory(data)
    rule_separator_factory = PFSenseRuleSeparatorFactory(data)

    print('Generating rules...')
    (rules, src_nat_rules, dst_nat_rules) = rule_factory.generate_rules(rule_filter)

    if rule_filter is None:
        print('Generating rule separators...')
        rule_separators = rule_separator_factory.generate_rule_separators(rule_filter)
    else:
        print('Filter set. Skipping rule separators...')

    print('Generating aliases...')
    aliases = alias_factory.generate_aliases(rule_filter)

    alias_factory.output_aliases(aliases)
    rule_factory.output_rules(rules)
    rule_factory.output_src_nat_rules(src_nat_rules)
    rule_factory.output_dst_nat_rules(dst_nat_rules)
    if rule_filter is None:
        rule_separator_factory.output_rule_separators(rule_separators)


if __name__ == '__main__':
    main()
