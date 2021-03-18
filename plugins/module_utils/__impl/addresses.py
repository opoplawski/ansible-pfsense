# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2019, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
from ansible_collections.pfsensible.core.plugins.module_utils.compat.ipaddress import ip_address, ip_network, IPv4Address, IPv6Address, IPv4Network, IPv6Network
import re


@staticmethod
def is_ipv4_address(address):
    """ test if address is a valid ipv4 address """
    try:
        addr = ip_address(u'{0}'.format(address))
        return isinstance(addr, IPv4Address)
    except ValueError:
        pass
    return False


@staticmethod
def is_ipv6_address(address):
    """ test if address is a valid ipv6 address """
    try:
        addr = ip_address(u'{0}'.format(address))
        return isinstance(addr, IPv6Address)
    except ValueError:
        pass
    return False


@staticmethod
def is_ipv4_network(address, strict=True):
    """ test if address is a valid ipv4 network """
    try:
        addr = ip_network(u'{0}'.format(address), strict=strict)
        return isinstance(addr, IPv4Network)
    except ValueError:
        pass
    return False


@staticmethod
def is_ipv6_network(address, strict=True):
    """ test if address is a valid ipv6 network """
    try:
        addr = ip_network(u'{0}'.format(address), strict=strict)
        return isinstance(addr, IPv6Network)
    except ValueError:
        pass
    return False


def is_ip_network(self, address, strict=True):
    """ test if address is a valid ip network """
    return self.is_ipv4_network(address, strict) or self.is_ipv6_network(address, strict)


def is_within_local_networks(self, address):
    """ test if address is contained in our local networks """
    networks = self.get_interfaces_networks()
    try:
        addr = ip_address(u'{0}'.format(address))
    except ValueError:
        return False

    for network in networks:
        try:
            net = ip_network(u'{0}'.format(network), strict=False)
            if addr in net:
                return True
        except ValueError:
            pass
    return False


@staticmethod
def parse_ip_network(address, strict=True, returns_ip=True):
    """ return cidr parts of address """
    try:
        addr = ip_network(u'{0}'.format(address), strict=strict)
        if strict or not returns_ip:
            return (str(addr.network_address), addr.prefixlen)
        else:
            # we parse the address with ipaddr just for type checking
            # but we use a regex to return the result as it dont kept the address bits
            group = re.match(r'(.*)/(.*)', address)
            if group:
                return (group.group(1), group.group(2))
    except ValueError:
        pass
    return None


def parse_address(self, param, allow_self=True):
    """ validate param address field and returns it as a dict """
    addr = param.split(':')
    if len(addr) > 3:
        self.module.fail_json(msg='Cannot parse address %s' % (param))

    address = addr[0]

    ret = dict()
    # Check if the first character is "!"
    if address[0] == '!':
        # Invert the rule
        ret['not'] = None
        address = address[1:]

    if address == 'NET' or address == 'IP':
        interface = addr[1] if len(addr) > 1 else None
        ports = addr[2] if len(addr) > 2 else None
        if interface is None or interface == '':
            self.module.fail_json(msg='Cannot parse address %s' % (param))

        ret['network'] = self.parse_interface(interface)
        if address == 'IP':
            ret['network'] += 'ip'
    else:
        ports = addr[1] if len(addr) > 1 else None
        if address == 'any':
            ret['any'] = None
        # rule with this firewall
        elif allow_self and address == '(self)':
            ret['network'] = '(self)'
        # rule with interface name (LAN, WAN...)
        elif self.is_interface_display_name(address):
            ret['network'] = self.get_interface_by_display_name(address)
        else:
            if not self.is_ip_or_alias(address):
                self.module.fail_json(msg='Cannot parse address %s, not IP or alias' % (address))
            ret['address'] = address

    if ports is not None:
        self.parse_port(ports, ret)
        msg = "the :ports syntax at end of addresses is deprecated and support will be removed soon. Please use source_port and destination_port options."
        self.module.warn(msg)

    return ret


def parse_port(self, src_ports, ret):
    """ validate and parse port address field and set it in ret """
    ports = src_ports.split('-')
    if len(ports) > 2 or ports[0] is None or ports[0] == '' or len(ports) == 2 and (ports[1] is None or ports[1] == ''):
        self.module.fail_json(msg='Cannot parse port %s' % (src_ports))

    if not self.is_port_or_alias(ports[0]):
        self.module.fail_json(msg='Cannot parse port %s, not port number or alias' % (ports[0]))
    ret['port'] = ports[0]

    if len(ports) > 1:
        if not self.is_port_or_alias(ports[1]):
            self.module.fail_json(msg='Cannot parse port %s, not port number or alias' % (ports[1]))
        ret['port'] += '-' + ports[1]
