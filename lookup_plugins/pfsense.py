from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from copy import deepcopy
from collections import OrderedDict

import json
import ipaddress
import re
import sys
import yaml

from colorama import Fore
import colorama

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase


try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()


def to_unicode(string):
    """ return a unicode representation of string if required """
    if sys.version_info[0] >= 3:
        return string
    return string.decode("utf-8")


def ordered_load(stream, loader_cls=yaml.Loader, object_pairs_hook=OrderedDict):
    """ load and return yaml data from stream using ordered dicts """

    class OrderedLoader(loader_cls):
        pass

    def construct_mapping(loader, node):
        loader.flatten_mapping(node)
        return object_pairs_hook(loader.construct_pairs(node))
    OrderedLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping)
    return yaml.load(stream, OrderedLoader)


def static_vars(**kwargs):
    """ static decorator to declare static vars """

    def decorate(func):
        """ static decorator func """
        for k in kwargs:
            setattr(func, k, kwargs[k])
        return func
    return decorate


@static_vars(
    classA=ipaddress.IPv4Network((u"10.0.0.0", u"255.0.0.0")),
    classB=ipaddress.IPv4Network((u"172.16.0.0", u"255.240.0.0")),
    classC=ipaddress.IPv4Network((u"192.168.0.0", u"255.255.0.0")))
def is_local_ip(address):
    """ check if ip address is class A, B or C """
    if not isinstance(address, ipaddress.IPv4Address):
        ip_address = ipaddress.ip_address(to_unicode(address))
    else:
        ip_address = address
    return ip_address in is_local_ip.classA or ip_address in is_local_ip.classB or ip_address in is_local_ip.classC


@static_vars(
    classA=ipaddress.IPv4Network((u"10.0.0.0", u"255.0.0.0")),
    classB=ipaddress.IPv4Network((u"172.16.0.0", u"255.240.0.0")),
    classC=ipaddress.IPv4Network((u"192.168.0.0", u"255.255.0.0")))
def is_local_network(address):
    """ check if network is class A, B or C """
    if not isinstance(address, ipaddress.IPv4Network):
        net = ipaddress.ip_network(to_unicode(address))
    else:
        net = address
    return net.subnet_of(is_local_ip.classA) or net.subnet_of(is_local_ip.classB) or net.subnet_of(is_local_ip.classC)


def is_valid_ip(address):
    """ validate ip address format """
    try:
        ipaddress.ip_address(to_unicode(address))
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
    if not group: return False
    nport1 = int(group.group(1))
    nport2 = int(group.group(2))

    return nport1 >= 0 and nport1 <= 65535 and nport2 >= 0 and nport2 <= 65535


def is_valid_network(address):
    """ validate network address format """
    try:
        ipaddress.ip_network(to_unicode(address))
        return True
    except ValueError:
        return False
    return False


def cleanup_def_name(name):
    """ return a valid alias name """
    return name.lower().replace(' ', '_').replace('-', '_').replace('.', '_')


def cross_str(tab, rule, field, out_field=None):
    """ Return cartesian cross between rule[field] and tab as strings """
    if field not in rule:
        return tab
    if not out_field:
        out_field = field
    out = []
    for new_val in rule[field].split(' '):
        for existing_val in tab:
            if not existing_val:
                result = out_field + ": \"" + new_val + "\""
            else:
                result = existing_val + ", " + out_field + ": \"" + new_val + "\""
            out.append(result)

    return out


def cross_dict(tab, rule, field, out_field=None):
    """ Return cartesian cross between rule[field] and tab as dicts """
    if field not in rule:
        return tab
    if not out_field:
        out_field = field
    out = []
    for new_val in rule[field].split(' '):
        for existing_val in tab:
            obj = deepcopy(existing_val)
            obj[out_field] = new_val
            out.append(obj)

    return out


def cross_ports(rule, field, field_port):
    """ Return cartesian cross between rule[field] and field_port as string """
    if field_port not in rule: return rule[field]

    aliases = rule[field].split(' ')
    ports = rule[field_port].split(' ')
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


def format_after(last_name):
    """ Format after field for rules definition if filled """
    if last_name: return ", after: \"" + last_name + "\""
    return ""


class PFSenseHostAlias(object):
    """ Class holding structured pfsense host alias definition """
    def __init__(self):
        self.name = None
        self.descr = None
        self.definition = []
        self.ips = []
        self.networks = []
        self.fake_alias_ip = False
        self.fake_alias_network = False

        # define all interfaces on which the alias is to be defined
        # interfaces['gw_aja_1'] = ['lan', 'obs']
        self.interfaces = {}
        self.interfaces_src = {}

    def compute_any(self, data):
        """ Do all computations for object 'any' """

        # we add all interfaces of all pfsenses
        for pfsense in data.pfsenses_obj.values():
            if pfsense.name not in self.interfaces:
                self.interfaces[pfsense.name] = []
            for interface in pfsense.interfaces.values():
                self.interfaces[pfsense.name].append(interface.name)

    def compute_all(self, data):
        """ Do all computations """
        if self.name != 'any':
            self.compute_addresses(data)
            self.compute_interfaces(data)
            self.compute_interfaces_src(data)

    def compute_addresses(self, data):
        """ Convert all aliases to structured ip addresses or networks """
        todo = []
        todo.extend(self.definition)

        while todo:
            address = todo.pop()

            try:
                host_ip = ipaddress.ip_address(to_unicode(address))
                self.ips.append(host_ip)
                continue
            except ValueError:
                pass

            try:
                net = ipaddress.ip_network(to_unicode(address))
                self.networks.append(net)
                continue
            except ValueError:
                pass

            if address not in data.all_defs:
                data.set_error("Invalid address: " + address + " for " + self.name)
            assert address in data.all_defs
            todo.extend(data.all_defs[address]['ip'].split(' '))

    def match_interface_src(self, interface):
        """ check if an alias match the src network of an interface """
        if not interface.local_network: return False

        for alias_ip in self.ips:
            local_ip = is_local_ip(alias_ip)
            snet = interface.local_network
            # print(interface.name + ' ' + snet.exploded + ' -> ' + alias_ip.exploded + ' ' + str(alias_ip in snet))
            local_net = is_local_network(snet)
            if local_ip and local_net or not local_ip and not local_net:
                return alias_ip in snet
            return False

        for alias_net in self.networks:
            local_neta = is_local_network(alias_net)
            snet = interface.local_network
            # print(interface.name + ' ' + snet.exploded + ' -> ' + alias_ip.exploded + ' ' + str(alias_ip in snet))
            local_net = is_local_network(snet)
            if local_neta and local_net or not local_neta and not local_net:
                return alias_net.subnet_of(snet)
        return False

    def match_interface_dst(self, interface):
        """ check if an alias match the dst networks of an interface """
        for alias_ip in self.ips:
            local_ip = is_local_ip(alias_ip)
            for snet in interface.routed_networks:
                # print(interface.name + ' ' + snet.exploded + ' -> ' + alias_ip.exploded + ' ' + str(alias_ip in snet))
                local_net = is_local_network(snet)
                if local_ip and local_net or not local_ip and not local_net:
                    if alias_ip in snet:
                        return True

        for alias_net in self.networks:
            local_neta = is_local_network(alias_net)
            for snet in interface.routed_networks:
                # print(interface.name + ' ' + snet.exploded + ' -> ' + alias_ip.exploded + ' ' + str(alias_ip in snet))
                local_net = is_local_network(snet)
                if local_neta and local_net or not local_neta and not local_net:
                    if alias_net.subnet_of(snet):
                        return True
        return False

    def match_interface(self, interface, src=True):
        """ check if an singleton alias match the src or dst networks of an interface """
        if src:
            return self.match_interface_src(interface)
        return self.match_interface_dst(interface)

    def compute_interfaces(self, data):
        """ Find all interfaces on all pfsense where the alias can be used """
        interfaces = {}
        for alias_ip in self.ips:
            local_ip = is_local_ip(alias_ip)
            for pfsense in data.pfsenses_obj.values():
                for interface in pfsense.interfaces.values():
                    for snet in interface.networks:
                        # print(interface.name + ' ' + snet.exploded + ' -> ' + alias_ip.exploded + ' ' + str(alias_ip in snet))
                        local_net = is_local_network(snet)
                        if local_ip and local_net or not local_ip and not local_net:
                            if alias_ip in snet:
                                if pfsense.name not in interfaces:
                                    interfaces[pfsense.name] = []
                                interfaces[pfsense.name].append(interface.name)

        for alias_net in self.networks:
            local_neta = is_local_network(alias_net)
            for pfsense in data.pfsenses_obj.values():
                for interface in pfsense.interfaces.values():
                    for snet in interface.networks:
                        # print(interface.name + ' ' + snet.exploded + ' -> ' + alias_ip.exploded + ' ' + str(alias_ip in snet))
                        local_net = is_local_network(snet)
                        if local_neta and local_net or not local_neta and not local_net:
                            if alias_net.subnet_of(snet):
                                if pfsense.name not in interfaces:
                                    interfaces[pfsense.name] = []
                                interfaces[pfsense.name].append(interface.name)

        for key, value in interfaces.items():
            # print(key + ' -> ' + json.dumps(value))
            self.interfaces[key] = list(set(value))

        # print(self.name + ' -> ' + json.dumps(self.interfaces))

    def compute_interfaces_src(self, data):
        """ Find all interfaces on all pfsense where the alias can be used """
        interfaces = {}
        for alias_ip in self.ips:
            local_ip = is_local_ip(alias_ip)
            for pfsense in data.pfsenses_obj.values():
                for interface in pfsense.interfaces.values():
                    if interface.local_network:
                        snet = interface.local_network
                        # print(interface.name + ' ' + snet.exploded + ' -> ' + alias_ip.exploded + ' ' + str(alias_ip in snet))
                        local_net = is_local_network(snet)
                        if local_ip and local_net or not local_ip and not local_net:
                            if alias_ip in snet:
                                if pfsense.name not in interfaces:
                                    interfaces[pfsense.name] = []
                                interfaces[pfsense.name].append(interface.name)

        for alias_net in self.networks:
            local_neta = is_local_network(alias_net)
            for pfsense in data.pfsenses_obj.values():
                for interface in pfsense.interfaces.values():
                    for snet in interface.networks:
                        # print(interface.name + ' ' + snet.exploded + ' -> ' + alias_ip.exploded + ' ' + str(alias_ip in snet))
                        local_net = is_local_network(snet)
                        if local_neta and local_net or not local_neta and not local_net:
                            if alias_net.subnet_of(snet):
                                if pfsense.name not in interfaces:
                                    interfaces[pfsense.name] = []
                                interfaces[pfsense.name].append(interface.name)

        for key, value in interfaces.items():
            # print(key + ' -> ' + json.dumps(value))
            self.interfaces_src[key] = list(set(value))

        # print(self.name + ' iface_src -> ' + json.dumps(self.interfaces_src))

    def is_whole_local(self, pfsense):
        """ check if all ips/networks match a local network interface in pfense """
        for alias_ip in self.ips:
            local_ip = is_local_ip(alias_ip)
            found = False
            for interface in pfsense.interfaces.values():
                if interface.local_network:
                    snet = interface.local_network
                    # print(interface.name + ' ' + snet.exploded + ' -> ' + alias_ip.exploded + ' ' + str(alias_ip in snet))
                    local_net = is_local_network(snet)
                    if local_ip and local_net or not local_ip and not local_net:
                        if alias_ip in snet:
                            found = True
            if not found: return False

        for alias_net in self.networks:
            local_neta = is_local_network(alias_net)
            found = False
            for interface in pfsense.interfaces.values():
                if interface.local_network:
                    snet = interface.local_network
                    # print(interface.name + ' ' + snet.exploded + ' -> ' + alias_net.exploded + ' ' + str(alias_net.subnet_of(snet)))
                    local_net = is_local_network(snet)
                    if local_neta and local_net or not local_neta and not local_net:
                        if alias_net.subnet_of(snet):
                            found = True
            if not found: return False

        return True

    def is_routed(self, pfsense):
        """ check if all ips/networks match a routed network in pfense """
        for alias_ip in self.ips:
            local_ip = is_local_ip(alias_ip)
            found = False
            for interface in pfsense.interfaces.values():
                for snet in interface.routed_networks:
                    # print(interface.name + ' ' + snet.exploded + ' -> ' + alias_ip.exploded + ' ' + str(alias_ip in snet))
                    local_net = is_local_network(snet)
                    if local_ip and local_net or not local_ip and not local_net:
                        if alias_ip in snet:
                            found = True
            if not found: return False

        for alias_net in self.networks:
            local_neta = is_local_network(alias_net)
            found = False
            for interface in pfsense.interfaces.values():
                for snet in interface.routed_networks:
                    # print(interface.name + ' ' + snet.exploded + ' -> ' + alias_net.exploded + ' ' + str(alias_net.subnet_of(snet)))
                    local_net = is_local_network(snet)
                    if local_neta and local_net or not local_neta and not local_net:
                        if alias_net.subnet_of(snet):
                            found = True
            if not found: return False

        return True

    def is_whole_in_pfsense(self, pfsense):
        """ check if all ips/networks have as least one interface in pfense """
        for alias_ip in self.ips:
            local_ip = is_local_ip(alias_ip)
            found = False
            for interface in pfsense.interfaces.values():
                for snet in interface.networks:
                    # print(interface.name + ' ' + snet.exploded + ' -> ' + alias_ip.exploded + ' ' + str(alias_ip in snet))
                    local_net = is_local_network(snet)
                    if local_ip and local_net or not local_ip and not local_net:
                        if alias_ip in snet:
                            found = True
            if not found: return False

        for alias_net in self.networks:
            local_neta = is_local_network(alias_net)
            found = False
            for interface in pfsense.interfaces.values():
                for snet in interface.networks:
                    # print(interface.name + ' ' + snet.exploded + ' -> ' + alias_net.exploded + ' ' + str(alias_net.subnet_of(snet)))
                    local_net = is_local_network(snet)
                    if local_neta and local_net or not local_neta and not local_net:
                        if alias_net.subnet_of(snet):
                            found = True
            if not found: return False

        return True

    def is_whole_not_in_pfsense(self, pfsense):
        """ check if all ips/networks have as least one interface in pfense """
        for alias_ip in self.ips:
            local_ip = is_local_ip(alias_ip)
            found = False
            for interface in pfsense.interfaces.values():
                for snet in interface.networks:
                    # print(interface.name + ' ' + snet.exploded + ' -> ' + alias_ip.exploded + ' ' + str(alias_ip in snet))
                    local_net = is_local_network(snet)
                    if local_ip and local_net or not local_ip and not local_net:
                        if alias_ip in snet:
                            found = True
            if found: return False

        for alias_net in self.networks:
            local_neta = is_local_network(alias_net)
            found = False
            for interface in pfsense.interfaces.values():
                for snet in interface.networks:
                    # print(interface.name + ' ' + snet.exploded + ' -> ' + alias_ip.exploded + ' ' + str(alias_ip in snet))
                    local_net = is_local_network(snet)
                    if local_neta and local_net or not local_neta and not local_net:
                        if alias_net.subnet_of(snet):
                            found = True
            if found: return False

        return True

    def is_whole_in_same_ifaces(self, pfsense):
        """ check if all ips/networks have the same interfaces in pfense """
        target_interfaces = None
        for alias_ip in self.ips:
            local_ip = is_local_ip(alias_ip)
            interfaces = set()
            for interface in pfsense.interfaces.values():
                for snet in interface.networks:
                    # print(interface.name + ' ' + snet.exploded + ' -> ' + alias_ip.exploded + ' ' + str(alias_ip in snet))
                    local_net = is_local_network(snet)
                    if local_ip and local_net or not local_ip and not local_net:
                        if alias_ip in snet:
                            interfaces.add(interface.name)
            if not target_interfaces:
                target_interfaces = interfaces
            elif target_interfaces ^ interfaces:
                return False

        for alias_net in self.networks:
            local_neta = is_local_network(alias_net)
            interfaces = set()
            for interface in pfsense.interfaces.values():
                for snet in interface.networks:
                    # print(interface.name + ' ' + snet.exploded + ' -> ' + alias_ip.exploded + ' ' + str(alias_ip in snet))
                    local_net = is_local_network(snet)
                    if local_neta and local_net or not local_neta and not local_net:
                        if alias_net.subnet_of(snet):
                            interfaces.add(interface.name)
            if not target_interfaces:
                target_interfaces = interfaces
            elif target_interfaces ^ interfaces:
                return False

        return True


class PFSenseRule(object):
    """ Class holding structured pfsense rule declaration """
    def __init__(self):
        self.name = None
        self.src = []
        self.src_port = []
        self.dst = []
        self.dst_port = []
        self.protocol = []
        self.action = "pass"
        self.log = "yes"

        self.sub_rules = []

    def to_json(self):
        """ return JSON String containing rule """
        srcs = []
        for src in self.src: srcs.append(src.name)
        dsts = []
        for dst in self.dst: dsts.append(dst.name)
        res = self.name + ": { src: " + " ".join(srcs) + ", dst: " + " ".join(dsts)
        if self.src_port: res += ", src_port: " + " ".join(self.src_port)
        if self.dst_port: res += ", dst_port: " + " ".join(self.dst_port)
        if self.protocol: res += ", protocol: " + " ".join(self.protocol)
        if self.action != "pass": res += ", action: " + " ".join(self.action)
        if self.log != "yes": res += ", log: " + " ".join(self.log)
        res += " }"
        return res


class PFSenseInterface(object):
    """ Class holding structured pfsense interface definition """
    def __init__(self):
        self.name = None
        self.local_ip = None
        self.local_network = None
        self.routed_networks = []
        self.networks = []


class PFSense(object):
    """ Class holding structured pfsense definition """
    def __init__(self, name, site, interfaces):
        self.name = name
        self.site = site
        self.interfaces = interfaces
        self.local_networks = []
        self.all_networks = []
        self.compute_local_networks()

    def compute_local_networks(self):
        """ grab all local networks from interfaces """
        self.local_networks = []
        for interface in self.interfaces.values():
            if interface.local_network:
                self.local_networks.append(interface.local_network)

    def is_local_ip(self, address):
        """ Check if address belong to our local networks """
        try:
            host_ip = ipaddress.ip_address(to_unicode(address))
            if not is_local_ip(host_ip): return False
            for snet in self.local_networks:
                if host_ip in snet: return True
        except ValueError:
            pass

        try:
            net = ipaddress.ip_network(to_unicode(address))
            if not is_local_network(net): return False
            for snet in self.local_networks:
                if net.subnet_of(snet): return True
        except ValueError:
            pass
        return False


class PFSenseData(object):
    """ Class holding all data """

    def __init__(self, sites, hosts_aliases, ports_aliases, pfsenses, rules, target_name):
        self._all_defs = OrderedDict()
        self._sites = sites
        self._hosts_aliases = hosts_aliases
        self._ports_aliases = ports_aliases
        self._pfsenses = pfsenses
        self._rules = rules
        self._target_name = target_name
        self._rules_obj = OrderedDict()
        self._pfsenses_obj = {}
        self._hosts_aliases_obj = OrderedDict()
        self._target = None
        self._errors = []
        self.log_errors = False

    @property
    def all_defs(self):
        """ all_defs getter """
        return self._all_defs

    @property
    def sites(self):
        """ _sites getter """
        return self._sites

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

    def _cleanup_defs(self, defs_name):
        """ cleaning attribute defs_name """
        defs = getattr(self, defs_name)
        _defs = {}
        ret = True
        for name, _def in defs.items():
            name = cleanup_def_name(name)
            if name in self._all_defs:
                self.set_error("duplicate def " + name + " (" + json.dumps(self._all_defs[name]) + ")")
                ret = False

            self._all_defs[name] = _def
            _defs[name] = _def

        setattr(self, defs_name, _defs)
        return ret

    def cleanup_defs(self):
        """ cleaning all attributes (except src and dst which are processed later) """
        ret = self._cleanup_defs('_hosts_aliases')
        if not self._cleanup_defs('_ports_aliases'): ret = False
        if not self._cleanup_defs('_sites'): ret = False
        if not self._cleanup_defs('_pfsenses'): ret = False
        if not self._cleanup_defs('_rules'): ret = False
        self._target_name = cleanup_def_name(self._target_name)

        return ret

    def unalias_ip(self, alias):
        """ expand alias to it's ip definition """
        ret = []
        todo = []
        todo.extend(alias.split(' '))

        while todo:
            elts = todo.pop()
            if elts in self._all_defs:
                todo.extend(self._all_defs[elts]['ip'].split(' '))
            else:
                ret.append(elts)

        return ret


class PFSenseDataChecker(object):
    """ Class doing all data checks """

    def __init__(self, data):
        self._data = data

    def check_host_alias(self, obj, src_name, type_name, name, allow_any):
        """ Checking an host alias definition """
        ret = True
        value = obj[src_name]
        values = str(value).split(' ')
        if not values:
            self._data.set_error("Empty " + src_name + " field for " + type_name + " " + name)
            return False

        # we check that all exists and we cleanup aliases
        net_defs = 0
        clean = []
        for value in values:
            if is_valid_ip(value):
                self._data.hosts_aliases_obj[value] = self.create_obj_host_alias(value)
                clean.append(value)
                continue

            if is_valid_network(value):
                self._data.hosts_aliases_obj[value] = self.create_obj_host_alias(value)
                clean.append(value)
                net_defs = net_defs + 1
                continue

            clean_name = cleanup_def_name(value)
            if clean_name not in self._data.hosts_aliases and (value != 'any' or not allow_any):
                self._data.set_error(value + " is not a valid alias, ip address or network in " + type_name + " " + name)
                ret = False
            clean.append(clean_name)
        obj[src_name] = ' '.join(clean)

        # if it's a real alias, we must check for network definitions
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

    def check_hosts_aliases(self):
        """ Checking all hosts alias definitions """
        dups = {}
        ret = True
        for name, alias in self._data.hosts_aliases.items():
            # ip field is mandatory
            if 'ip' not in alias:
                self._data.set_error("No ip field for alias " + name)
                ret = False
                continue

            # we check that all fields are valid
            for field in alias:
                if field != 'ip' and field != 'descr':
                    self._data.set_error(field + " is not a valid field name in alias " + name)
                    ret = False

            # we check that all ip exist and are not empty
            if not self.check_host_alias(alias, 'ip', 'alias', name, False):
                ret = False
                continue

            # we check for duplicates
            _alias = deepcopy(alias)
            if 'descr' in _alias: del _alias['descr']
            dup = json.dumps(_alias)
            if dup in dups:
                display.warning("duplicate alias definition for ip " + alias['ip'] + " (" + dups[dup] + ", " + name + ")")
            else:
                dups[dup] = name

            obj = PFSenseHostAlias()
            obj.name = name
            obj.definition = alias['ip'].split(' ')
            if 'descr' in alias: obj.descr = alias['descr']
            self._data.hosts_aliases_obj[name] = obj

        return ret

    def check_port_alias(self, ports, src_name, type_name, name):
        """ Checking a port alias definition """
        ret = True
        values = str(ports).split(' ')
        if not values:
            self._data.set_error("Empty " + src_name + " field for " + type_name + " " + name)
            return False

        # we check that all exists
        for value in values:
            if not is_valid_port(value) and not is_valid_port_range(value) and cleanup_def_name(value) not in self._data.ports_aliases:
                self._data.set_error(value + " is not a valid alias, port or port range in " + type_name + " " + name)
                ret = False

        return ret

    def check_ports_aliases(self):
        """ Checking all ports alias definitions """
        dups = {}
        ret = True
        for name, alias in self._data.ports_aliases.items():
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
            if 'descr' in _alias: del _alias['descr']
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
        obj.fake_alias_network = True
        obj.compute_any(self._data)

        self._data.all_defs['any'] = {}
        self._data.all_defs['any']['ip'] = '0.0.0.0/0'
        self._data.all_defs['any']['type'] = 'network'

        return obj

    def create_obj_host_alias(self, src):
        """ Create a PFSenseHostAlias object from address (for easier processing later) """
        obj = PFSenseHostAlias()
        obj.name = src
        obj.definition = [src]
        if is_valid_ip(src):
            obj.fake_alias_ip = True
        elif is_valid_network(src):
            obj.fake_alias_network = True
        elif src == 'any':
            return self.create_obj_any_alias()
        else:
            self._data.set_error("Invalid alias: " + src)
            assert False

        return obj

    def create_obj_rule_from_def(self, name, rule):
        """ Create a PFSenseRule object from yaml definition """
        obj = PFSenseRule()
        obj.name = name

        if 'src_port' in rule:
            if not isinstance(rule['src_port'], str):
                obj.src_port = str(rule['src_port'])
            else:
                obj.src_port = rule['src_port'].split(' ')

        if 'dst_port' in rule:
            if not isinstance(rule['dst_port'], str):
                obj.dst_port = str(rule['dst_port'])
            else:
                obj.dst_port = rule['dst_port'].split(' ')

        if 'protocol' in rule:
            obj.protocol = rule['protocol'].split(' ')

        if 'action' in rule:
            obj.action = rule['action']

        if 'log' in rule:
            obj.log = rule['log']

        for src in rule['src'].split(' '):
            if src not in self._data.hosts_aliases_obj:
                self._data.hosts_aliases_obj[src] = self.create_obj_host_alias(src)
            target = self._data.hosts_aliases_obj[src]
            obj.src.append(target)

        for dst in rule['dst'].split(' '):
            if dst not in self._data.hosts_aliases_obj:
                self._data.hosts_aliases_obj[dst] = self.create_obj_host_alias(dst)
            target = self._data.hosts_aliases_obj[dst]
            obj.dst.append(target)

        return obj

    def check_rules(self):
        """ Checking all rules definitions """
        ret = True
        for name, rule in self._data.rules.items():
            # src field is mandatory
            if 'src' not in rule:
                self._data.set_error("No src field for rule " + name)
                ret = False
                continue

            # we check that all src exist and are not empty
            if not self.check_host_alias(rule, 'src', 'rule', name, True):
                ret = False

            # dst field is mandatory
            if 'dst' not in rule:
                self._data.set_error("No dst field for rule " + name)
                ret = False
                continue

            # we check that all dst exist and are not empty
            if not self.check_host_alias(rule, 'dst', 'rule', name, True):
                ret = False

            # checking ports
            if 'src_port' in rule:
                if not isinstance(rule['src_port'], str):
                    rule['src_port'] = str(rule['src_port'])

                if not self.check_port_alias(rule['src_port'], 'src_port', 'rule', name) or not self.check_tcp_udp(rule, name):
                    ret = False

            if 'dst_port' in rule:
                if not isinstance(rule['dst_port'], str):
                    rule['dst_port'] = str(rule['dst_port'])

                if not self.check_port_alias(rule['dst_port'], 'dst_port', 'rule', name) or not self.check_tcp_udp(rule, name):
                    ret = False

            if 'action' not in rule:
                rule['action'] = 'pass'

            if 'log' not in rule:
                rule['log'] = 'yes'

            # we check that all fields are valid
            valid_fields = {'src', 'dst', 'src_port', 'dst_port', 'protocol', 'action', 'log'}
            for field in rule:
                if field not in valid_fields:
                    self._data.set_error(field + " is not a valid field name in rule " + name)
                    ret = False

            self._data.rules_obj[name] = self.create_obj_rule_from_def(name, rule)

        return ret

    def check_target_name(self):
        """ Checking target_name definition """
        if self._data.target_name not in self._data.pfsenses:
            self._data.set_error(self._data.target_name + " is unknown")
        self._data.target = self._data.pfsenses_obj[self._data.target_name]
        return True

    def check_networks(self, networks, src_name, type_name, name):
        """ check if a field is filled with valid networks """
        ret = True
        values = str(networks).split(' ')
        if not values:
            self._data.set_error("Empty " + src_name + " field for " + type_name + " " + name)
            return False

        # we check that all exists
        for value in values:
            if not is_valid_network(value):
                self._data.set_error(value + " is not a valid network in " + type_name + " " + name)
                ret = False

        return ret

    def check_tcp_udp(self, rule, name):
        """ check if protocol is valid when ports are sets """
        if 'protocol' not in rule: return True
        protocols = str(rule['protocol']).split(' ')
        for protocol in protocols:
            if protocol != 'udp' and protocol != 'tcp' and protocol != 'tcp/udp':
                self._data.set_error(protocol + " protocol used with src_port or dst_port in rule " + name)
                return False
        return True

    def check_sites(self):
        """ Checking all sites definitions """
        dups = {}
        ret = True
        for name, site in self._data.sites.items():
            # network field is mandatory
            if 'network' not in site:
                self._data.set_error("No network field for site " + name)
                ret = False
                continue

            # we check that all ip exist and are not empty
            if not self.check_networks(site['network'], 'network', 'site', name):
                ret = False
                continue

            # we check that all fields are valid
            for field in site:
                if field != 'network':
                    self._data.set_error(field + " is not a valid field name in site " + name)
                    ret = False

            # we check for duplicates
            _site = deepcopy(site)
            if 'descr' in _site: del _site['descr']
            dup = json.dumps(_site)
            if dup in dups:
                display.warning("duplicate site definition for network " + site['network'] + " (" + dups[dup] + ", " + name + ")")
            else:
                dups[dup] = name

        return ret

    def check_pfsense_interfaces_objs(self, interfaces, name):
        """ Checking all interfaces networks between them """
        for src_name, src in interfaces.items():
            for dst_name, dst in interfaces.items():
                if src_name == dst_name: continue
                if not src.local_network: continue

                if dst.local_network and src.local_network.overlaps(dst.local_network):
                    self._data.set_error("Local networks of " + src_name + " and " + dst_name + " overlap in " + name)
                    return False

                # we remove the local networks from the routed_networks of other interfaces
                routed_networks = deepcopy(dst.routed_networks)
                for network in dst.routed_networks:
                    if network.prefixlen == 0: continue
                    if network.compare_networks(src.local_network) == 0:
                        routed_networks.remove(network)
                        dst.networks.remove(network)
                    elif network.overlaps(src.local_network):
                        self._data.set_error("Local network of " + src_name + " overlaps with routed network " + network.exploded + " of " + dst_name + " in " + name)
                        return False

                if len(routed_networks) != len(dst.routed_networks):
                    dst.routed_networks = routed_networks

        return True

    def check_pfsense_interfaces(self, pfsense, name):
        """ Checking all pfsense interfaces definitions """
        ret = {}
        for iname, interface in pfsense['interfaces'].items():
            # extracting & checking localt network
            local_ip = None
            local_network = None
            if 'ip' in interface:
                try:
                    local_network = ipaddress.ip_network(to_unicode(interface['ip']), False)
                except ValueError:
                    self._data.set_error("Invalid network " + interface['ip'] + " in " + name)
                    ret = {}
                    break

                if local_network.prefixlen == 32:
                    self._data.set_error("Invalid network prefix length for network " + interface['ip'] + " in " + name)
                    ret = {}
                    break

                # extracting & checking ip
                group = re.match(r'([^\/]*)\/(\d+)', interface['ip'])
                try:
                    local_ip = ipaddress.ip_address(to_unicode(group.group(1)))
                except ValueError:
                    self._data.set_error("Invalid ip " + interface['ip'] + " in " + name)
                    ret = {}
                    break

            # extracting & checking routed networks
            routed_networks = []
            if 'routed_networks' in interface:
                networks = self._data.unalias_ip(interface['routed_networks'])
                for network in networks:
                    try:
                        routed_networks.append(ipaddress.ip_network(to_unicode(network)))
                    except ValueError:
                        self._data.set_error("Invalid network " + network + " in routed_networks of " + name)
                        return {}

            obj = PFSenseInterface()
            obj.name = iname
            obj.local_ip = local_ip
            obj.local_network = local_network
            obj.routed_networks.extend(routed_networks)
            obj.networks.extend(routed_networks)
            if local_network:
                obj.networks.append(local_network)
            ret[iname] = obj

        if not self.check_pfsense_interfaces_objs(ret, name):
            ret = {}

        return ret

    def check_pfsenses(self):
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

            interfaces = self.check_pfsense_interfaces(pfsense, name)
            # checking interfaces
            if not interfaces:
                ret = False
                continue

            # site field is mandatory
            if 'site' not in pfsense:
                self._data.set_error("No site field for pfsense " + name)
                ret = False
                continue

            # we check the site exists
            if pfsense['site'] not in self._data.sites:
                self._data.set_error(pfsense['site'] + " is unknown for " + name)
                ret = False
                continue

            # we check that all fields are valid
            for field in pfsense:
                if field != 'interfaces' and field != 'site':
                    self._data.set_error(field + " is not a valid field name in pfsense " + name)
                    ret = False

            # we check for duplicates
            _pfsense = deepcopy(pfsense)
            if 'descr' in _pfsense: del _pfsense['descr']
            dup = json.dumps(_pfsense)
            if dup in dups:
                display.warning("duplicate pfsense definition for ip " + pfsense['ip'] + " (" + dups[dup] + ", " + name + ")")
            else:
                dups[dup] = name

            obj = PFSense(name, pfsense['site'], interfaces)
            self._data.pfsenses_obj[obj.name] = obj

        return ret

    def check_hosts_aliases_objs(self):
        """ Checking all host alias objs, addresses and finding pfsenses interfaces """
        for obj in self._data.hosts_aliases_obj.values():
            obj.compute_all(self._data)

        return True

    def check_defs(self):
        """ Check everything """
        ret = True
        ret = ret and self.check_hosts_aliases()
        ret = ret and self.check_ports_aliases()
        ret = ret and self.check_rules()
        ret = ret and self.check_sites()
        ret = ret and self.check_pfsenses()
        ret = ret and self.check_target_name()
        ret = ret and self.check_hosts_aliases_objs()

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
            ret.append(host)
        elif host.is_whole_in_pfsense(self._data.target):
            ret.append(host)
        else:
            alias = self._data.all_defs[host.name]
            if 'ip' in alias:
                for alias_ip in alias['ip'].split(' '):
                    ret_n = self.host_separate(self._data.hosts_aliases_obj[alias_ip])
                    ret.extend(ret_n)

        return ret

    def host_separate_by_iface(self, host):
        """ separate aliases to remove mixed configuration
        where there is a local and remote network/ip is the host
        host is expanded to sub-aliases if required """
        ret = []
        if host.is_whole_in_same_ifaces(self._data.target):
            ret.append(host)
        else:
            alias = self._data.all_defs[host.name]
            if 'ip' in alias:
                for alias_ip in alias['ip'].split(' '):
                    ret_n = self.host_separate_by_iface(self._data.hosts_aliases_obj[alias_ip])
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
        sub_rules = []
        if len(rule.src) > 1 or len(rule.dst) > 1:
            for src in rule.src:
                for dst in rule.dst:
                    new_rule = deepcopy(rule)
                    new_rule.src = [src]
                    new_rule.dst = [dst]
                    sub_rules.append(new_rule)

            return sub_rules

        assert len(rule.src) == 1
        assert len(rule.dst) == 1

        src = rule.src[0]
        dst = rule.dst[0]

        sub_rules = self.separate_aliases(rule, src, 'src', 'host_separate')
        if not sub_rules: sub_rules = self.separate_aliases(rule, dst, 'dst', 'host_separate')
        if not sub_rules: sub_rules = self.separate_aliases(rule, src, 'src', 'host_separate_by_iface')
        if not sub_rules: sub_rules = self.separate_aliases(rule, dst, 'dst', 'host_separate_by_iface')

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
        name = alias.name
        aliases[name] = self._data.all_defs[name]
        for target in alias.definition:
            obj = self._data.hosts_aliases_obj[target]
            if obj.fake_alias_ip or obj.fake_alias_network: continue
            self.add_host_alias_rec(obj, aliases)

    def add_port_alias_rec(self, alias, aliases):
        """ Return aliases ports names to define (recursive) """
        if alias in self._data.all_defs:
            if alias not in aliases:
                aliases[alias] = self._data.all_defs[alias]

            if 'port' in aliases[alias]:
                for port in aliases[alias]['port'].split(' '):
                    self.add_port_alias_rec(port, aliases)

    def add_hosts_aliases(self, rule, aliases):
        """ Return aliases hosts names to define """
        for alias in rule.src:
            if alias.fake_alias_ip or alias.fake_alias_network: continue
            self.add_host_alias_rec(alias, aliases)

        for alias in rule.dst:
            if alias.fake_alias_ip or alias.fake_alias_network: continue
            self.add_host_alias_rec(alias, aliases)

    def add_ports_aliases(self, rule, aliases):
        """ Return aliases ports names to define """
        for alias in rule.src_port:
            self.add_port_alias_rec(alias, aliases)

        for alias in rule.dst_port:
            self.add_port_alias_rec(alias, aliases)

    def generate_aliases(self):
        """ Return aliases definitions for pfsense_aliases_aggregate """

        hosts_aliases = {}
        ports_aliases = {}

        for name, rule in self._data.rules_obj.items():
            for subrule in rule.sub_rules:
                if not subrule.interfaces: continue
                self.add_hosts_aliases(subrule, hosts_aliases)
                self.add_ports_aliases(subrule, ports_aliases)

        ret = []
        for name, alias in hosts_aliases.items():
            definition = {}
            definition['name'] = name
            definition['type'] = alias['type']
            definition['address'] = alias['ip']
            definition['state'] = 'present'
            if 'descr' in alias:
                definition['descr'] = alias['descr']
            ret.append(definition)

        for name, alias in ports_aliases.items():
            definition = {}
            definition['name'] = name
            definition['type'] = 'port'
            definition['address'] = alias['port'].replace('-', ':')
            definition['state'] = 'present'
            if 'descr' in alias:
                definition['descr'] = alias['descr']
            ret.append(definition)

        return ret

    def output_aliases(self, aliases=None):
        """ Output aliases definitions for pfsense_aliases_aggregate """
        if not aliases:
            aliases = self.generate_aliases()
        print(Fore.CYAN + "          #===========================")
        print(Fore.CYAN + "          # Hosts & network aliases")
        print(Fore.CYAN + "          # ")
        for alias in aliases:
            if alias['type'] == 'port': continue
            definition = "          - { name: \"" + alias['name'] + "\", type: \"" + alias['type'] + "\", address: \"" + alias['address'] + "\""
            if 'descr' in alias:
                definition = definition + ", descr: \"" + alias['descr'] + "\""
            definition = definition + ", state: \"present\" }"
            print(Fore.GREEN + definition)

        print(Fore.CYAN + "          #===========================")
        print(Fore.CYAN + "          # ports aliases")
        print(Fore.CYAN + "          # ")
        for alias in aliases:
            if alias['type'] != 'port': continue
            definition = "          - { name: \"" + alias['name'] + "\", type: \"port\", address: \"" + alias['address'] + "\""
            if 'descr' in alias:
                definition = definition + ", descr: \"" + alias['descr'] + "\""
            definition = definition + ", state: \"present\" }"
            print(Fore.GREEN + definition)


class PFSenseRuleFactory(object):
    """ Class generating rules definitions """

    def __init__(self, data):
        self._data = data
        self._decomposer = PFSenseRuleDecomposer(data)

    def rule_interfaces_any(self, rule_obj):
        """ Return interfaces list on which the rule is needed to be defined
            Manage rules with any src or dst """
        src = rule_obj.src[0]
        dst = rule_obj.dst[0]

        if src.name == 'any' and dst.name == 'any':
            # we return all interfaces of target
            return set(self._data.target.interfaces.keys())
        elif src.name == 'any':
            # if the destination is local, we return all interfaces of target
            if dst.is_whole_local(self._data.target):
                return set(self._data.target.interfaces.keys())

            # otherwise we return all interfaces of target if the destination is routable
            # (we must be able to reach the destination to allow any src to access it)
            for iface, interface in self._data.target.interfaces.items():
                if dst.match_interface(interface, False):
                    return set(self._data.target.interfaces.keys())
            return set()

        elif rule_obj.dst[0].name == 'any':
            # we allow the interfaces matching the source ip/networks
            interfaces = set()
            for iface, interface in self._data.target.interfaces.items():
                if src.match_interface_src(interface):
                    interfaces.add(iface)
            return interfaces
        return None

    def rule_interfaces(self, rule_obj):
        """ Return interfaces list on which the rule is needed to be defined """

        assert len(rule_obj.src) == 1
        assert len(rule_obj.dst) == 1

        interfaces = self.rule_interfaces_any(rule_obj)
        if interfaces: return interfaces

        interfaces = set()
        src_is_local = rule_obj.src[0].is_whole_local(self._data.target)
        dst_is_local = rule_obj.dst[0].is_whole_local(self._data.target)

        # if source and dst are local, nothing to do
        if src_is_local and dst_is_local:
            return []

        # if source and dst are not local, nothing to do
        # we may have to remove that to allow 2 remote networks to communicate threw us
        if not src_is_local and not dst_is_local:
            return []

        # if the destination is unreachable
        if not dst_is_local and not rule_obj.dst[0].is_routed(self._data.target):
            return []

        target = rule_obj.src[0]
        if self._data.target.name in target.interfaces_src:
            for iface in target.interfaces_src[self._data.target.name]:
                interfaces.add(iface)
        return list(interfaces)

    @staticmethod
    def generate_rule(name, rule_obj, interfaces, last_name):
        """ Generate rules definitions for rule """
        base = []
        base.append({})

        assert len(rule_obj.src) == 1
        assert len(rule_obj.dst) == 1

        rule = {}
        rule['src'] = rule_obj.src[0].name
        rule['dst'] = rule_obj.dst[0].name
        if rule_obj.src_port: rule['src_port'] = ' '.join(rule_obj.src_port)
        if rule_obj.dst_port: rule['dst_port'] = ' '.join(rule_obj.dst_port)
        if rule_obj.protocol: rule['protocol'] = ' '.join(rule_obj.protocol)

        rule['src'] = cross_ports(rule, 'src', 'src_port')
        rule['dst'] = cross_ports(rule, 'dst', 'dst_port')

        base = cross_dict(base, rule, 'src', 'source')
        base = cross_dict(base, rule, 'dst', 'destination')
        base = cross_dict(base, rule, 'protocol')

        for interface in rule_obj.interfaces:
            if len(base) == 1:
                definition = {}
                definition['name'] = name
                definition['action'] = rule_obj.action
                definition['log'] = rule_obj.log
                definition['interface'] = interface
                if last_name: definition['after'] = last_name[interface]
                definition.update(base[0])
                interfaces[interface].append(definition)
                last_name[interface] = name
            else:
                rule_idx = 1
                for rule_def in base:
                    definition = {}
                    rule_name = name + "_" + str(rule_idx)
                    definition['name'] = rule_name
                    definition['action'] = rule_obj.action
                    definition['log'] = rule_obj.log
                    definition['interface'] = interface
                    if last_name: definition['after'] = last_name[interface]
                    definition.update(rule_def)
                    interfaces[interface].append(definition)
                    last_name[interface] = rule_name
                    rule_idx = rule_idx + 1

    def generate_rules(self):
        """ Return rules definitions for pfsense_rules_aggregate """

        self._decomposer.decompose_rules()
        ret = []

        interfaces = {}
        last_name = {}
        rules = {}
        for name, rule in self._data.rules_obj.items():
            subrules = []
            for subrule in rule.sub_rules:
                subrule.interfaces = self.rule_interfaces(subrule)
                if not subrule.interfaces: continue
                subrules.append(subrule)
                for interface in subrule.interfaces:
                    if interface not in interfaces:
                        interfaces[interface] = []
                        last_name[interface] = ""
            if len(subrules) > 1:
                rule_number = 1
                for subrule in subrules:
                    rules[name + "_" + str(rule_number)] = subrule
                    rule_number += 1
            elif len(subrules) == 1:
                rules[name] = subrules[0]

        for name, rule in rules.items():
            self.generate_rule(name, rule, interfaces, last_name)

        ret = []
        for name, interface in interfaces.items():
            for rule in interface:
                ret.append(rule)

        return ret

    def output_rules(self, rules=None):
        """ Output aliases definitions for pfsense_aliases_aggregate """
        if not rules:
            rules = self.generate_rules()
        print(Fore.CYAN + "          #===========================")
        print(Fore.CYAN + "          # Rules")
        print(Fore.CYAN + "          # ")
        for rule in rules:
            definition = "          - { name: \"" + rule['name'] + "\", source: \"" + rule['source'] + "\", destination: \"" + rule['destination'] + "\", interface: \"" + rule['interface'] + "\", action: \"" + rule['action'] + "\""
            if 'protocol' in rule: definition = definition + ", protocol: \"" + rule['protocol'] + "\""
            if 'descr' in rule: definition = definition + ", descr: \"" + rule['descr'] + "\""
            if 'log' in rule: definition = definition + ", log: \"" + rule['log'] + "\""
            if 'after' in rule: definition = definition + ", after: \"" + rule['after'] + "\""
            definition = definition + ", state: \"present\" }"
            print(Fore.GREEN + definition)


class LookupModule(LookupBase):
    """ Lookup module generating pfsense definitions """

    def load_data(self, from_file):
        """ Load and return pfsense data """
        myvars = getattr(self._templar, '_available_variables', {})
        current_host = myvars['inventory_hostname']

        fvars = ordered_load(open(from_file), yaml.SafeLoader)
        data = PFSenseData(
            sites=fvars['sites'],
            hosts_aliases=fvars['hosts_aliases'],
            ports_aliases=fvars['ports_aliases'],
            pfsenses=fvars['pfsenses'],
            rules=fvars['rules'],
            target_name=current_host
        )
        return data

    def run(self, terms, variables, **kwargs):
        """ Main function """
        colorama.init()

        data = self.load_data(terms[0])
        if not data.cleanup_defs():
            raise AnsibleError("Error parsing pfsense data")

        checker = PFSenseDataChecker(data)
        if not checker.check_defs():
            raise AnsibleError("Error checking pfsense data")

        alias_factory = PFSenseAliasFactory(data)
        rule_factory = PFSenseRuleFactory(data)

        rules = rule_factory.generate_rules()
        aliases = alias_factory.generate_aliases()

        if terms[1] == 'gen_aliases':
            return [aliases]
        elif terms[1] == 'gen_rules':
            return [rules]

        return []
