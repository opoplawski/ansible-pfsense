# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import sys
if sys.version_info >= (3, 4):
    import html
import json
import shutil
import os
import pwd
import random
import re
import time
import xml.etree.ElementTree as ET
from tempfile import mkstemp


class PFSenseModule(object):
    """ class managing pfsense base configuration """

    # pylint: disable=bad-option-value, import-outside-toplevel
    from ansible_collections.pfsensible.core.plugins.module_utils.__impl.interfaces import (
        get_interface_display_name,
        get_interface_elt,
        get_interface_port,
        get_interface_port_by_display_name,
        get_interface_by_display_name,
        get_interface_by_port,
        get_interfaces_networks,
        is_interface_display_name,
        is_interface_group,
        is_interface_port,
        parse_interface,
    )
    from ansible_collections.pfsensible.core.plugins.module_utils.__impl.addresses import (
        is_ipv4_address,
        is_ipv6_address,
        is_ipv4_network,
        is_ipv6_network,
        is_ip_network,
        is_within_local_networks,
        parse_address,
        parse_ip_network,
        parse_port,
    )
    from ansible_collections.pfsensible.core.plugins.module_utils.__impl.checks import check_name, check_ip_address

    def __init__(self, module, config='/cf/conf/config.xml'):
        self.module = module
        self.config = config
        self.tree = ET.parse(config)
        self.root = self.tree.getroot()
        self.config_version = float(self.get_element('version').text)
        self.aliases = self.get_element('aliases')
        self.interfaces = self.get_element('interfaces')
        self.ifgroups = self.get_element('ifgroups')
        self.rules = self.get_element('filter')
        self.shapers = self.get_element('shaper')
        self.dnshapers = self.get_element('dnshaper')
        self.vlans = self.get_element('vlans')
        self.gateways = self.get_element('gateways')
        self.ipsec = self.get_element('ipsec')
        self.openvpn = self.get_element('openvpn')
        self.virtualip = self.get_element('virtualip')
        self.debug = open('/tmp/pfsense.debug', 'w')
        if sys.version_info >= (3, 4):
            self._scrub()

        self.pfsense_version = None

    # Work around pfSense CDATA xml formatting issue
    # https://github.com/opoplawski/ansible-pfsense/issues/61
    def _scrub(self):
        for elt in self.root.iter():
            if elt.text is not None:
                elt.text = html.unescape(elt.text)

    @staticmethod
    def addr_normalize(addr):
        """ return address element formatted like module argument """
        address = ''
        ports = ''
        if 'address' in addr:
            address = addr['address']
        if 'any' in addr:
            address = 'any'
        if 'network' in addr:
            address = 'NET:%s' % addr['network']
        if address == '':
            raise ValueError('UNKNOWN addr %s' % addr)
        if 'port' in addr:
            ports = addr['port']
        if 'not' in addr:
            address = '!' + address
        return address, ports

    @staticmethod
    def new_element(tag, text='\n\t\t\t'):
        """ Create and return new XML configuration element  """
        elt = ET.Element(tag)
        # Attempt to preserve some of the formatting of pfSense's config.xml
        elt.text = text
        elt.tail = '\n\t\t'
        return elt

    def get_element(self, node, root_elt=None, create_node=False):
        """ return <node> configuration element """
        if root_elt is None:
            root_elt = self.root
        elt = root_elt.find(node)
        if elt is None and create_node:
            elt = self.new_element(node)
            root_elt.append(elt)
        return elt

    def get_elements(self, node, root_elt=None):
        """ return all <node> configuration elements  """
        if root_elt is None:
            root_elt = self.root
        return root_elt.findall(node)

    def get_index(self, elt, root_elt=None):
        """ Get elt index  """
        if root_elt is None:
            root_elt = self.root
        return list(root_elt).index(elt)

    def find_elt(self, node, search_text, search_field='descr', root_elt=None, multiple_ok=False):
        """ return object elt if found """
        search_xpath = "{0}[{1}='{2}']".format(node, search_field, search_text)
        return self.find_elt_xpath(search_xpath, root_elt, multiple_ok)

    def find_elt_xpath(self, search_xpath, root_elt=None, multiple_ok=False):
        """ return object elt if found """
        if root_elt is None:
            root_elt = self.root
        result = root_elt.findall(search_xpath)
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            if multiple_ok:
                return result
            else:
                self.module.fail_json(msg='Found multiple groups for name {0}.'.format(self.obj['name']))
        return None

    @staticmethod
    def remove_deleted_param_from_elt(elt, param, params):
        """ Remove from a deleted param from an xml elt """
        changed = False
        if param not in params:
            param_elt = elt.find(param)
            if param_elt is not None:
                changed = True
                elt.remove(param_elt)
        return changed

    def is_ipsec_enabled(self):
        """ return True if ipsec is enabled """
        if self.ipsec is None:
            return False

        for elt in self.ipsec:
            if elt.tag == 'phase1' and elt.find('disabled') is None:
                return True
        return False

    def is_openvpn_enabled(self):
        """ return True if openvpn is enabled """
        if self.openvpn is None:
            return False

        for elt in self.openvpn:
            if elt.tag == 'openvpn-server' or elt.tag == 'openvpn-client':
                return True
        return False

    def find_ipsec_phase1(self, field_value, field='descr'):
        """ return ipsec phase1 elt if found """
        for ipsec_elt in self.ipsec:
            if ipsec_elt.tag != 'phase1':
                continue

            field_elt = ipsec_elt.find(field)
            if field_elt is not None and field_elt.text == field_value:
                return ipsec_elt

        return None

    @staticmethod
    def rule_match_interface(rule_elt, interface, floating):
        """ check if a rule elt match the targeted interface
            floating rules must match the floating mode instead of the interface name
        """
        interface_elt = rule_elt.find('interface')
        floating_elt = rule_elt.find('floating')
        if floating_elt is not None:
            return floating
        elif floating:
            return False
        return interface_elt is not None and interface_elt.text == interface

    def get_interface_rules_count(self, interface, floating):
        """ get rules count in interface/floating """
        count = 0
        for rule_elt in self.rules:
            if not self.rule_match_interface(rule_elt, interface, floating):
                continue
            count += 1

        return count

    def get_rule_position(self, descr, interface, floating):
        """ get rule position in interface/floating """
        i = 0
        for rule_elt in self.rules:
            if not self.rule_match_interface(rule_elt, interface, floating):
                continue
            descr_elt = rule_elt.find('descr')
            if descr_elt is not None and descr_elt.text == descr:
                return i
            i += 1

        return None

    def copy_dict_to_element(self, src, top_elt, sub=0):
        """ Copy/update top_elt from src """
        changed = False
        for (key, value) in src.items():
            self.debug.write('changed=%s key=%s value=%s\n' % (changed, key, value))
            this_elt = top_elt.find(key)
            if this_elt is None:
                changed = True
                if isinstance(value, dict):
                    self.debug.write('calling copy_dict_to_element()\n')
                    # Create a new element
                    new_elt = ET.Element(key)
                    new_elt.text = '\n%s' % ('\t' * (sub + 4))
                    new_elt.tail = '\n%s' % ('\t' * (sub + 3))
                    self.copy_dict_to_element(value, new_elt, sub=sub + 1)
                    top_elt.append(new_elt)
                elif isinstance(value, list):
                    for item in value:
                        new_elt = self.new_element(key)
                        new_elt.text = item
                        top_elt.append(new_elt)
                else:
                    # Create a new element
                    new_elt = ET.Element(key)
                    new_elt.text = value
                    new_elt.tail = '\n%s' % ('\t' * (sub + 3))
                    top_elt.append(new_elt)
                self.debug.write('changed=%s added key=%s value=%s tag=%s\n' % (changed, key, value, top_elt.tag))
            else:
                if isinstance(value, dict):
                    self.debug.write('calling copy_dict_to_element()\n')
                    if self.copy_dict_to_element(value, this_elt, sub=sub + 1):
                        changed = True
                elif isinstance(value, list):
                    all_sub_elts = top_elt.findall(key)

                    # remove extra elts
                    while len(all_sub_elts) > len(value):
                        top_elt.remove(all_sub_elts.pop())
                        changed = True

                    # add new elts
                    while len(all_sub_elts) < len(value):
                        new_elt = self.new_element(key)
                        top_elt.append(new_elt)
                        all_sub_elts.append(new_elt)
                        changed = True

                    # set all elts
                    for idx, item in enumerate(value):
                        if isinstance(item, str):
                            if all_sub_elts[idx].text is None and item == '':
                                pass
                            elif all_sub_elts[idx].text != item:
                                all_sub_elts[idx].text = item
                                changed = True
                        elif self.copy_dict_to_element(item, all_sub_elts[idx], sub=sub + 1):
                            changed = True
                elif this_elt.text is None and value == '':
                    pass
                elif this_elt.text != value:
                    this_elt.text = value
                    changed = True
                self.debug.write('changed=%s this_elt.text=%s value=%s\n' % (changed, this_elt.text, value))
        # Sub-elements must be completely described, so remove any missing elements
        if sub:
            for child_elt in list(top_elt):
                if child_elt.tag not in src:
                    changed = True
                    self.debug.write('changed=%s removed tag=%s\n' % (changed, child_elt.tag))
                    top_elt.remove(child_elt)

        return changed

    @staticmethod
    def element_to_dict(src_elt):
        """ Create dict from XML src_elt """
        res = {}
        for elt in src_elt:
            if len(elt) > 0:
                value = PFSenseModule.element_to_dict(elt)
            else:
                value = elt.text if elt.text is not None else ''

            if elt.tag in res:
                if not isinstance(res[elt.tag], list):
                    res[elt.tag] = [res[elt.tag]]
                res[elt.tag].append(value)
            else:
                res[elt.tag] = value
        return res

    def get_caref(self, name):
        """ get CA refid for name """
        # global is a special case
        if name == 'global':
            return 'global'
        # Otherwise search for added CAs
        cas = self.get_elements('ca')
        for elt in cas:
            if elt.find('descr').text == name:
                return elt.find('refid').text
        return None

    @staticmethod
    def get_username():
        """ get username logged """
        username = pwd.getpwuid(os.getuid()).pw_name
        if os.environ.get('SUDO_USER'):
            username = os.environ.get('SUDO_USER')
        # sudo masks this
        sshclient = os.environ.get('SSH_CLIENT')
        if sshclient:
            username = username + '@' + sshclient
        return username

    def find_alias(self, name, aliastype=None):
        """ return alias named name, having type aliastype if specified """
        for alias in self.aliases:
            if alias.find('name').text == name and (aliastype is None or alias.find('type').text == aliastype):
                return alias
        return None

    def is_ip_or_alias(self, address):
        """ return True if address is an ip or an alias """
        # Is it an alias?
        if (self.find_alias(address, 'host') is not None
                or self.find_alias(address, 'network') is not None
                or self.find_alias(address, 'urltable') is not None
                or self.find_alias(address, 'urltable_ports') is not None):
            return True

        # Is it an IP address or network?
        if self.is_ipv4_address(address) or self.is_ipv4_network(address) or self.is_ipv6_address(address) or self.is_ipv6_network(address):
            return True

        # None of the above
        return False

    def is_port_or_alias(self, port):
        """ return True if port is a valid port number or an alias """
        if self.find_alias(port, 'port') is not None:
            return True
        try:
            if int(port) > 0 and int(port) < 65536:
                return True
        except ValueError:
            pass
        return False

    def is_virtual_ip(self, addr):
        """ return True if addr is a virtual ip """
        if self.virtualip is None:
            return False

        if self.find_elt('vip', addr, 'subnet', root_elt=self.virtualip) is None:
            return False

        return True

    def get_virtual_ip_interface(self, vip):
        """ return interface name for virtual IP name or network """
        if self.virtualip is None:
            return None

        vip_elt = self.find_elt('vip', vip, 'descr', root_elt=self.virtualip)
        if vip_elt is None:
            vip_elt = self.find_elt('vip', vip, 'subnet', root_elt=self.virtualip)

        if vip_elt is None:
            return None

        uniqid_elt = vip_elt.find('uniqid')
        if uniqid_elt is None:
            return None

        return "_vip" + vip_elt.find('uniqid').text

    def find_queue(self, name, interface=None, enabled=False):
        """ return QOS queue if found """

        # iterate each interface
        for shaper_elt in self.shapers:
            if interface is not None:
                interface_elt = shaper_elt.find('interface')
                if interface_elt is None or interface_elt.text != interface:
                    continue

            if enabled:
                enabled_elt = shaper_elt.find('enabled')
                if enabled_elt is None or enabled_elt.text != 'on':
                    continue

            # iterate each queue
            for queue_elt in shaper_elt.findall('.//queue'):
                name_elt = queue_elt.find('name')
                if name_elt is None or name_elt.text != name:
                    continue

                if enabled:
                    enabled_elt = queue_elt.find('enabled')
                    if enabled_elt is None or enabled_elt.text != 'on':
                        continue

                # found it
                return queue_elt

        return None

    def find_limiter(self, name, enabled=False):
        """ return QOS limiter if found """

        # iterate each queue
        for queue_elt in self.dnshapers:
            if enabled:
                enabled_elt = queue_elt.find('enabled')
                if enabled_elt is None or enabled_elt.text != 'on':
                    continue

            name_elt = queue_elt.find('name')
            if name_elt is None or name_elt.text != name:
                continue

            return queue_elt

        return None

    def find_vlan(self, interface, tag):
        """ return vlan elt if found """
        if self.vlans is None:
            self.vlans = self.get_element('vlans')

        if self.vlans is not None:
            for vlan in self.vlans:
                if vlan.find('if').text == interface and vlan.find('tag').text == tag:
                    return vlan

        return None

    def _create_gw_elt(self, name, interface_id, protocol):
        gw_elt = ET.Element('gateway_item')
        gw_elt.append(self.new_element('interface', interface_id))
        gw_elt.append(self.new_element('gateway', 'dynamic'))
        gw_elt.append(self.new_element('name', name))
        gw_elt.append(self.new_element('weight', '1'))
        gw_elt.append(self.new_element('ipprotocol', protocol))
        gw_elt.append(self.new_element('descr', 'Interface ' + name + ' Gateway'))
        return gw_elt

    def find_gateway_elt(self, name, interface=None, protocol=None, dhcp=False, vti=False):
        """ return gateway elt if found """
        for gw_elt in self.gateways:
            if gw_elt.tag != 'gateway_item':
                continue

            if protocol is not None and gw_elt.find('ipprotocol').text != protocol:
                continue

            if interface is not None and gw_elt.find('interface').text != interface:
                continue

            if gw_elt.find('name').text == name:
                return gw_elt

        for interface_elt in self.interfaces:
            descr_elt = interface_elt.find('descr')
            if descr_elt is None or descr_elt.text is None:
                continue

            if_elt = interface_elt.find('if')
            if if_elt is None or if_elt.text is None:
                continue

            descr_text = descr_elt.text.strip().upper()

            # todo: implement interface match with ipsec tunnels threw vtimaps
            if vti and (protocol is None or protocol == 'inet') and if_elt.text.startswith('ipsec') and descr_text + '_VTIV4' == name:
                return self._create_gw_elt(name, interface_elt.tag, 'inet')

            if vti and (protocol is None or protocol == 'inet6') and if_elt.text.startswith('ipsec') and descr_text + '_VTIV6' == name:
                return self._create_gw_elt(name, interface_elt.tag, 'inet6')

            if dhcp:
                ipaddr_elt = interface_elt.find('ipaddr')
                if (protocol is None or protocol == 'inet') and ipaddr_elt is not None and ipaddr_elt.text == 'dhcp' and descr_text + "_DHCP" == name:
                    return self._create_gw_elt(name, interface_elt.tag, 'inet')

                ipaddr_elt = interface_elt.find('ipaddrv6')
                if (protocol is None or protocol == 'inet6') and ipaddr_elt is not None and ipaddr_elt.text == 'dhcp6' and descr_text + "_DHCP6" == name:
                    return self._create_gw_elt(name, interface_elt.tag, 'inet6')

        return None

    def find_gateway_group_elt(self, name, protocol='inet'):
        """ return gateway_group elt if found """
        for gw_grp_elt in self.gateways:
            if gw_grp_elt.tag != 'gateway_group':
                continue
            if gw_grp_elt.find('name').text != name:
                continue

            # check if protocol match
            match_protocol = True
            for gw_elt in gw_grp_elt:
                if gw_elt.tag != 'item' or gw_elt.text is None:
                    continue

                items = gw_elt.text.split('|')
                if not items or self.find_gateway_elt(items[0], None, protocol) is None:
                    match_protocol = False
                    break

            if not match_protocol:
                continue

            return gw_grp_elt

        return None

    def find_ca_elt(self, ca, search_field='descr'):
        """ return certificate authority elt if found """
        return self.find_elt('ca', ca, search_field)

    def find_cert_elt(self, cert, search_field='descr'):
        """ return certificate elt if found """
        return self.find_elt('cert', cert, search_field)

    def find_crl_elt(self, crl, search_field='descr'):
        """ return certificate revocation list elt if found """
        return self.find_elt('crl', crl, search_field)

    def find_schedule_elt(self, name):
        """ return schedule elt if found """
        return self.find_elt_xpath("./schedules/schedule[name='{0}']".format(name))

    @staticmethod
    def uniqid(prefix='', more_entropy=False):
        """ return an identifier based on time """
        if more_entropy:
            return prefix + hex(int(time.time()))[2:10] + hex(int(time.time() * 1000000) % 0x100000)[2:7] + "%.8F" % (random.random() * 10)

        return prefix + hex(int(time.time()))[2:10] + hex(int(time.time() * 1000000) % 0x100000)[2:7]

    def phpshell(self, command):
        """ Run a command in the php developer shell """
        command = "global $debug;\n$debug = 1;\n" + command + "\nexec\nexit"
        # Dummy argument suppresses displaying help message
        return self.module.run_command('/usr/local/sbin/pfSsh.php dummy', data=command)

    def php(self, command):
        """ Run a command in php and return the output """
        cmd = '<?php\n'
        cmd += command
        cmd += '\n?>\n'
        (dummy, stdout, stderr) = self.module.run_command('/usr/local/bin/php', data=cmd)
        # TODO: check stderr for errors
        return json.loads(stdout)

    def write_config(self, descr='Updated by ansible pfsense module'):
        """ Generate config file """
        revision = self.get_element('revision')
        revision.find('time').text = '%d' % time.time()
        revdescr = revision.find('description')
        if revdescr is None:
            revdescr = ET.Element('description')
            revision.append(revdescr)
        revdescr.text = descr
        username = self.get_username()
        revision.find('username').text = username
        (tmp_handle, tmp_name) = mkstemp()
        os.close(tmp_handle)
        if sys.version_info >= (3, 4):
            self.tree.write(tmp_name, xml_declaration=True, method='xml', short_empty_elements=False)
        else:
            self.tree.write(tmp_name, xml_declaration=True, method='xml')
        shutil.move(tmp_name, self.config)
        os.chmod(self.config, 0o644)
        try:
            os.remove('/tmp/config.cache')
        except OSError as exception:
            if exception.errno == 2:
                # suppress "No such file or directory error
                pass
            else:
                raise

    @staticmethod
    def get_version():
        """ get pfSense version """
        # TODO: use subprocess when we'll drop support for python 2.7
        os.system("pkg-static info | grep pfSense-base > /tmp/pfVersion")
        vfile = open("/tmp/pfVersion", "r")
        version = vfile.read().replace("pfSense-base-", "").split()[0]
        vfile.close()
        return version

    @staticmethod
    def is_ce_version(version):
        """ return True if version is a CE version (for now, we only have 2.x patterns) """
        return version[0] == 2

    def is_version(self, version, or_more=True):
        """ check target pfSense version """
        if self.pfsense_version is None:
            pfsense_version = self.get_version()
            self.pfsense_version = []
            match = re.match(r'(\d+)\.(\d+)\.?(\d+)?', pfsense_version)
            if match is None:
                self.module.fail_json(msg="Unable to get version from pfSense (got '{0}')".format(pfsense_version))
            for idx in range(0, match.lastindex):
                self.pfsense_version.append(int(match.group(idx + 1)))

        # we must compare a CE with a CE or pfSense+ with pfSense+
        is_ce_in = self.is_ce_version(version)
        is_ce = self.is_ce_version(self.pfsense_version)
        if is_ce != is_ce_in:
            return False

        for idx, ver in enumerate(version):
            if idx == len(self.pfsense_version):
                return True

            if ver < self.pfsense_version[idx] and not or_more or ver > self.pfsense_version[idx]:
                return False

        return True

    def is_at_least_2_5_0(self):
        """ check target pfSense version """
        return self.is_version([2, 5, 0]) or self.is_version([21, 2])

    def apply_ipsec_changes(self):
        """ execute pfSense code to appy ipsec changes """
        if self.is_at_least_2_5_0():
            return self.phpshell(
                "require_once('vpn.inc');"
                "$ipsec_dynamic_hosts = ipsec_configure();"
                "ipsec_reload_package_hook();"
                "$retval = 0;"
                "$retval |= filter_configure();"
                "if ($ipsec_dynamic_hosts >= 0 && is_subsystem_dirty('ipsec'))"
                "    clear_subsystem_dirty('ipsec');"
            )
        return self.phpshell(
            "require_once('vpn.inc');"
            "$ipsec_dynamic_hosts = vpn_ipsec_configure();"
            "$retval = 0;"
            "$retval |= filter_configure();"
            "if ($ipsec_dynamic_hosts >= 0 && is_subsystem_dirty('ipsec'))"
            "   clear_subsystem_dirty('ipsec');"
        )
