# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
import re
from ansible.module_utils.network.pfsense.pfsense import PFSenseModule, PFSenseModuleBase
from ansible.module_utils.network.pfsense.pfsense_rule import PFSenseRuleModule
from ansible.module_utils.compat.ipaddress import ip_network

INTERFACE_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),
    descr=dict(required=True, type='str'),
    interface=dict(required=False, type='str'),
    enable=dict(required=False, type='bool'),
    ipv4_type=dict(default='none', choices=['none', 'static']),
    mac=dict(required=False, type='str'),
    mtu=dict(required=False, type='int'),
    mss=dict(required=False, type='int'),
    speed_duplex=dict(default='autoselect', required=False, type='str'),
    ipv4_address=dict(required=False, type='str'),
    ipv4_prefixlen=dict(default=24, required=False, type='int'),
    ipv4_gateway=dict(required=False, type='str'),
    create_ipv4_gateway=dict(required=False, type='bool'),
    ipv4_gateway_address=dict(required=False, type='str'),
    blockpriv=dict(required=False, type='bool'),
    blockbogons=dict(required=False, type='bool'),
)

INTERFACE_REQUIRED_IF = [
    ["state", "present", ["interface", "ipv4_type"]],
    ["ipv4_type", "static", ["ipv4_address", "ipv4_prefixlen"]],
    ["create_ipv4_gateway", True, ["ipv4_gateway_address"]],
]


class PFSenseInterfaceModule(PFSenseModuleBase):
    """ module managing pfsense interfaces """

    def __init__(self, module, pfsense=None):
        if pfsense is None:
            pfsense = PFSenseModule(module)
        self.module = module
        self.pfsense = pfsense
        self.interfaces = self.pfsense.interfaces

        self.change_descr = ''

        self.result = {}
        self.result['changed'] = False
        self.result['commands'] = []

        self._params = None

    def _update(self):
        """ make the target pfsense reload aliases """
        return self.pfsense.phpshell('''require_once("filter.inc");
if (filter_configure() == 0) { clear_subsystem_dirty('interfaces'); }''')

    def _get_media_mode(self, interface):
        """ Find all possible media options for the interface """
        return self.pfsense.php(
            '$mediaopts_list = array();\n'
            'exec("/sbin/ifconfig -m ' + interface + ' | grep \'media \'", $mediaopts);\n'
            'foreach ($mediaopts as $mediaopt) {\n'
            '        preg_match("/media (.*)/", $mediaopt, $matches);\n'
            '        if (preg_match("/(.*) mediaopt (.*)/", $matches[1], $matches1)) {\n'
            '                // there is media + mediaopt like "media 1000baseT mediaopt full-duplex"\n'
            '                array_push($mediaopts_list, $matches1[1] . " " . $matches1[2]);\n'
            '        } else {\n'
            '                // there is only media like "media 1000baseT"\n'
            '                array_push($mediaopts_list, $matches[1]);\n'
            '        }\n'
            '}\n'
            'echo json_encode($mediaopts_list);')

    def _get_interface_list(self):
        return self.pfsense.php(
            "require_once('/etc/inc/interfaces.inc');"
            "$portlist = get_interface_list();"
            ""
            "/* add wireless clone interfaces */"
            "if (is_array($config['wireless']['clone']) && count($config['wireless']['clone']))"
            "    foreach ($config['wireless']['clone'] as $clone)  $portlist[$clone['cloneif']] = $clone;"
            ""
            "/* add VLAN interfaces */"
            "if (is_array($config['vlans']['vlan']) && count($config['vlans']['vlan']))"
            "    foreach ($config['vlans']['vlan'] as $vlan)  $portlist[$vlan['vlanif']] = $vlan;"
            ""
            "/* add Bridge interfaces */"
            "if (is_array($config['bridges']['bridged']) && count($config['bridges']['bridged']))"
            "    foreach ($config['bridges']['bridged'] as $bridge) $portlist[$bridge['bridgeif']] = $bridge;"
            ""
            "/* add GIF interfaces */"
            "if (is_array($config['gifs']['gif']) && count($config['gifs']['gif']))"
            "    foreach ($config['gifs']['gif'] as $gif) $portlist[$gif['gifif']] = $gif;"
            ""
            "/* add GRE interfaces */"
            "if (is_array($config['gres']['gre']) && count($config['gres']['gre']))"
            "    foreach ($config['gres']['gre'] as $gre) $portlist[$gre['greif']] = $gre;"
            ""
            "/* add LAGG interfaces */"
            "if (is_array($config['laggs']['lagg']) && count($config['laggs']['lagg']))"
            "    foreach ($config['laggs']['lagg'] as $lagg) {"
            "        $portlist[$lagg['laggif']] = $lagg;"
            "        /* LAGG members cannot be assigned */"
            "        $lagifs = explode(',', $lagg['members']);"
            "        foreach ($lagifs as $lagif)"
            "            if (isset($portlist[$lagif])) unset($portlist[$lagif]);"
            "    }"
            ""
            "/* add QinQ interfaces */"
            "if (is_array($config['qinqs']['qinqentry']) && count($config['qinqs']['qinqentry']))"
            "    foreach ($config['qinqs']['qinqentry'] as $qinq) {"
            "        $portlist[\"{$qinq['vlanif']}\"] = $qinq;"
            "        /* QinQ members */"
            "        $qinqifs = explode(' ', $qinq['members']);"
            "        foreach ($qinqifs as $qinqif) $portlist[\"{$qinq['vlanif']}.{$qinqif}\"] = $qinqif;"
            "    }"
            ""
            "/* add PPP interfaces */"
            "if (is_array($config['ppps']['ppp']) && count($config['ppps']['ppp']))"
            "    foreach ($config['ppps']['ppp'] as $pppid => $ppp) $portlist[$ppp['if']] = $ppp;"
            ""
            "if (is_array($config['openvpn'])) {"
            "    if (is_array($config['openvpn']['openvpn-server']))"
            "        foreach ($config['openvpn']['openvpn-server'] as $s) $portlist[\"ovpns{$s['vpnid']}\"] = $s;"
            "    if (is_array($config['openvpn']['openvpn-client']))"
            "        foreach ($config['openvpn']['openvpn-client'] as $c)  $portlist[\"ovpns{$c['vpnid']}\"] = $c;"
            "}"
            ""
            "$ipsec_descrs = interface_ipsec_vti_list_all();"
            "foreach ($ipsec_descrs as $ifname => $ifdescr) $portlist[$ifname] = array('descr' => $ifdescr);"
            ""
            "echo json_encode(array_keys($portlist), JSON_PRETTY_PRINT);")

    def _log_create(self, interface):
        """ generate pseudo-CLI command to create an interface """
        log = "create interface '{0}'".format(interface['descr'])
        log += self.format_cli_field(interface, 'if', fname='port')
        log += self.format_cli_field(interface, 'enable', fvalue=self.fvalue_bool)
        log += self.format_cli_field(self._params, 'ipv4_type')
        log += self.format_cli_field(self._params, 'mac')
        log += self.format_cli_field(interface, 'mtu')
        log += self.format_cli_field(interface, 'mss')
        log += self.format_cli_field(interface, 'ipaddr', fname='ipv4_address')
        log += self.format_cli_field(interface, 'subnet', fname='ipv4_prefixlen')
        log += self.format_cli_field(interface, 'gateway', fname='ipv4_gateway')
        log += self.format_cli_field(interface, 'blockpriv', fvalue=self.fvalue_bool)
        log += self.format_cli_field(interface, 'blockbogons', fvalue=self.fvalue_bool)
        log += self.format_cli_field(self._params, 'speed_duplex', fname='speed_duplex')
        self.result['commands'].append(log)

    def _log_delete(self, interface):
        """ generate pseudo-CLI command to delete an interface """
        log = "delete interface '{0}'".format(interface['descr'])
        self.result['commands'].append(log)

    def _log_update(self, interface, before):
        """ generate pseudo-CLI command to update an interface """
        log = "update interface '{0}'".format(before['descr'])
        values = ''
        values += self.format_updated_cli_field(interface, before, 'descr', add_comma=(values), fname='interface')
        values += self.format_updated_cli_field(interface, before, 'if', add_comma=(values), fname='port')
        values += self.format_updated_cli_field(interface, before, 'enable', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(interface, before, 'ipv4_type', add_comma=(values), log_none='True')
        values += self.format_updated_cli_field(interface, before, 'spoofmac', add_comma=(values), fname='mac')
        values += self.format_updated_cli_field(interface, before, 'mtu', add_comma=(values))
        values += self.format_updated_cli_field(interface, before, 'mss', add_comma=(values))
        values += self.format_updated_cli_field(interface, before, 'media', add_comma=(values), fname='speed_duplex')
        values += self.format_updated_cli_field(interface, before, 'ipaddr', add_comma=(values), fname='ipv4_address')
        values += self.format_updated_cli_field(interface, before, 'subnet', add_comma=(values), fname='ipv4_prefixlen')
        values += self.format_updated_cli_field(interface, before, 'gateway', add_comma=(values), fname='ipv4_gateway')
        values += self.format_updated_cli_field(interface, before, 'blockpriv', add_comma=(values), fvalue=self.fvalue_bool)
        values += self.format_updated_cli_field(interface, before, 'blockbogons', add_comma=(values), fvalue=self.fvalue_bool)
        self.result['commands'].append(log + ' set ' + values)

    def _find_interface_elt(self, interface, name):
        """ return pfsense interface physical name """
        for iface in self.interfaces:
            descr_elt = iface.find('descr')
            if descr_elt is None:
                continue
            if iface.find('if').text.strip() == interface and descr_elt.text.strip().lower() == name.lower():
                return iface
        return None

    def _find_interface_elt_by_name(self, name):
        """ return pfsense interface by name """
        for iface in self.interfaces:
            descr_elt = iface.find('descr')
            if descr_elt is None:
                continue
            if descr_elt.text.strip().lower() == name.lower():
                return iface
        return None

    def _find_interface_elt_by_port(self, interface):
        """ find pfsense interface by port name """
        for iface in self.interfaces:
            if iface.find('if').text.strip() == interface:
                return iface
        return None

    def _find_interface_elt_by_tag(self, interface):
        """ find pfsense interface by port name """
        for iface in self.interfaces:
            if iface.tag == interface:
                return iface
        return None

    def _get_interface_name_by_physical_name(self, interface):
        """ return pfsense interface physical name """
        for iface in self.interfaces:
            if iface.find('if').text.strip() == interface:
                descr_elt = iface.find('descr')
                if descr_elt is not None:
                    return descr_elt.text.strip()
                return iface.tag

        return None

    def _find_matching_interface(self, interface, exact_match=False):
        """ return target interface """

        # we first try to find an interface having same name and physical
        interface_elt = self._find_interface_elt(interface['if'], interface['descr'])
        if interface_elt is not None or exact_match:
            return interface_elt

        # we then try to find an existing interface with the name
        interface_elt = self._find_interface_elt_by_name(interface['descr'])
        if interface_elt is not None:
            # we check the targeted physical interface can be used
            used_by = self._get_interface_name_by_physical_name(interface['if'])
            if used_by is not None:
                self.module.fail_json(msg='Port {0} is already in use on interface {1}'.format(interface['if'], used_by))
            return interface_elt

        # last, we  try to find an existing interface with the port (interface will be renamed)
        return self._find_interface_elt_by_port(interface['if'])

    def _create_interface_elt(self):
        """ find a free place to create an interface and return the elt """
        # wan can't be deleted, so the first interface we can create is lan
        if not self._find_interface_elt_by_tag('lan'):
            interface_elt = self.pfsense.new_element('lan')
            self.interfaces.insert(1, interface_elt)
            return interface_elt

        # lan is used, so we must create an optX interface
        i = 1
        while True:
            interface = 'opt{0}'.format(i)
            if not self._find_interface_elt_by_tag(interface):
                interface_elt = self.pfsense.new_element(interface)
                # i + 1 = i + (lan and wan) - 1
                self.interfaces.insert(i + 1, interface_elt)
                return interface_elt
            i = i + 1

    def _create_gateway(self, interface, interface_elt):
        """ create gateway is required """

        # todo: maybe it would be better to create a module to manage gateways and to call it there
        if interface.get('gateway') and not self.pfsense.find_gateway_elt(interface['gateway'], interface_elt.tag, 'inet'):
            if not self._params.get('create_ipv4_gateway'):
                self.module.fail_json(msg='Gateway {0} does not exist on {1}'.format(interface['gateway'], interface['descr']))

            gateway_elt = self.pfsense.new_element('gateway_item')
            gateway = {}
            gateway['interface'] = interface_elt.tag
            gateway['gateway'] = self._params['ipv4_gateway_address']
            gateway['name'] = interface['gateway']
            gateway['weight'] = ''
            gateway['ipprotocol'] = 'inet'
            gateway['descr'] = ''
            self.pfsense.copy_dict_to_element(gateway, gateway_elt)
            self.pfsense.gateways.append(gateway_elt)

            cmd = 'create gateway \'{0}\', interface=\'{1}\', ip=\'{2}\''.format(interface['gateway'], interface_elt.tag, self._params['ipv4_gateway_address'])
            self.result['commands'].append(cmd)

    def _check_overlaps(self, interface, interface_elt):
        """ check new address does not overlaps with one existing """

        if not interface.get('ipaddr'):
            return

        our_addr = ip_network(u'{0}/{1}'.format(interface['ipaddr'], interface['subnet']), strict=False)

        for iface in self.interfaces:
            if iface == interface_elt:
                continue

            ipaddr_elt = iface.find('ipaddr')
            subnet_elt = iface.find('subnet')
            if ipaddr_elt is None or subnet_elt is None:
                continue

            other_addr = ip_network(u'{0}/{1}'.format(ipaddr_elt.text, subnet_elt.text), strict=False)
            if our_addr.overlaps(other_addr):
                descr_elt = iface.find('descr')
                if descr_elt is not None and descr_elt.text:
                    ifname = descr_elt.text
                else:
                    ifname = iface.tag
                msg = 'IPv4 address {0}/{1} is being used by or overlaps with: {2} ({3}/{4})'.format(
                    interface['ipaddr'],
                    interface['subnet'],
                    ifname,
                    ipaddr_elt.text,
                    subnet_elt.text
                )
                self.module.fail_json(msg=msg)

    def _add(self, interface):
        """ add or update interface """
        interface_elt = self._find_matching_interface(interface)

        self._check_overlaps(interface, interface_elt)

        if interface_elt is None:
            interface_elt = self._create_interface_elt()
            self.pfsense.copy_dict_to_element(interface, interface_elt)
            self._create_gateway(interface, interface_elt)

            changed = True
            self.change_descr = 'ansible pfsense_interface added {0} on {1}'.format(interface['descr'], interface['if'])
            self._log_create(interface)
        else:
            before = self.pfsense.element_to_dict(interface_elt)
            changed = self.pfsense.copy_dict_to_element(interface, interface_elt)
            self._create_gateway(interface, interface_elt)

            if self._remove_deleted_interface_params(interface_elt, interface):
                changed = True

            if changed:
                self.change_descr = 'ansible pfsense_interface updated {0} on {1}'.format(interface['descr'], interface['if'])
                self._log_update(interface, before)

        if changed:
            self.result['changed'] = changed

    def _remove_deleted_interface_params(self, interface_elt, interface):
        """ Remove from rule a few deleted params """
        changed = False
        for param in ['mtu', 'mss', 'gateway', 'enable', 'mac', 'media', 'ipaddr', 'subnet', 'blockpriv', 'blockbogons']:
            if self.pfsense.remove_deleted_param_from_elt(interface_elt, param, interface):
                changed = True

        return changed

    def _remove_interface_elt(self, interface_elt):
        """ delete interface_elt from xml """
        self.interfaces.remove(interface_elt)
        self.result['changed'] = True

    def _remove_all_separators(self, interface):
        """ delete all interface separators """
        todel = []
        separators = self.pfsense.rules.find('separator')
        for interface_elt in separators:
            if interface_elt.tag != interface:
                continue
            for separator_elt in interface_elt:
                todel.append(separator_elt)
            for separator_elt in todel:
                cmd = 'delete rule_separator \'{0}\', interface=\'{1}\''.format(separator_elt.find('text').text, interface)
                self.result['commands'].append(cmd)
                interface_elt.remove(separator_elt)
            separators.remove(interface_elt)
            break

    def _remove_all_rules(self, interface):
        """ delete all interface rules """

        # we use the pfsense_rule module to delete the rules since, at least for floating rules,
        # it implies to recalculate separators positions
        # if we have to just remove the deleted interface of a floating rule we do it ourselves
        todel = []
        for rule_elt in self.pfsense.rules:
            if rule_elt.find('floating') is not None:
                interfaces = rule_elt.find('interface').text.split(',')
                if interface in interfaces:
                    if len(interfaces) > 1:
                        interfaces.remove(interface)
                        rule_elt.find('interface').text = ','.join(interfaces)
                        cmd = 'update rule \'{0}\', interface=\'floating\' set interface=\'{1}\''.format(rule_elt.find('descr').text, ','.join(interfaces))
                        self.result['commands'].append(cmd)
                        continue
                    todel.append(rule_elt)
                else:
                    continue
            else:
                iface = rule_elt.find('interface')
                if iface is not None and iface.text == interface:
                    todel.append(rule_elt)

        if todel:
            pfsense_rules = PFSenseRuleModule(self.module, self.pfsense)
            for rule_elt in todel:
                params = {}
                params['state'] = 'absent'
                params['name'] = rule_elt.find('descr').text
                params['interface'] = rule_elt.find('interface').text
                if rule_elt.find('floating') is not None:
                    params['floating'] = True
                pfsense_rules.run(params)
            if pfsense_rules.result['commands']:
                self.result['commands'].extend(pfsense_rules.result['commands'])

    def _remove(self, interface):
        """ delete interface """
        # todo:
        # - check if interface is part of a group, bridge, gre tunnel, gif tunnel or has a traffic shaper queue and block if any
        # - unconfigure dhcpd & dhcpdv6 if relevent
        # - delete nat rules if relevent
        interface_elt = self._find_interface_elt_by_name(interface['descr'])
        if interface_elt is not None:
            interface['if'] = interface_elt.find('if').text
            self._remove_all_separators(interface_elt.tag)
            self._remove_all_rules(interface_elt.tag)
            self._log_delete(interface)
            self._remove_interface_elt(interface_elt)
            self.change_descr = 'ansible pfsense_interface removed {0} on {1}'.format(interface['descr'], interface['if'])

    def _validate_params(self, params):
        """ do some extra checks on input parameters """
        # check name
        if re.match('^[a-zA-Z0-9_]+$', params['descr']) is None:
            self.module.fail_json(msg='The name of the interface may only consist of the characters "a-z, A-Z, 0-9 and _"')

        if params['state'] == 'present':
            if params.get('mac') and re.match('^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$', params['mac']) is None:
                self.module.fail_json(msg='MAC address must be in the following format: xx:xx:xx:xx:xx:xx (or blank).')

            # todo can't change mac address on vlan interface

            if params.get('ipv4_prefixlen') is not None and params['ipv4_prefixlen'] < 1 or params['ipv4_prefixlen'] > 32:
                self.module.fail_json(msg='ipv4_prefixlen must be between 1 and 32.')

            if params.get('mtu') is not None and params['mtu'] < 1:
                self.module.fail_json(msg='mtu must be above 0')

            if params.get('mss') is not None and params['mtu'] < 1:
                self.module.fail_json(msg='mtu must be above 0')

            interfaces = self._get_interface_list()
            if params['interface'] not in interfaces:
                self.module.fail_json(msg='{0} can\'t be assigned. Interface may only be one the following: {1}'.format(params['interface'], interfaces))

            media_modes = set(self._get_media_mode(params['interface']))
            media_modes.add('autoselect')
            if params.get('speed_duplex') and params['speed_duplex'] not in media_modes:
                self.module.fail_json(msg='For this interface, media mode may only be one the following: {0}'.format(media_modes))

            if params['ipv4_type'] == 'static':
                if params.get('ipv4_address') and not self.pfsense.is_ip_address(params['ipv4_address']):
                    self.module.fail_json(msg='{0} is not a valid ip address'.format(params['ipv4_address']))

            if params.get('create_ipv4_gateway'):
                if params.get('ipv4_gateway_address') and not self.pfsense.is_ip_address(params['ipv4_gateway_address']):
                    self.module.fail_json(msg='{0} is not a valid ip address'.format(params['ipv4_gateway_address']))

    def _params_to_interface(self, params):
        """ return an interface dict from module params """
        self._validate_params(params)

        interface = dict()
        interface['descr'] = params['descr']
        if params['state'] == 'present':
            interface['if'] = params['interface']

            if params.get('enable'):
                interface['enable'] = ''

            if params.get('mac'):
                interface['spoofmac'] = params['mac']
            else:
                interface['spoofmac'] = ''

            if params.get('mtu'):
                interface['mtu'] = str(params['mtu'])

            if params.get('mss'):
                interface['mss'] = str(params['mss'])

            if params.get('speed_duplex') and params['speed_duplex'] != 'autoselect':
                interface['media'] = params['speed_duplex']

            if params.get('blockpriv'):
                interface['blockpriv'] = ''

            if params.get('blockbogons'):
                interface['blockbogons'] = ''

            if params['ipv4_type'] == 'static':
                if params.get('ipv4_address'):
                    interface['ipaddr'] = params['ipv4_address']

                if params.get('ipv4_prefixlen'):
                    interface['subnet'] = str(params['ipv4_prefixlen'])

                if params.get('ipv4_gateway'):
                    interface['gateway'] = params['ipv4_gateway']

        return interface

    def commit_changes(self):
        """ apply changes and exit module """
        self.result['stdout'] = ''
        self.result['stderr'] = ''
        if self.result['changed'] and not self.module.check_mode:
            self.pfsense.write_config(descr=self.change_descr)
            (dummy, self.result['stdout'], self.result['stderr']) = self._update()

        self.module.exit_json(**self.result)

    def run(self, params):
        """ process input params to add/update/delete an interface """
        self._params = params
        interface = self._params_to_interface(params)

        if params['state'] == 'absent':
            self._remove(interface)
        else:
            self._add(interface)
