# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import time
import re

from ansible_collections.opoplawski.pfsense.plugins.module_utils.pfsense import PFSenseModule, PFSenseModuleBase

RULE_ARGUMENT_SPEC = dict(
    name=dict(required=True, type='str'),
    action=dict(default='pass', required=False, choices=['pass', "block", 'reject']),
    state=dict(default='present', choices=['present', 'absent']),
    disabled=dict(default=False, required=False, type='bool'),
    interface=dict(required=True, type='str'),
    floating=dict(required=False, type='bool'),
    direction=dict(required=False, choices=["any", "in", "out"]),
    ipprotocol=dict(required=False, default='inet', choices=['inet', 'inet46', 'inet6']),
    protocol=dict(default='any', required=False, choices=["any", "tcp", "udp", "tcp/udp", "icmp", "igmp"]),
    source=dict(required=False, type='str'),
    destination=dict(required=False, type='str'),
    log=dict(required=False, type='bool'),
    after=dict(required=False, type='str'),
    before=dict(required=False, type='str'),
    statetype=dict(required=False, default='keep state', choices=['keep state', 'sloppy state', 'synproxy state', 'none']),
    queue=dict(required=False, type='str'),
    ackqueue=dict(required=False, type='str'),
    in_queue=dict(required=False, type='str'),
    out_queue=dict(required=False, type='str'),
    gateway=dict(required=False, type='str', default='default'),
)

RULE_REQUIRED_IF = [
    ["floating", True, ["direction"]],
    ["state", "present", ["source", "destination"]]
]

# These are rule elements that are (currently) unmanaged by this module
RULE_UNMANAGED_ELEMENTS = [
    'created', 'id', 'max', 'max-src-conn', 'max-src-nodes', 'max-src-states', 'os',
    'statetimeout', 'statetype', 'tag', 'tagged', 'tracker', 'updated'
]


class PFSenseRuleModule(PFSenseModuleBase):
    """ module managing pfsense rules """

    def __init__(self, module, pfsense=None):
        if pfsense is None:
            pfsense = PFSenseModule(module)
        self.module = module
        self.pfsense = pfsense
        self.rules = self.pfsense.get_element('filter')

        self.changed = False
        self.change_descr = ''

        self.diff = {'after': {}, 'before': {}}

        self.result = {}
        self.result['added'] = []
        self.result['deleted'] = []
        self.result['modified'] = []
        self.result['commands'] = []

        # internals params
        self._rule = None
        self._descr = None
        self._interface = None
        self._floating = None
        self._after = None
        self._before = None
        self._params = None
        self._position_changed = False

    def _interface_name(self):
        """ return formated interface name for logging """
        if self._floating:
            return 'floating(' + self._interface + ')'
        return self._interface

    def _match_interface(self, rule_elt):
        """ check if a rule elt match the targeted interface """
        return self.pfsense.rule_match_interface(rule_elt, self._interface, self._floating)

    def _find_matching_rule(self):
        """ retturn rule element and index that matches by description or action """
        # Prioritize matching my name
        found, i = self._find_rule_by_descr(self._descr)
        if found is not None:
            return (found, i)

        # Match action without name/descr
        match_rule = self._rule.copy()
        del match_rule['descr']
        for rule_elt in self.rules:
            this_rule = self.pfsense.element_to_dict(rule_elt)
            this_rule.pop('descr', None)
            # Remove unmanaged elements
            for unwanted in RULE_UNMANAGED_ELEMENTS:
                this_rule.pop(unwanted, None)
            if this_rule == match_rule:
                return (rule_elt, i)
            i += 1

        return (None, -1)

    def _find_rule_by_descr(self, descr):
        """ return rule element and index on interface/floating that matches description """
        i = 0
        for rule_elt in self.rules:
            descr_elt = rule_elt.find('descr')
            if self._match_interface(rule_elt) and descr_elt is not None and descr_elt.text == descr:
                return (rule_elt, i)
            i += 1
        return (None, -1)

    def _adjust_separators(self, start_idx, add=True, before=False):
        """ update separators position """
        separators_elt = self.rules.find('separator')
        if separators_elt is None:
            return

        separators_elt = separators_elt.find(self._interface)
        if separators_elt is None:
            return

        for separator_elt in separators_elt:
            row_elt = separator_elt.find('row')
            if row_elt is None or row_elt.text is None:
                continue

            if_elt = separator_elt.find('if')
            if if_elt is None or if_elt.text != self._interface:
                continue

            match = re.match(r'fr(\d+)', row_elt.text)
            if match:
                idx = int(match.group(1))
                if add:
                    if before:
                        if idx > start_idx:
                            row_elt.text = 'fr' + str(idx + 1)
                    else:
                        if idx >= start_idx:
                            row_elt.text = 'fr' + str(idx + 1)
                elif idx > start_idx:
                    row_elt.text = 'fr' + str(idx - 1)

    def _get_first_rule_xml_index(self):
        """ Find the first rule for the interface/floating and return its xml index """
        i = 0
        for rule_elt in self.rules:
            if self._match_interface(rule_elt):
                break
            i += 1
        return i

    def _get_last_rule_xml_index(self):
        """ Find the last rule for the interface/floating and return its xml index """
        last_found = -1
        i = 0
        for rule_elt in self.rules:
            if self._match_interface(rule_elt):
                last_found = i
            i += 1
        return last_found

    def _get_rule_position(self, descr=None, fail=True):
        """ get rule position in interface/floating """
        if descr is None:
            descr = self._descr

        res = self.pfsense.get_rule_position(descr, self._interface, self._floating)
        if fail and res is None:
            self.module.fail_json(msg='Failed to find rule=%s interface=%s' % (descr, self._interface_name()))
        return res

    def _get_expected_rule_xml_index(self):
        """ get expected rule index in xml """
        if self._before == 'bottom':
            return self._get_last_rule_xml_index() + 1
        elif self._after == 'top':
            return self._get_first_rule_xml_index()
        elif self._after is not None:
            found, i = self._find_rule_by_descr(self._after)
            if found is not None:
                return i + 1
            else:
                self.module.fail_json(msg='Failed to insert after rule=%s interface=%s' % (self._after, self._interface_name()))
        elif self._before is not None:
            found, i = self._find_rule_by_descr(self._before)
            if found is not None:
                return i
            else:
                self.module.fail_json(msg='Failed to insert before rule=%s interface=%s' % (self._before, self._interface_name()))
        else:
            found, i = self._find_rule_by_descr(self._descr)
            if found is not None:
                return i
            return self._get_last_rule_xml_index() + 1
        return -1

    def _get_expected_rule_position(self):
        """ get expected rule position in interface/floating """
        if self._before == 'bottom':
            return self.pfsense.get_interface_rules_count(self._interface, self._floating) - 1
        elif self._after == 'top':
            return 0
        elif self._after is not None:
            return self._get_rule_position(self._after) + 1
        elif self._before is not None:
            position = self._get_rule_position(self._before) - 1
            if position < 0:
                return 0
            return position
        else:
            position = self._get_rule_position(self._after, fail=False)
            if position is not None:
                return position
            return self.pfsense.get_interface_rules_count(self._interface, self._floating)
        return -1

    def _insert(self, rule_elt):
        """ insert rule into xml """
        rule_xml_idx = self._get_expected_rule_xml_index()
        self.rules.insert(rule_xml_idx, rule_elt)

        rule_position = self._get_rule_position()
        self._adjust_separators(rule_position, before=(self._after is None and self._before is not None))

    def _update_rule_position(self, rule_elt):
        """ move rule in xml if required """
        current_position = self._get_rule_position()
        expected_position = self._get_expected_rule_position()
        if current_position == expected_position:
            self._position_changed = False
            return False

        self.diff['before']['position'] = current_position
        self.diff['after']['position'] = expected_position
        self._adjust_separators(current_position, add=False)
        self.rules.remove(rule_elt)
        self._insert(rule_elt)
        self._position_changed = True
        return True

    def _update(self):
        """ make the target pfsense reload rules """
        return self.pfsense.phpshell('''require_once("filter.inc");
if (filter_configure() == 0) { clear_subsystem_dirty('filter'); }''')

    def _log_create(self, rule):
        """ generate pseudo-CLI command to create a rule """
        log = "create rule '{0}'".format(rule['descr'])
        log += self.format_cli_field(self._params, 'source')
        log += self.format_cli_field(self._params, 'destination')
        log += self.format_cli_field(self._params, 'protocol')
        log += self.format_cli_field(self._params, 'interface')
        log += self.format_cli_field(self._params, 'floating')
        log += self.format_cli_field(self._params, 'direction')
        log += self.format_cli_field(self._params, 'ipprotocol', default='inet')
        log += self.format_cli_field(self._params, 'statetype', default='keep state')
        log += self.format_cli_field(self._params, 'action', default='pass')
        log += self.format_cli_field(self._params, 'disabled', default=False)
        log += self.format_cli_field(self._params, 'log', default=False)
        log += self.format_cli_field(self._params, 'after')
        log += self.format_cli_field(self._params, 'before')
        log += self.format_cli_field(self._params, 'queue')
        log += self.format_cli_field(self._params, 'ackqueue')
        log += self.format_cli_field(self._params, 'in_queue')
        log += self.format_cli_field(self._params, 'out_queue')
        log += self.format_cli_field(self._params, 'default', default='default')

        self.result['commands'].append(log)

    def _log_delete(self, rule):
        """ generate pseudo-CLI command to delete a rule """
        log = "delete rule '{0}'".format(rule['descr'])
        if self._floating:
            log += ", interface='floating'"
        else:
            log += ", interface='{0}'".format(self.pfsense.get_interface_display_name(self._interface))
        self.result['commands'].append(log)

    @staticmethod
    def _obj_address_to_log_field(rule, addr):
        """ return formated address from dict """
        field = ''
        if isinstance(rule[addr], dict):
            if 'any' in rule[addr]:
                field = 'any'
            if 'address' in rule[addr]:
                field = rule[addr]['address']
            if 'port' in rule[addr]:
                if field:
                    field += ':'
                field += rule[addr]['port']
        else:
            field = rule[addr]
        return field

    def _obj_to_log_fields(self, rule):
        """ return formated source and destination from dict """
        res = {}
        res['source'] = self._obj_address_to_log_field(rule, 'source')
        res['destination'] = self._obj_address_to_log_field(rule, 'destination')
        return res

    def _log_update(self, rule, before):
        """ generate pseudo-CLI command to update a rule """
        log = "update rule '{0}'".format(rule['descr'])
        if self._floating:
            log += ", interface='floating'"
        else:
            log += ", interface='{0}'".format(self.pfsense.get_interface_display_name(self._interface))

        fbefore = self._obj_to_log_fields(before)
        fafter = self._obj_to_log_fields(rule)
        fafter['before'] = self._before
        fafter['after'] = self._after

        values = ''
        values += self.format_updated_cli_field(fafter, fbefore, 'source', add_comma=(values))
        values += self.format_updated_cli_field(fafter, fbefore, 'destination', add_comma=(values))
        values += self.format_updated_cli_field(rule, before, 'protocol', add_comma=(values))
        values += self.format_updated_cli_field(rule, before, 'interface', add_comma=(values))
        values += self.format_updated_cli_field(rule, before, 'floating', add_comma=(values))
        values += self.format_updated_cli_field(rule, before, 'direction', add_comma=(values))
        values += self.format_updated_cli_field(rule, before, 'ipprotocol', add_comma=(values))
        values += self.format_updated_cli_field(rule, before, 'statetype', add_comma=(values))
        values += self.format_updated_cli_field(rule, before, 'action', add_comma=(values))
        values += self.format_updated_cli_field(rule, before, 'disabled', add_comma=(values))
        values += self.format_updated_cli_field(rule, before, 'log', add_comma=(values))
        if self._position_changed:
            values += self.format_updated_cli_field(fafter, {}, 'after', log_none=False, add_comma=(values))
            values += self.format_updated_cli_field(fafter, {}, 'before', log_none=False, add_comma=(values))
        values += self.format_updated_cli_field(rule, before, 'queue', add_comma=(values))
        values += self.format_updated_cli_field(rule, before, 'ackqueue', add_comma=(values))
        values += self.format_updated_cli_field(rule, before, 'in_queue', add_comma=(values))
        values += self.format_updated_cli_field(rule, before, 'out_queue', add_comma=(values))
        values += self.format_updated_cli_field(rule, before, 'gateway', add_comma=(values))

        self.result['commands'].append(log + ' set ' + values)

    def _parse_address(self, param):
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

            ret['network'] = self.pfsense.parse_interface(interface)
            if address == 'IP':
                ret['network'] += 'ip'
        else:
            ports = addr[1] if len(addr) > 1 else None
            if address == 'any':
                ret['any'] = None
            # rule with this firewall
            elif address == '(self)':
                ret['network'] = '(self)'
            # rule with interface name (LAN, WAN...)
            elif self.pfsense.is_interface_name(address):
                ret['network'] = self.pfsense.get_interface_pfsense_by_name(address)
            else:
                if not self.pfsense.is_ip_or_alias(address):
                    self.module.fail_json(msg='Cannot parse address %s, not IP or alias' % (address))
                ret['address'] = address

        if ports is not None:
            ports = ports.split('-')
            if len(ports) > 2 or ports[0] is None or ports[0] == '' or len(ports) == 2 and (ports[1] is None or ports[1] == ''):
                self.module.fail_json(msg='Cannot parse address %s' % (param))

            if not self.pfsense.is_port_or_alias(ports[0]):
                self.module.fail_json(msg='Cannot parse port %s, not port number or alias' % (ports[0]))
            ret['port'] = ports[0]

            if len(ports) > 1:
                if not self.pfsense.is_port_or_alias(ports[1]):
                    self.module.fail_json(msg='Cannot parse port %s, not port number or alias' % (ports[1]))
                ret['port'] += '-' + ports[1]

        return ret

    def _parse_floating_interfaces(self, interfaces):
        """ validate param interface field when floating is true """
        res = []
        for interface in interfaces.split(','):
            res.append(self.pfsense.parse_interface(interface))
        return ','.join(res)

    def _validate_params(self, params):
        """ do some extra checks on input parameters """
        if params.get('ackqueue') is not None and params['queue'] is None:
            self.module.fail_json(msg='A default queue must be selected when an acknowledge queue is also selected')

        if params.get('ackqueue') is not None and params['ackqueue'] == params['queue']:
            self.module.fail_json(msg='Acknowledge queue and default queue cannot be the same')

        # as in pfSense 2.4, the GUI accepts any queue defined on any interface without checking, we do the same
        if params.get('ackqueue') is not None and self.pfsense.find_queue(params['ackqueue'], enabled=True) is None:
            self.module.fail_json(msg='Failed to find enabled ackqueue=%s' % params['ackqueue'])

        if params.get('queue') is not None and self.pfsense.find_queue(params['queue'], enabled=True) is None:
            self.module.fail_json(msg='Failed to find enabled queue=%s' % params['queue'])

        if params.get('out_queue') is not None and params['in_queue'] is None:
            self.module.fail_json(msg='A queue must be selected for the In direction before selecting one for Out too')

        if params.get('out_queue') is not None and params['out_queue'] == params['in_queue']:
            self.module.fail_json(msg='In and Out Queue cannot be the same')

        if params.get('out_queue') is not None and self.pfsense.find_limiter(params['out_queue'], enabled=True) is None:
            self.module.fail_json(msg='Failed to find enabled out_queue=%s' % params['out_queue'])

        if params.get('in_queue') is not None and self.pfsense.find_limiter(params['in_queue'], enabled=True) is None:
            self.module.fail_json(msg='Failed to find enabled in_queue=%s' % params['in_queue'])

        if params.get('floating') and params.get('direction') == 'any' and (params['in_queue'] is not None or params['out_queue'] is not None):
            self.module.fail_json(msg='Limiters can not be used in Floating rules without choosing a direction')

        if params.get('after') and params.get('before'):
            self.module.fail_json(msg='Cannot specify both after and before')
        elif params.get('after'):
            if params['after'] == params['name']:
                self.module.fail_json(msg='Cannot specify the current rule in after')
        elif params.get('before'):
            if params['before'] == params['name']:
                self.module.fail_json(msg='Cannot specify the current rule in before')

        # gateway
        if params.get('gateway') is not None and params['gateway'] != 'default':
            if params['ipprotocol'] == 'inet46':
                self.module.fail_json(msg='Gateway selection is not valid for "IPV4+IPV6" address family.')
            elif (self.pfsense.find_gateway_group_elt(params['gateway'], params['ipprotocol']) is None
                  and self.pfsense.find_gateway_elt(params['gateway'], None, params['ipprotocol']) is None):
                self.module.fail_json(msg='Gateway "%s" does not exist or does not match target rule ip protocol.' % params['gateway'])

            if params.get('floating') and params.get('direction') == 'any':
                self.module.fail_json(msg='Gateways can not be used in Floating rules without choosing a direction')

    def _remove_deleted_rule_params(self, rule_elt):
        """ Remove from rule a few deleted params """
        changed = False
        for param in ['log', 'protocol', 'disabled', 'defaultqueue', 'ackqueue', 'dnpipe', 'pdnpipe', 'gateway']:
            if self.pfsense.remove_deleted_param_from_elt(rule_elt, param, self._rule):
                changed = True

        return changed

    def _remove_rule_elt(self, rule_elt):
        """ delete rule_elt from xml """
        self.rules.remove(rule_elt)
        self.changed = True
        self.diff['before'] = self._rule_element_to_dict(rule_elt)
        self.result['deleted'].append(self._rule_element_to_dict(rule_elt))

    ##################
    # public methods
    #
    @staticmethod
    def _rule_element_to_dict(rule_elt):
        """ convert rule_elt to dictionary like module arguments """
        rule = PFSenseModule.element_to_dict(rule_elt)

        # We use 'name' for 'descr'
        rule['name'] = rule.pop('descr', 'UNKNOWN')
        # We use 'action' for 'type'
        rule['action'] = rule.pop('type', 'UNKNOWN')

        # Convert addresses to argument format
        for addr_item in ['source', 'destination']:
            rule[addr_item] = PFSenseModule.addr_normalize(rule[addr_item])

        return rule

    def _add(self):
        """ add or update rule """
        rule = self._rule
        rule_elt, dummy = self._find_matching_rule()
        changed = False
        timestamp = '%d' % int(time.time())
        if rule_elt is None:
            changed = True
            rule['id'] = ''
            rule['tracker'] = timestamp
            rule['created'] = rule['updated'] = dict()
            rule['created']['time'] = rule['updated']['time'] = timestamp
            rule['created']['username'] = rule['updated']['username'] = self.pfsense.get_username()
            rule_elt = self.pfsense.new_element('rule')
            self.pfsense.copy_dict_to_element(rule, rule_elt)
            self.diff['after'] = self._rule_element_to_dict(rule_elt)
            self._insert(rule_elt)
            self.result['added'].append(rule)
            self._log_create(self._rule)
            self.change_descr = 'ansible pfsense_rule added %s' % (rule['descr'])
        else:
            self.diff['before'] = self._rule_element_to_dict(rule_elt)
            changed = self.pfsense.copy_dict_to_element(rule, rule_elt)
            if self._remove_deleted_rule_params(rule_elt):
                changed = True

            if self._update_rule_position(rule_elt):
                changed = True

            if changed:
                updated_elt = rule_elt.find('updated')
                if updated_elt is None:
                    updated_elt = self.pfsense.new_element('updated')
                    updated_elt.append(self.pfsense.new_element('time', timestamp))
                    updated_elt.append(self.pfsense.new_element('username', self.pfsense.get_username()))
                    rule_elt.append(updated_elt)
                else:
                    updated_elt.find('time').text = timestamp
                    updated_elt.find('username').text = self.pfsense.get_username()
                self.diff['after'].update(self._rule_element_to_dict(rule_elt))
                self.result['modified'].append(self._rule_element_to_dict(rule_elt))
                self.change_descr = 'ansible pfsense_rule updated "%s" interface %s action %s' % (rule['descr'], rule['interface'], rule['type'])
                self._log_update(rule, self.diff['before'])

        if changed:
            self.changed = True

    def _remove(self):
        """ delete rule """
        rule_elt, dummy = self._find_matching_rule()
        if rule_elt is not None:
            self._log_delete(self._rule)
            self.diff['before'] = self._rule_element_to_dict(rule_elt)
            self._adjust_separators(self._get_rule_position(), add=False)
            self._remove_rule_elt(rule_elt)
            self.change_descr = 'ansible pfsense_rule removed "%s" interface %s' % (self._rule['descr'], self._rule['interface'])

    def _params_to_rule(self, params):
        """ return a rule dict from module params """
        self._validate_params(params)

        rule = dict()

        def param_to_rule(param_field, rule_field):
            """ set rule_field if param_field is defined """
            if params[param_field] is not None:
                rule[rule_field] = params[param_field]

        def bool_to_rule(param_field, rule_field):
            """ set rule_field if param_field is True """
            if params[param_field]:
                rule[rule_field] = ''

        rule['descr'] = params['name']

        if params.get('floating'):
            rule['floating'] = 'yes'
            rule['interface'] = self._parse_floating_interfaces(params['interface'])
        else:
            rule['interface'] = self.pfsense.parse_interface(params['interface'])

        if params['state'] == 'present':
            rule['type'] = params['action']
            rule['ipprotocol'] = params['ipprotocol']
            rule['statetype'] = params['statetype']
            rule['source'] = self._parse_address(params['source'])
            rule['destination'] = self._parse_address(params['destination'])

            if params['protocol'] != 'any':
                rule['protocol'] = params['protocol']

            bool_to_rule('disabled', 'disabled')
            bool_to_rule('log', 'log')

            param_to_rule('direction', 'direction')
            param_to_rule('queue', 'defaultqueue')
            param_to_rule('ackqueue', 'ackqueue')
            param_to_rule('in_queue', 'dnpipe')
            param_to_rule('out_queue', 'pdnpipe')

            if params['gateway'] != 'default':
                rule['gateway'] = params['gateway']

        return rule

    def commit_changes(self):
        """ apply changes and exit module """
        stdout = ''
        stderr = ''
        if self.changed and not self.module.check_mode:
            self.pfsense.write_config(descr=self.change_descr)
            (dummy, stdout, stderr) = self._update()

        self.module.exit_json(stdout=stdout, stderr=stderr, changed=self.changed, diff=self.diff)

    def run(self, params):
        """ process input params to add/update/delete a rule """
        self._params = params
        self._rule = self._params_to_rule(params)
        self._descr = self._rule['descr']
        self._interface = self._rule['interface']
        self._floating = 'floating' in self._rule and self._rule['floating'] == 'yes'
        self._after = params.get('after')
        self._before = params.get('before')

        if params['state'] == 'absent':
            self._remove()
        else:
            self._add()
