# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import time
import re

from ansible.module_utils.network.pfsense.pfsense import PFSenseModule, PFSenseModuleBase

NAT_ARGUMENT_SPEC = dict(
    name=dict(required=True, type='str'),
    type=dict(default='portforward', required=False, choices=["portforward", "onetoone"]),
    state=dict(default='present', choices=['present', 'absent']),
    disabled=dict(default=False, required=False, type='bool'),
    interface=dict(required=True, type='str'),
    protocol=dict(default='tcp', required=False, choices=["tcp", "udp", "tcp/udp", "icmp", "igmp"]),
    source=dict(required=False, type='str'),
    destination=dict(required=True, type='str'),
    target=dict(required=True, type='str'),
    rule=dict(default='associated', required=False, choices=["none", "associated", "unassociated", "pass"]),
    after=dict(required=False, type='str'),
    before=dict(required=False, type='str'),
)

# These are nat elements that are (currently) unmanaged by this module
NAT_UNMANAGED_ELEMENTS = [
    'created', 'updated'
]


class PFSenseNatModule(PFSenseModuleBase):
    """ module managing pfsense NAT rules """

    def __init__(self, module, pfsense=None):
        if pfsense is None:
            pfsense = PFSenseModule(module)
        self.module = module
        self.pfsense = pfsense
        self.nats = self.pfsense.get_element('nat')

        self.changed = False
        self.change_descr = ''

        self.diff = {'after': {}, 'before': {}}

        self.result = {}
        self.result['added'] = []
        self.result['deleted'] = []
        self.result['modified'] = []
        self.result['commands'] = []

        # internals params
        self._nat = None
        self._descr = None
        self._interface = None
        self._after = None
        self._before = None
        self._params = None
        self._position_changed = False

    def _match_type(self, nat_elt):
        """ check if a nat elt matches the targeted type """
        return self.pfsense.nat_match_type(nat_elt, self._type)

    def _find_matching_nat(self):
        """ retturn nat element and index that matches by description or action """
        # Prioritize matching by name
        found, i = self._find_nat_by_descr(self._descr)
        if found is not None:
            return (found, i)

        # Match action without name/descr
        match_nat = self._nat.copy()
        del match_nat['descr']
        for nat_elt in self.nats:
            this_nat = self.pfsense.element_to_dict(nat_elt)
            this_nat.pop('descr', None)
            # Remove unmanaged elements
            for unwanted in NAT_UNMANAGED_ELEMENTS:
                this_nat.pop(unwanted, None)
            if this_nat == match_nat:
                return (nat_elt, i)
            i += 1

        return (None, -1)

    def _find_nat_by_descr(self, descr):
        """ return nat element and index of type that matches description """
        i = 0
        for nat_elt in self.nats.find(self._type):
            descr_elt = nat_elt.find('descr')
            if self._match_type(nat_elt) and descr_elt is not None and descr_elt.text == descr:
                return (nat_elt, i)
            i += 1
        return (None, -1)

    def _adjust_separators(self, start_idx, add=True, before=False):
        """ update separators position """
        separators_elt = self.nats.find('separator')
        if separators_elt is None:
            return

        separators_elt = separators_elt.find(self._type)
        if separators_elt is None:
            return

        for separator_elt in separators_elt:
            row_elt = separator_elt.find('row')
            if row_elt is None or row_elt.text is None:
                continue

            # TODO - see how this works
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

    def _get_first_nat_xml_index(self):
        """ Find the first nat for the type and return its xml index """
        i = 0
        for nat_elt in self.nats:
            if self._match_type(nat_elt):
                break
            i += 1
        return i

    def _get_last_nat_xml_index(self):
        """ Find the last nat for the type and return its xml index """
        last_found = -1
        i = 0
        for nat_elt in self.nats:
            if self._match_type(nat_elt):
                last_found = i
            i += 1
        return last_found

    def _get_nat_position(self, descr=None, fail=True):
        """ get nat position of that type"""
        if descr is None:
            descr = self._descr

        res = self.pfsense.get_nat_position(descr, self._type)
        if fail and res is None:
            self.module.fail_json(msg='Failed to find nat=%s type=%s' % (descr, self._type))
        return res

    def _get_expected_nat_xml_index(self):
        """ get expected nat index in xml """
        if self._before == 'bottom':
            return self._get_last_nat_xml_index() + 1
        elif self._after == 'top':
            return self._get_first_nat_xml_index()
        elif self._after is not None:
            found, i = self._find_nat_by_descr(self._after)
            if found is not None:
                return i + 1
            else:
                self.module.fail_json(msg='Failed to insert after nat=%s type=%s' % (self._after, self._type))
        elif self._before is not None:
            found, i = self._find_nat_by_descr(self._before)
            if found is not None:
                return i
            else:
                self.module.fail_json(msg='Failed to insert before nat=%s type=%s' % (self._before, self._type))
        else:
            found, i = self._find_nat_by_descr(self._descr)
            if found is not None:
                return i
            return self._get_last_nat_xml_index() + 1
        return -1

    def _get_expected_nat_position(self):
        """ get expected nat position for type """
        if self._before == 'bottom':
            return self.pfsense.get_type_nats_count(self._type) - 1
        elif self._after == 'top':
            return 0
        elif self._after is not None:
            return self._get_nat_position(self._after) + 1
        elif self._before is not None:
            position = self._get_nat_position(self._before) - 1
            if position < 0:
                return 0
            return position
        else:
            position = self._get_nat_position(self._after, fail=False)
            if position is not None:
                return position
            return self.pfsense.get_type_nats_count(self._type)
        return -1

    def _insert(self, nat_elt):
        """ insert nat into xml """
        nat_xml_idx = self._get_expected_nat_xml_index()
        self.nats.insert(nat_xml_idx, nat_elt)

        nat_position = self._get_nat_position()
        self._adjust_separators(nat_position, before=(self._after is None and self._before is not None))

    def _update_nat_position(self, nat_elt):
        """ move nat in xml if required """
        current_position = self._get_nat_position()
        expected_position = self._get_expected_nat_position()
        if current_position == expected_position:
            self._position_changed = False
            return False

        self.diff['before']['position'] = current_position
        self.diff['after']['position'] = expected_position
        self._adjust_separators(current_position, add=False)
        self.nats.remove(nat_elt)
        self._insert(nat_elt)
        self._position_changed = True
        return True

    def _update(self):
        """ make the target pfsense reload nats """
        return self.pfsense.phpshell('''require_once("filter.inc");
if (filter_configure() == 0) { clear_subsystem_dirty('filter'); }''')

    def _log_create(self, nat):
        """ generate pseudo-CLI command to create a nat """
        log = "create nat '{0}'".format(nat['descr'])
        log += self.format_cli_field(self._params, 'type')
        log += self.format_cli_field(self._params, 'source')
        log += self.format_cli_field(self._params, 'destination')
        log += self.format_cli_field(self._params, 'protocol')
        log += self.format_cli_field(self._params, 'interface')
        log += self.format_cli_field(self._params, 'direction')
        log += self.format_cli_field(self._params, 'ipprotocol', default='inet')
        log += self.format_cli_field(self._params, 'statetype', default='keep state')
        log += self.format_cli_field(self._params, 'action', default='pass')
        log += self.format_cli_field(self._params, 'disabled', default=False)
        log += self.format_cli_field(self._params, 'log', default=False)
        log += self.format_cli_field(self._params, 'after')
        log += self.format_cli_field(self._params, 'before')
        log += self.format_cli_field(self._params, 'default', default='default')

        self.result['commands'].append(log)

    def _log_delete(self, nat):
        """ generate pseudo-CLI command to delete a nat """
        log = "delete nat '{0}', type='{1}'".format(nat['descr'],nat['type'])
        self.result['commands'].append(log)

    @staticmethod
    def _obj_address_to_log_field(nat, addr):
        """ return formated address from dict """
        field = ''
        if isinstance(nat[addr], dict):
            if 'any' in nat[addr]:
                field = 'any'
            if 'address' in nat[addr]:
                field = nat[addr]['address']
            if 'port' in nat[addr]:
                if field:
                    field += ':'
                field += nat[addr]['port']
        else:
            field = nat[addr]
        return field

    def _obj_to_log_fields(self, nat):
        """ return formated source and destination from dict """
        res = {}
        res['source'] = self._obj_address_to_log_field(nat, 'source')
        res['destination'] = self._obj_address_to_log_field(nat, 'destination')
        return res

    def _log_update(self, nat, before):
        """ generate pseudo-CLI command to update a nat """
        log = "update nat '{0}, type='{1}'".format(nat['descr'],self.pfsense.get_type_display_name(self._type))

        fbefore = self._obj_to_log_fields(before)
        fafter = self._obj_to_log_fields(nat)
        fafter['before'] = self._before
        fafter['after'] = self._after

        values = ''
        values += self.format_updated_cli_field(fafter, fbefore, 'source', add_comma=(values))
        values += self.format_updated_cli_field(fafter, fbefore, 'destination', add_comma=(values))
        values += self.format_updated_cli_field(nat, before, 'protocol', add_comma=(values))
        values += self.format_updated_cli_field(nat, before, 'interface', add_comma=(values))
        values += self.format_updated_cli_field(nat, before, 'disabled', add_comma=(values))
        values += self.format_updated_cli_field(nat, before, 'log', add_comma=(values))
        if self._position_changed:
            values += self.format_updated_cli_field(fafter, {}, 'after', log_none=False, add_comma=(values))
            values += self.format_updated_cli_field(fafter, {}, 'before', log_none=False, add_comma=(values))

        self.result['commands'].append(log + ' set ' + values)

    def _parse_address(self, param):
        """ validate param address field and returns it as a dict """
        match = re.match('^([^:]+)(?::?([^:-]+)-?([^:-]+)?)?$', param)
        if match is None:
            self.module.fail_json(msg='Cannot parse address %s' % (param))
        address = match.group(1)
        port_start = match.group(2)
        port_end = match.group(3)

        ret = dict()
        # Check if the first character is "!"
        if address[0] == '!':
            # Invert the nat
            ret['not'] = None
            address = address[1:]
        if address == 'any':
            ret['any'] = None
        # nat with this firewall
        elif address == '(self)':
            ret['network'] = '(self)'
        elif address == 'NET' or address == 'IP':
            interface = port_start
            if port_end:
                interface += '-' + port_end
            ret['network'] = self.pfsense.parse_interface(interface)
            if address == 'IP':
                ret['network'] += 'ip'
            return ret
        # nat with interface name (LAN, WAN...)
        elif self.pfsense.is_interface_name(address):
            interface = self.pfsense.get_interface_pfsense_by_name(address)
            ret['network'] = interface
        else:
            if not self.pfsense.is_ip_or_alias(address):
                self.module.fail_json(msg='Cannot parse address %s, not IP or alias' % (address))
            ret['address'] = address

        if port_start is not None:
            if not self.pfsense.is_port_or_alias(port_start):
                self.module.fail_json(msg='Cannot parse port %s, not port number or alias' % (port_start))
            ret['port'] = port_start
        if port_end is not None:
            if not self.pfsense.is_port_or_alias(port_end):
                self.module.fail_json(msg='Cannot parse port %s, not port number or alias' % (port_end))
            ret['port'] += '-' + port_end

        return ret

    def _validate_params(self, params):
        """ do some extra checks on input parameters """
        if params.get('after') and params.get('before'):
            self.module.fail_json(msg='Cannot specify both after and before')
        elif params.get('after'):
            if params['after'] == params['name']:
                self.module.fail_json(msg='Cannot specify the current nat in after')
        elif params.get('before'):
            if params['before'] == params['name']:
                self.module.fail_json(msg='Cannot specify the current nat in before')

    def _remove_deleted_nat_param(self, nat_elt, param):
        """ Remove from nat a deleted nat param """
        changed = False
        if param not in self._nat:
            param_elt = nat_elt.find(param)
            if param_elt is not None:
                changed = True
                nat_elt.remove(param_elt)
        return changed

    def _remove_deleted_nat_params(self, nat_elt):
        """ Remove from nat a few deleted nat params """
        changed = False
        for param in ['log', 'protocol', 'disabled']:
            if self._remove_deleted_nat_param(nat_elt, param):
                changed = True

        return changed

    def _remove_nat_elt(self, nat_elt):
        """ delete nat_elt from xml """
        self.nats.remove(nat_elt)
        self.changed = True
        self.diff['before'] = self._nat_element_to_dict(nat_elt)
        self.result['deleted'].append(self._nat_element_to_dict(nat_elt))

    ##################
    # public methods
    #
    @staticmethod
    def _nat_element_to_dict(nat_elt):
        """ convert nat_elt to dictionary like module arguments """
        nat = PFSenseModule.element_to_dict(nat_elt)

        # We use 'name' for 'descr'
        nat['name'] = nat.pop('descr', 'UNKNOWN')
        # We use 'action' for 'type'
        nat['action'] = nat.pop('type', 'UNKNOWN')

        # Convert addresses to argument format
        for addr_item in ['source', 'destination']:
            nat[addr_item] = PFSenseModule.addr_normalize(nat[addr_item])

        return nat

    def _add(self):
        """ add or update nat """
        nat = self._nat
        nat_elt, dummy = self._find_matching_nat()
        changed = False
        timestamp = '%d' % int(time.time())
        if nat_elt is None:
            changed = True
            nat['id'] = ''
            nat['tracker'] = timestamp
            nat['created'] = nat['updated'] = dict()
            nat['created']['time'] = nat['updated']['time'] = timestamp
            nat['created']['username'] = nat['updated']['username'] = self.pfsense.get_username()
            nat_elt = self.pfsense.new_element('nat')
            self.pfsense.copy_dict_to_element(nat, nat_elt)
            self.diff['after'] = self._nat_element_to_dict(nat_elt)
            self._insert(nat_elt)
            self.result['added'].append(nat)
            self._log_create(self._nat)
            self.change_descr = 'ansible pfsense_nat added %s' % (nat['descr'])
        else:
            self.diff['before'] = self._nat_element_to_dict(nat_elt)
            changed = self.pfsense.copy_dict_to_element(nat, nat_elt)
            if self._remove_deleted_nat_params(nat_elt):
                changed = True

            if self._update_nat_position(nat_elt):
                changed = True

            if changed:
                updated_elt = nat_elt.find('updated')
                if updated_elt is None:
                    updated_elt = self.pfsense.new_element('updated')
                    updated_elt.append(self.pfsense.new_element('time', timestamp))
                    updated_elt.append(self.pfsense.new_element('username', self.pfsense.get_username()))
                    nat_elt.append(updated_elt)
                else:
                    updated_elt.find('time').text = timestamp
                    updated_elt.find('username').text = self.pfsense.get_username()
                self.diff['after'].update(self._nat_element_to_dict(nat_elt))
                self.result['modified'].append(self._nat_element_to_dict(nat_elt))
                self.change_descr = 'ansible pfsense_nat updated "%s" type %s' % (nat['descr'], nat['type'])
                self._log_update(nat, self.diff['before'])

        if changed:
            self.changed = True

    def _remove(self):
        """ delete nat """
        nat_elt, dummy = self._find_matching_nat()
        if nat_elt is not None:
            self._log_delete(self._nat)
            self.diff['before'] = self._nat_element_to_dict(nat_elt)
            self._adjust_separators(self._get_nat_position(), add=False)
            self._remove_nat_elt(nat_elt)
            self.change_descr = 'ansible pfsense_nat removed "%s" type %s' % (self._nat['descr'], self._nat['type'])

    def _params_to_nat(self, params):
        """ return a nat dict from module params """
        self._validate_params(params)

        nat = dict()

        def param_to_nat(param_field, nat_field):
            """ set nat_field if param_field is defined """
            if params[param_field] is not None:
                nat[nat_field] = params[param_field]

        def bool_to_nat(param_field, nat_field):
            """ set nat_field if param_field is True """
            if params[param_field]:
                nat[nat_field] = ''

        nat['descr'] = params['name']

        nat['interface'] = self.pfsense.parse_interface(params['interface'])

        if params['state'] == 'present':
            nat['type'] = params['action']
            nat['ipprotocol'] = params['ipprotocol']
            nat['statetype'] = params['statetype']
            nat['source'] = self._parse_address(params['source'])
            nat['destination'] = self._parse_address(params['destination'])

            if params['protocol'] != 'any':
                nat['protocol'] = params['protocol']

            bool_to_nat('disabled', 'disabled')
            bool_to_nat('log', 'log')

            param_to_nat('direction', 'direction')

        return nat

    def commit_changes(self):
        """ apply changes and exit module """
        stdout = ''
        stderr = ''
        if self.changed and not self.module.check_mode:
            self.pfsense.write_config(descr=self.change_descr)
            (dummy, stdout, stderr) = self._update()

        self.module.exit_json(stdout=stdout, stderr=stderr, changed=self.changed, diff=self.diff)

    def run(self, params):
        """ process input params to add/update/delete a nat """
        self._params = params
        self._nat = self._params_to_nat(params)
        self._descr = self._nat['descr']
        self._interface = self._nat['interface']
        self._after = params.get('after')
        self._before = params.get('before')

        if params['state'] == 'absent':
            self._remove()
        else:
            self._add()
