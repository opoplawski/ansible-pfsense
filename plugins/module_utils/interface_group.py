# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
import re
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase
from ansible_collections.pfsensible.core.plugins.module_utils.rule import PFSenseRuleModule

INTERFACE_GROUP_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),
    name=dict(required=True, type='str'),
    descr=dict(type='str'),
    members=dict(required=True, type='list', elements='str'),
)

INTERFACE_GROUP_PHP_COMMAND = '''
require_once("interfaces.inc");
{0}
interface_group_setup($ifgroupentry);'''


class PFSenseInterfaceGroupModule(PFSenseModuleBase):
    """ module managing pfsense interfaces """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return INTERFACE_GROUP_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseInterfaceGroupModule, self).__init__(module, pfsense)
        self.name = "pfsense_interface_group"
        self.obj = dict()

        self.root_elt = self.pfsense.get_element('ifgroups')

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return an interface dict from module params """
        params = self.params

        obj = dict()
        self.obj = obj
        obj['ifname'] = params['name']
        if params['state'] == 'present':
            obj['descr'] = params['descr']
            members = []
            for interface in params['members']:
                if self.pfsense.is_interface_display_name(interface):
                    members.append(self.pfsense.get_interface_by_display_name(interface))
                elif self.pfsense.is_interface_port(interface):
                    members.append(interface)
                else:
                    self.module.fail_json(msg='Unknown interface name "{0}".'.format(interface))
            obj['members'] = ' '.join(members)
            self.result['member_ifnames'] = members

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """

        params = self.params

        # check name
        if re.match('^[a-zA-Z0-9_]+$', params['name']) is None:
            self.module.fail_json(msg='The name of the interface group may only consist of the characters "a-z, A-Z, 0-9 and _"')
        if len(params['name']) > 15:
            self.module.fail_json(msg='Group name cannot have more than 15 characters.')
        if re.match('[0-9]$', params['name']) is not None:
            self.module.fail_json(msg='Group name cannot end with a digit.')
        # TODO - check that name isn't in use by any interfaces

    ##############################
    # XML processing
    #
    def _copy_and_add_target(self):
        """ create the XML target_elt """
        self.pfsense.copy_dict_to_element(self.obj, self.target_elt)

    def _copy_and_update_target(self):
        """ update the XML target_elt """
        before = self.pfsense.element_to_dict(self.target_elt)
        changed = self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        if self._remove_deleted_params():
            changed = True

        self.diff['before'] = before
        if changed:
            self.diff['after'] = self.pfsense.element_to_dict(self.target_elt)
            self.result['changed'] = True
        else:
            self.diff['after'] = self.obj

        return (before, changed)

    def _create_target(self):
        """ create the XML target_elt """
        self.diff['before'] = ''
        self.diff['after'] = self.obj
        return self.pfsense.new_element('ifgroupentry')

    def _find_target(self):
        """ find the XML target_elt """
        target_elt = self.root_elt.findall("ifgroupentry[ifname='{0}']".format(self.obj['ifname']))[0]
        return target_elt

    def _pre_remove_target_elt(self):
        """ processing before removing elt """
        self.diff['before'] = self.pfsense.element_to_dict(self.target_elt)

    def _remove_all_rules(self, interface):
        """ delete all interface rules """

        # we use the pfsense_rule module to delete the rules since, at least for floating rules,
        # it implies to recalculate separators positions
        # if we have to just remove the deleted interface of a floating rule we do it ourselves
        todel = []
        for rule_elt in self.pfsense.rules:
            if rule_elt.find('floating') is not None:
                interfaces = rule_elt.find('interface').text.split(',')
                old_ifs = ','.join([self.pfsense.get_interface_display_name(old_interface) for old_interface in interfaces])
                if interface in interfaces:
                    if len(interfaces) > 1:
                        interfaces.remove(interface)
                        new_ifs = ','.join([self.pfsense.get_interface_display_name(new_interface) for new_interface in interfaces])
                        rule_elt.find('interface').text = ','.join(interfaces)
                        cmd = 'update rule \'{0}\' on \'floating({1})\' set interface=\'{2}\''.format(rule_elt.find('descr').text, old_ifs, new_ifs)
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

    ##############################
    # run
    #

    def _update(self):
        """ make the target pfsense reload interfaces """
        return self.pfsense.phpshell(INTERFACE_GROUP_PHP_COMMAND.format(self.pfsense.dict_to_php(self.obj, 'ifgroupentry')))

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return "'{0}'".format(self.obj['ifname'])

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            values += self.format_cli_field(self.obj, 'descr')
            values += self.format_cli_field(self.obj, 'members')
        else:
            values += self.format_updated_cli_field(self.obj, before, 'descr', add_comma=(values))
            values += self.format_updated_cli_field(self.obj, before, 'members', add_comma=(values))
        return values

    def _log_update(self, before):
        """ generate pseudo-CLI command to update an interface """
        log = "update {0}".format(self._get_module_name(True))
        values = self._log_fields(before)
        self.result['commands'].append(log + ' set ' + values)
