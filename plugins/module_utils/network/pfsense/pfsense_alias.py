# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Orion Poplawski <orion@nwra.com>
# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
import re
from ansible.module_utils.network.pfsense.pfsense import PFSenseModule, PFSenseModuleBase

ALIAS_ARGUMENT_SPEC = dict(
    name=dict(required=True, type='str'),
    state=dict(default='present', choices=['present', 'absent']),
    type=dict(default=None, required=False, choices=['host', 'network', 'port', 'urltable', 'urltable_ports']),
    address=dict(default=None, required=False, type='str'),
    descr=dict(default=None, required=False, type='str'),
    detail=dict(default=None, required=False, type='str'),
    updatefreq=dict(default=None, required=False, type='int'),
)

ALIAS_REQUIRED_IF = [
    ["type", "urltable", ["updatefreq"]],
    ["type", "urltable_ports", ["updatefreq"]],
]


class PFSenseAliasModule(PFSenseModuleBase):
    """ module managing pfsense aliases """

    def __init__(self, module, pfsense=None):
        if pfsense is None:
            pfsense = PFSenseModule(module)
        self.module = module
        self.pfsense = pfsense
        self.aliases = self.pfsense.get_element('aliases')

        self.change_descr = ''

        self.diff = {}
        self.result = {}
        self.result['changed'] = False
        self.result['diff'] = self.diff
        self.result['commands'] = []

    def _update(self):
        """ make the target pfsense reload aliases """
        return self.pfsense.phpshell('''require_once("filter.inc");
if (filter_configure() == 0) { clear_subsystem_dirty('aliases'); }''')

    def _log_create(self, alias):
        """ generate pseudo-CLI command to create an alias """
        log = "create alias '{0}'".format(alias['name'])
        log += self.format_cli_field(alias, 'type')
        log += self.format_cli_field(alias, 'address')
        log += self.format_cli_field(alias, 'updatefreq')
        log += self.format_cli_field(alias, 'descr')
        log += self.format_cli_field(alias, 'detail')
        self.result['commands'].append(log)

    def _log_delete(self, alias):
        """ generate pseudo-CLI command to delete an alias """
        log = "delete alias '{0}'".format(alias['name'])
        self.result['commands'].append(log)

    def _log_update(self, alias, before):
        """ generate pseudo-CLI command to update an alias """
        log = "update alias '{0}'".format(alias['name'])
        values = ''
        values += self.format_updated_cli_field(alias, before, 'address', add_comma=(values))
        values += self.format_updated_cli_field(alias, before, 'updatefreq', add_comma=(values))
        values += self.format_updated_cli_field(alias, before, 'descr', add_comma=(values))
        values += self.format_updated_cli_field(alias, before, 'detail', add_comma=(values))
        self.result['commands'].append(log + ' set ' + values)

    def _add(self, alias):
        """ add or update alias """
        alias_elt = self.pfsense.find_alias(alias['name'])
        self.diff['after'] = alias
        if alias_elt is None:
            alias_elt = self.pfsense.new_element('alias')
            self.pfsense.copy_dict_to_element(alias, alias_elt)
            self.aliases.append(alias_elt)

            changed = True
            self.diff['before'] = ''
            self.change_descr = 'ansible pfsense_alias added %s type %s' % (alias['name'], alias['type'])
            self._log_create(alias)
        else:
            self.diff['before'] = self.pfsense.element_to_dict(alias_elt)
            changed = self.pfsense.copy_dict_to_element(alias, alias_elt)
            if changed:
                self.diff['after'] = self.pfsense.element_to_dict(alias_elt)
                self.change_descr = 'ansible pfsense_alias updated "%s" type %s' % (alias['name'], alias['type'])
                self._log_update(alias, self.diff['before'])

        if changed:
            self.result['changed'] = changed

    def _remove_alias_elt(self, alias_elt):
        """ delete alias_elt from xml """
        self.aliases.remove(alias_elt)
        self.result['changed'] = True
        self.diff['before'] = self.pfsense.element_to_dict(alias_elt)

    def _remove(self, alias):
        """ delete alias """
        alias_elt = self.pfsense.find_alias(alias['name'])
        self.diff['after'] = ''
        self.diff['before'] = ''
        if alias_elt is not None:
            self._log_delete(alias)
            self._remove_alias_elt(alias_elt)
            self.change_descr = 'ansible pfsense_alias removed "%s"' % (alias['name'])

    def _validate_params(self, params):
        """ do some extra checks on input parameters """
        # check name
        if re.match('^[a-zA-Z0-9_]+$', params['name']) is None:
            self.module.fail_json(msg='The alias name may only consist of the characters "a-z, A-Z, 0-9 and _"')

        if len(params['name']) >= 32:
            self.module.fail_json(msg='The alias name must be less than 32 characters long')

        # when deleting, only name is allowed
        if params['state'] == 'absent':
            for param, value in sorted(params.items()):
                if param != 'state' and param != 'name' and value is not None:
                    self.module.fail_json(msg=param + " is invalid with state='absent'")
        else:
            # the GUI does not allow to create 2 aliases with same name and differents types
            alias_elt = self.pfsense.find_alias(params['name'])
            if alias_elt is not None:
                if params['type'] != alias_elt.find('type').text:
                    self.module.fail_json(msg='An alias with this name and a different type already exists')

            if self.pfsense.get_interface_pfsense_by_name(params['name']) is not None:
                self.module.fail_json(msg='An interface description with this name already exists')

            missings = ['type', 'address']
            for param, value in params.items():
                if param in missings and value is not None and value != '':
                    missings.remove(param)
            if missings:
                self.module.fail_json(msg='state is present but all of the following are missing: ' + ','.join(missings))

            # updatefreq is for urltable only
            if params['updatefreq'] is not None and params['type'] != 'urltable' and params['type'] != 'urltable_ports':
                self.module.fail_json(msg='updatefreq is only valid with type urltable or urltable_ports')

            # check details count
            details = params['detail'].split('||') if params['detail'] is not None else []
            addresses = params['address'].split(' ')
            if len(details) > len(addresses):
                self.module.fail_json(msg='Too many details in relation to addresses')

            # pfSense GUI rule
            for detail in details:
                if detail.startswith('|') or detail.endswith('|'):
                    self.module.fail_json(msg='Vertical bars (|) at start or end of descriptions not allowed')

    def _params_to_alias(self, params):
        """ return an alias dict from module params """
        self._validate_params(params)

        alias = dict()
        alias['name'] = params['name']
        if params['state'] == 'present':
            alias['type'] = params['type']
            alias['address'] = params['address']
            alias['descr'] = params['descr']
            alias['detail'] = params['detail']
            if alias['type'] == 'urltable' or alias['type'] == 'urltable_ports':
                alias['url'] = params['address']
                alias['updatefreq'] = str(params['updatefreq'])

        return alias

    def commit_changes(self):
        """ apply changes and exit module """
        self.result['stdout'] = ''
        self.result['stderr'] = ''
        if self.result['changed'] and not self.module.check_mode:
            self.pfsense.write_config(descr=self.change_descr)
            (dummy, self.result['stdout'], self.result['stderr']) = self._update()

        self.module.exit_json(**self.result)

    def run(self, params):
        """ process input params to add/update/delete an alias """
        alias = self._params_to_alias(params)

        if params['state'] == 'absent':
            self._remove(alias)
        else:
            self._add(alias)
