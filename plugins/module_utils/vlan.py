# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

VLAN_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),
    interface=dict(required=True, type='str'),
    vlan_id=dict(required=True, type='int'),
    priority=dict(default=None, required=False, type='int'),
    descr=dict(default='', type='str'),
)


class PFSenseVlanModule(PFSenseModuleBase):
    """ module managing pfsense vlans """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return VLAN_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseVlanModule, self).__init__(module, pfsense)
        self.name = "pfsense_vlan"
        self.root_elt = self.pfsense.get_element('vlans')
        self.obj = dict()

        if self.root_elt is None:
            self.root_elt = self.pfsense.new_element('vlans')
            self.pfsense.root.append(self.root_elt)

        self.setup_vlan_cmds = ""

        # get physical interfaces on which vlans can be set
        get_interface_cmd = (
            'require_once("/etc/inc/interfaces.inc");'
            '$portlist = get_interface_list();'
            '$lagglist = get_lagg_interface_list();'
            '$portlist = array_merge($portlist, $lagglist);'
            'foreach ($lagglist as $laggif => $lagg) {'
            "    $laggmembers = explode(',', $lagg['members']);"
            '    foreach ($laggmembers as $lagm)'
            '        if (isset($portlist[$lagm]))'
            '            unset($portlist[$lagm]);'
            '}')

        if self.pfsense.is_at_least_2_5_0():
            get_interface_cmd += (
                '$list = array();'
                'foreach ($portlist as $ifn => $ifinfo) {'
                '  $list[$ifn] = $ifn . " (" . $ifinfo["mac"] . ")";'
                '  $iface = convert_real_interface_to_friendly_interface_name($ifn);'
                '  if (isset($iface) && strlen($iface) > 0)'
                '    $list[$ifn] .= " - $iface";'
                '}'
                'echo json_encode($list);')
        else:
            get_interface_cmd += (
                '$list = array();'
                'foreach ($portlist as $ifn => $ifinfo)'
                '   if (is_jumbo_capable($ifn))'
                '       array_push($list, $ifn);'
                'echo json_encode($list);')

        self.interfaces = self.pfsense.php(get_interface_cmd)

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()

        obj['tag'] = str(params['vlan_id'])
        if params['interface'] not in self.interfaces:
            obj['if'] = self.pfsense.get_interface_port_by_display_name(params['interface'])
            if obj['if'] is None:
                obj['if'] = self.pfsense.get_interface_port(params['interface'])
        else:
            obj['if'] = params['interface']

        if params['state'] == 'present':
            if params['priority'] is not None:
                obj['pcp'] = str(params['priority'])
            else:
                obj['pcp'] = ''

            obj['descr'] = params['descr']
            obj['vlanif'] = '{0}.{1}'.format(obj['if'], obj['tag'])

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        # check interface
        if params['interface'] not in self.interfaces:
            # check with assign or friendly name
            interface = self.pfsense.get_interface_port_by_display_name(params['interface'])
            if interface is None:
                interface = self.pfsense.get_interface_port(params['interface'])

            if interface is None or interface not in self.interfaces:
                self.module.fail_json(msg='Vlans can\'t be set on interface {0}'.format(params['interface']))

        # check vlan
        if params['vlan_id'] < 1 or params['vlan_id'] > 4094:
            self.module.fail_json(msg='vlan_id must be between 1 and 4094 on interface {0}'.format(params['interface']))

        # check priority
        if params.get('priority') is not None and (params['priority'] < 0 or params['priority'] > 7):
            self.module.fail_json(msg='priority must be between 0 and 7 on interface {0}'.format(params['interface']))

    ##############################
    # XML processing
    #
    def _cmd_create(self):
        """ return the php shell to create the vlan's interface """
        cmd = "$vlan = array();\n"
        cmd += "$vlan['if'] = '{0}';\n".format(self.obj['if'])
        cmd += "$vlan['tag'] = '{0}';\n".format(self.obj['tag'])
        cmd += "$vlan['pcp'] = '{0}';\n".format(self.obj['pcp'])
        cmd += "$vlan['descr'] = '{0}';\n".format(self.obj['descr'])
        cmd += "$vlan['vlanif'] = '{0}';\n".format(self.obj['vlanif'])
        cmd += "$vlanif = interface_vlan_configure($vlan);\n"

        cmd += "if ($vlanif == NULL || $vlanif != $vlan['vlanif']) {pfSense_interface_destroy('%s');} else {\n" % (self.obj['vlanif'])

        # if vlan is assigned to an interface, configuration needs to be applied again
        interface = self.pfsense.get_interface_by_port('{0}.{1}'.format(self.obj['if'], self.obj['tag']))
        if interface is not None:
            cmd += "interface_configure('{0}', true);\n".format(interface)

        cmd += '}\n'

        return cmd

    def _copy_and_add_target(self):
        """ create the XML target_elt """
        super(PFSenseVlanModule, self)._copy_and_add_target()
        self.setup_vlan_cmds += self._cmd_create()

    def _copy_and_update_target(self):
        """ update the XML target_elt """
        old_vlanif = self.target_elt.find('vlanif').text
        (before, changed) = super(PFSenseVlanModule, self)._copy_and_update_target()
        if changed:
            self.setup_vlan_cmds += "pfSense_interface_destroy('{0}');\n".format(old_vlanif)
            self.setup_vlan_cmds += self._cmd_create()

        return (before, changed)

    def _create_target(self):
        """ create the XML target_elt """
        return self.pfsense.new_element('vlan')

    def _find_target(self):
        """ find the XML target_elt """
        return self.pfsense.find_vlan(self.obj['if'], self.obj['tag'])

    def _pre_remove_target_elt(self):
        """ processing before removing elt """
        if self.pfsense.get_interface_by_port('{0}.{1}'.format(self.obj['if'], self.obj['tag'])) is not None:
            self.module.fail_json(
                msg='vlan {0} on {1} cannot be deleted because it is still being used as an interface'.format(self.obj['tag'], self.obj['if'])
            )
        self.setup_vlan_cmds += "pfSense_interface_destroy('{0}');\n".format(self.target_elt.find('vlanif').text)

    ##############################
    # run
    #
    def get_update_cmds(self):
        """ build and return php commands to setup interfaces """
        cmd = 'require_once("filter.inc");\n'
        if self.setup_vlan_cmds != "":
            cmd += 'require_once("interfaces.inc");\n'
            cmd += self.setup_vlan_cmds
        cmd += "if (filter_configure() == 0) { clear_subsystem_dirty('filter'); }"
        return cmd

    def _update(self):
        """ make the target pfsense reload """
        return self.pfsense.phpshell(self.get_update_cmds())

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return "'{0}.{1}'".format(self.obj['if'], self.obj['tag'])

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            values += self.format_cli_field(self.obj, 'descr')
            values += self.format_cli_field(self.obj, 'pcp', fname='priority')
        else:
            values += self.format_updated_cli_field(self.obj, before, 'pcp', add_comma=(values), fname='priority')
            values += self.format_updated_cli_field(self.obj, before, 'descr', add_comma=(values))
        return values
