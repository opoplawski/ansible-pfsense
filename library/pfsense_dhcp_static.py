#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Carlos Rodrigues <cmarodrigues@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_dhcp_static
version_added: "0.1"
author: Carlos Rodrigues (@cmarodrigues)
short_description: Manage pfSense DHCP static mapping
description:
  - Manage pfSense DHCP static mapping
notes:
options:
  name:
    description: The client name identifier
    required: true
    type: str
  netif:
    description: The network interface
    type: str
  macaddr:
    description: The mac address
    type: str
  ipaddr:
    description: The IP address
    type: str
  hostname:
    description: The hostname
    type: str
  descr:
    description: The description
    type: str
  filename:
    description: The filename
    type: str
  rootpath:
    description: The roothpath
    type: str
  defaultleasetime:
    description: the default lease time
    type: str
  maxleasetime:
    description: The max lease time
    type: str
  gateway:
    description: The gateway
    type: str
  domain:
    description: The domain
    type: str
  winsserver:
    description: The WINS server
    type: list
    elements: str
  dnsserver:
    description: The dns server
    type: list
    elements: str
  ntpserver:
    description: The ntpserver
    type: list
    elements: str
  domainsearchlist:
    description: The domain search list servers
    type: str
  ddnsdomain:
    description: The ddns domain
    type: str
  ddnsdomainprimary:
    description: The ddns primary domain
    type: str
  ddnsdomainsecondary:
    description: The ddns secondary domain
    type: str
  ddnsdomainkeyname:
    description: The ddns domain key name
    type: str
  ddnsdomainkeyalgorithm:
    description: The ddns key algorithm
    type: str
  ddnsdomainkey:
    description: The ddns domain key
    type: str
  tftp:
    description: The TFTP server
    type: str
  ldap:
    description: The ldap server
    type: str
  nextserver:
    description: The next server
    type: str
  filename32:
    description: The filename for 32bits
    type: str
  filename64:
    description: The filename for 64bits
    type: str
  filename32arm:
    description: The filename for 32arm
    type: str
  filename64arm:
    description: The filename for 64arm
    type: str
  numberoptions:
    description: The number options
    type: str
  state:
    description: State in which to leave the configuration
    default: present
    choices: [ "present", "absent" ]
    type: str
"""

EXAMPLES = """
- name: Create DHCP static mapping
  pfsense_dhcp_static:
    name: "test"
    macaddr: "aa:aa:aa:aa:aa:aa"
    ipaddr: "192.168.1.10"
    state: present

- name: Remove DHCP static mapping
  pfsense_dhcp_static:
    name: "test"
    state: absent
"""

RETURN = """

"""

import base64
import re

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.pfsense.module_base import PFSenseModuleBase

DHCP_STATIC_ARGUMENT_SPEC = dict(
    name=dict(required=True, type='str'),
    netif=dict(type='str'),
    macaddr=dict(type='str'),
    ipaddr=dict(type='str'),
    hostname=dict(type='str'),
    descr=dict(type='str'),
    filename=dict(type='str'),
    rootpath=dict(type='str'),
    defaultleasetime=dict(type='str'),
    maxleasetime=dict(type='str'),
    gateway=dict(type='str'),
    domain=dict(type='str'),
    domainsearchlist=dict(type='str'),
    winsserver=dict(type='list', elements='str'),
    dnsserver=dict(type='list', elements='str'),
    ntpserver=dict(type='list', elements='str'),
    ddnsdomain=dict(type='str'),
    ddnsdomainprimary=dict(type='str'),
    ddnsdomainsecondary=dict(type='str'),
    ddnsdomainkeyname=dict(type='str'),
    ddnsdomainkeyalgorithm=dict(type='str'),
    ddnsdomainkey=dict(type='str'),
    tftp=dict(type='str'),
    ldap=dict(type='str'),
    nextserver=dict(type='str'),
    filename32=dict(type='str'),
    filename64=dict(type='str'),
    filename32arm=dict(type='str'),
    filename64arm=dict(type='str'),
    numberoptions=dict(type='str'),
    state=dict(type='str', default='present', choices=['present', 'absent']),
)

DHCP_STATIC_REQUIRED_IF = [
    ["state", "present", ["name", "macaddr", "ipaddr"]],
]


class PFSenseDHCPSTATICModule(PFSenseModuleBase):
    """ module managing pfsense dhcp static configuration """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return DHCP_STATIC_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseDHCPSTATICModule, self).__init__(module, pfsense)
        self.name = "pfsense_dhcp_static"
        self.dhcpd = self.pfsense.get_element('dhcpd')
        self.root_elt = None
        self.staticmaps = None

    ##############################
    # params processing
    #
    def _validate_params(self):
        """ do some extra checks on input parameters """

        params = self.params

        if params['state'] == 'absent':
            return

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()
        self.obj = obj
        # client identifier
        obj['cid'] = params['name']

        # find staticmaps
        self._find_staticmaps(params['netif'])

        if params['state'] == 'present':

            obj['mac'] = params['macaddr']
            obj['ipaddr'] = params['ipaddr']

            # other options
            for option in ['hostname', 'descr', 'filename',
                           'rootpath', 'defaultleasetime', 'maxleasetime',
                           'gateway', 'domain', 'domainsearchlist',
                           'winsserver', 'dnsserver', 'ntpserver',
                           'ddnsdomain', 'ddnsdomainprimary', 'ddnsdomainsecondary',
                           'ddnsdomainkeyname', 'ddnsdomainkeyalgorithm', 'ddnsdomainkey',
                           'tftp', 'ldap', 'nextserver', 'filename32', 'filename64',
                           'filename32arm', 'filename64arm', 'numberoptions']:
                if option in params and params[option] is not None:
                    obj[option] = params[option]

        return obj

    ##############################
    # XML processing
    #
    def _is_valid_netif(self, netif):
        for nic in self.pfsense.interfaces:
            if nic.tag == netif:
                if nic.find('ipaddr') is not None:
                    ipaddr = nic.find('ipaddr').text
                    if ipaddr is not None:
                        if nic.find('subnet') is not None:
                            subnet = int(nic.find('subnet').text)
                            if subnet < 31:
                                return True
        return False

    def _find_staticmaps(self, netif=None):
        for e in self.dhcpd:
            if netif is None or e.tag == netif:
                if e.find('enable') is not None:
                    if self._is_valid_netif(e.tag):
                        self.root_elt = e
                        self.staticmaps = self.root_elt.findall('staticmap')
                        break
        if self.root_elt is None:
            self.module.fail_json(msg='No DHCP configuration')

    def _find_target(self):
        result = self.root_elt.findall("staticmap[cid='{0}']".format(self.obj['cid']))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple static maps for cid {0}.'.format(self.obj['cid']))
        else:
            return None

    def _find_this_dhcp_static_index(self):
        return self.staticmaps.index(self.target_elt)

    def _find_last_dhcp_static_index(self):
        return list(self.root_elt).index(self.staticmaps[len(self.staticmaps) - 1])

    def _create_target(self):
        """ create the XML target_elt """
        return self.pfsense.new_element('staticmap')

    def _copy_and_add_target(self):
        """ populate the XML target_elt """
        obj = self.obj

        self.diff['after'] = obj
        self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.root_elt.insert(self._find_last_dhcp_static_index(), self.target_elt)
        # Reset static map list
        self.staticmaps = self.root_elt.findall('staticmap')

    def _copy_and_update_target(self):
        """ update the XML target_elt """

        before = self.pfsense.element_to_dict(self.target_elt)
        self.diff['before'] = before

        changed = self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.diff['after'] = self.pfsense.element_to_dict(self.target_elt)

        return (before, changed)

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return "'" + self.obj['cid'] + "'"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            values += self.format_cli_field(self.params, 'name')
        else:
            values += self.format_updated_cli_field(self.obj, before, 'cid', add_comma=(values))
        return values

    ##############################
    # run
    #
    def _update(self):
        """ make the target pfsense reload """
        return self.pfsense.phpshell("""
            require_once("util.inc");
            require_once("services.inc");
            $retvaldhcp = services_dhcpd_configure();
            if ($retvaldhcp == 0) {
              clear_subsystem_dirty('staticmaps');
            }""")

    def _pre_remove_target_elt(self):
        self.diff['after'] = {}
        if self.target_elt is not None:
            self.diff['before'] = self.pfsense.element_to_dict(self.target_elt)

            self.staticmaps.remove(self.target_elt)
        else:
            self.diff['before'] = {}


def main():
    module = AnsibleModule(
        argument_spec=DHCP_STATIC_ARGUMENT_SPEC,
        required_if=DHCP_STATIC_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseDHCPSTATICModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
