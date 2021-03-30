#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# Copyright: (c) 2021, Jan Wenzel <jan.wenzel@gonicus.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_log_settings
version_added: "0.4.2"
author: Jan Wenzel (@coffeelover)
short_description: Manage pfSense syslog settings
description:
  - Manage pfSense syslog settings
notes:
options:
  logformat:
    description: Log Message Format
    required: false
    type: str
    choices: ['rfc3164', 'rfc5424']
  reverse:
    description: Show log entries in reverse order (newest entries on top)
    required: false
    type: bool
  nentries:
    description: GUI Log Entries
    required: false
    type: int
  nologdefaultblock:
    description: Don't log packets that are blocked by the implicit default block rule.
    required: false
    type: bool
  nologdefaultpass:
    description: Don't log packets that are allowed by the implicit default pass rule.
    required: false
    type: bool
  nologbogons:
    description: Don't log packets blocked by 'Block Bogon Networks' rules
    required: false
    type: bool
  nologprivatenets:
    description: Don't log packets blocked by 'Block Private Networks' rules
    required: false
    type: bool
  nolognginx:
    description: Don't log errors from the web server process
    required: false
    type: bool
  rawfilter:
    description: Show raw filter logs
    required: false
    type: bool
  filterdescriptions:
    description: Where to show rule descriptions
    required: false
    type: int
    choices: [0,1,2]
  disablelocallogging:
    description: Disable writing log files to the local disk
    required: false
    type: bool
  logfilesize:
    description: Log Rotation Size (Bytes)
    required: false
    type: int
  logcompressiontype:
    description: The type of compression to use when rotating log files
    required: false
    type: str
    choices: ['bzip2', 'gzip', 'xz', 'zstd', 'none']
  rotatecount:
    description: The number of log files to keep before the oldest copy is removed on rotation
    required: false
    type: int
  enable:
    description: Enable Remote logging
    required: false
    type: bool
  sourceip:
    description: Source Address
    required: false
    type: str
  ipproto:
    description: IP Protocol
    required: false
    type: str
    choices: ['ipv4', 'ipv6']
  remoteserver:
    description: First Remote log server (IP Address or Hostname/FQDN)
    required: false
    type: str
  remoteserver2:
    description: Second Remote log server (IP Address or Hostname/FQDN)
    required: false
    type: str
  remoteserver3:
    description: Third Remote log server (IP Address or Hostname/FQDN)
    required: false
    type: str
  logall:
    description: Log Everything
    required: false
    type: bool
  system:
    description: Include System Events
    required: false
    type: bool
  logfilter:
    description: Include Firewall Events
    required: false
    type: bool
  resolver:
    description: Include DNS Events (Resolver/unbound, Forwarder/dnsmasq, filterdns)
    required: false
    type: bool
  dhcp:
    description: Include DHCP Events (DHCP Daemon, DHCP Relay, DHCP Client)
    required: false
    type: bool
  ppp:
    description: Include PPP Events (PPPoE WAN Client, L2TP WAN Client, PPTP WAN Client)
    required: false
    type: bool
  auth:
    description: Include General Authentication Events
    required: false
    type: bool
  portalauth:
    description: Include Captive Portal Events
    required: false
    type: bool
  vpn:
    description: Include VPN Events (IPsec, OpenVPN, L2TP, PPPoE Server)
    required: false
    type: bool
  dpinger:
    description: Include Gateway Monitor Events
    required: false
    type: bool
  routing:
    description: Include Routing Daemon Events (RADVD, UPnP, RIP, OSPF, BGP)
    required: false
    type: bool
  ntpd:
    description: Include Network Time Protocol Events (NTP Daemon, NTP Client)
    required: false
    type: bool
  hostapd:
    description: Wireless Events (hostapd)
    required: false
    type: bool
"""

EXAMPLES = """
- name: setup remote syslog
  pfsense_log_settings:
    enable: true
    remoteserver: syslog.example.com
    disablelocallogging: true
    logall: true

- name: always log default pass traffic
  pfsense_log_settings:
    nologdefaultpass: false
"""

RETURN = """
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["update log_settings syslog set logformat='rfc5424', rotatecount='8'"]
"""

import re
from copy import deepcopy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

LOG_SETTINGS_ARGUMENT_SPEC = dict(
    logformat=dict(required=False, type='str',
                   choices=['rfc3164', 'rfc5424']),
    reverse=dict(required=False, type='bool'),
    nentries=dict(required=False, type='int'),
    nologdefaultblock=dict(required=False, type='bool'),
    nologdefaultpass=dict(required=False, type='bool'),
    nologbogons=dict(required=False, type='bool'),
    nologprivatenets=dict(required=False, type='bool'),
    nolognginx=dict(required=False, type='bool'),
    rawfilter=dict(required=False, type='bool'),
    filterdescriptions=dict(required=False, type='int',
                            choices=[0, 1, 2]),
    disablelocallogging=dict(required=False, type='bool'),
    logfilesize=dict(required=False, type='int'),
    logcompressiontype=dict(required=False, type='str',
                            choices=['bzip2', 'gzip', 'xz', 'zstd', 'none']),
    rotatecount=dict(required=False, type='int'),
    enable=dict(required=False, type='bool'),
    sourceip=dict(required=False, type='str'),
    ipproto=dict(required=False, type='str',
                 choices=['ipv4', 'ipv6']),
    remoteserver=dict(required=False, type='str'),
    remoteserver2=dict(required=False, type='str'),
    remoteserver3=dict(required=False, type='str'),
    logall=dict(required=False, type='bool'),
    system=dict(required=False, type='bool'),
    logfilter=dict(required=False, type='bool'),
    resolver=dict(required=False, type='bool'),
    dhcp=dict(required=False, type='bool'),
    ppp=dict(required=False, type='bool'),
    auth=dict(required=False, type='bool'),
    portalauth=dict(required=False, type='bool'),
    vpn=dict(required=False, type='bool'),
    dpinger=dict(required=False, type='bool'),
    routing=dict(required=False, type='bool'),
    ntpd=dict(required=False, type='bool'),
    hostapd=dict(required=False, type='bool'),
)

# rename the reserved words with log prefix
params_map = {
    'logformat': 'format',
    'logfilter': 'filter',
}

# fields with inverted logic
inverted_list = ['nologdefaultpass']


class PFSenseLogSettingsModule(PFSenseModuleBase):
    """ module managing pfsense log settings """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return LOG_SETTINGS_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseLogSettingsModule, self).__init__(module, pfsense)
        self.name = "log_settings"
        self.root_elt = self.pfsense.get_element('syslog')
        self.target_elt = self.root_elt
        self.params = dict()
        self.obj = dict()
        self.before = None
        self.before_elt = None
        self.route_cmds = list()
        self.params_to_delete = list()

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = self.pfsense.element_to_dict(self.root_elt)
        self.before = deepcopy(obj)
        self.before_elt = deepcopy(self.root_elt)

        def _set_param(target, param):
            # get possibly mapped settings name
            _param = params_map.get(param, param)
            if params.get(param) is not None:
                if param == 'sourceip':
                    target[param] = self._get_source_ip_interface(params[param])
                else:
                    if isinstance(params[param], str):
                        target[_param] = params[param]
                    else:
                        target[_param] = str(params[param])

        def _set_param_bool(target, param):
            # get possibly mapped settings name
            _param = params_map.get(param, param)
            if params.get(param) is not None:
                value = not params.get(param) if param in inverted_list else params.get(param)
                if value is True and _param not in target:
                    target[_param] = ''
                elif value is False and _param in target:
                    del target[_param]

        for param in LOG_SETTINGS_ARGUMENT_SPEC:
            if LOG_SETTINGS_ARGUMENT_SPEC[param]['type'] == 'bool':
                _set_param_bool(obj, param)
            else:
                _set_param(obj, param)

        return obj

    def _is_interface_ip_or_descr(self, address):
        result = False

        if address in ['127.0.0.1', 'Localhost']:
            return True

        for interface_elt in self.pfsense.interfaces:
            descr = interface_elt.find('descr')
            ipaddr = interface_elt.find('ipaddr')

            if descr is not None and descr.text == address:
                return True
            elif ipaddr is not None and ipaddr.text == address:
                return True

        return result

    def _get_interface_by_ip_or_display_name(self, address):
        """ return interface_id by ip address or name """

        if address in ['127.0.0.1', 'Localhost']:
            return 'lo0'

        for interface_elt in self.pfsense.interfaces:
            descr = interface_elt.find('descr')
            ipaddr = interface_elt.find('ipaddr')

            if descr is not None and descr.text == address:
                return interface_elt.tag
            elif ipaddr is not None and ipaddr.text == address:
                return interface_elt.tag

        return None

    def _get_source_ip_interface(self, address):
        result = None

        if self._is_interface_ip_or_descr(address):
            result = self._get_interface_by_ip_or_display_name(address)

        elif self.pfsense.is_virtual_ip(address):
            result = self.pfsense.get_virtual_ip_interface(address)

        return result

    def _validate_syslog_server(self, hostname, name):
        """ check hostname / ip address combinations with optional port """
        if not hostname:
            return

        host = hostname.lower()
        contains_port = re.match(r'^(\[.+\]|[^:]+):[0-9]+$', host)
        if contains_port is not None:
            host, port = host.rsplit(':', 1)

            # check if we got a ipv6 address with port - need to remove '[' and ']'
            host = host.strip('[]')

            if port is not None and (int(port) <= 0 or int(port) >= 65536):
                self.module.fail_json(msg="Invalid port {0}".format(port))

        if self.pfsense.is_ipv4_address(host):
            return

        if self.pfsense.is_ipv6_address(host):
            return

        groups = re.match(r'^(?:(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9])\.)*(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9\.])$', host)
        if groups is None:
            self.module.fail_json(msg="The {0} can only contain the characters A-Z, 0-9 and '-'. It may not start or end with '-'".format(name))

    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        if params.get('sourceip') is not None:
            address = params.get('sourceip')
            if address == '':
                return

            if not self.pfsense.is_virtual_ip(address) and not self._is_interface_ip_or_descr(address):
                self.module.fail_json(msg="sourceip: Invalid address {address}!".format(address=params.get('sourceip')))

        if params.get('logall') is True:
            for log_param in ['system', 'logfilter', 'resolver',
                              'dhcp', 'ppp', 'auth', 'portalauth',
                              'vpn', 'dpinger', 'routing', 'ntpd', 'hostapd']:
                if params.get(log_param) is True:
                    self.module.fail_json(msg="{log_param} = True is invalid when logall is True".format(log_param=log_param))

        if params.get('enable') is True:
            remote_params = ['remoteserver', 'remoteserver2', 'remoteserver3']
            if params.get('remoteserver') is None and params.get('remoteserver2') is None and params.get('remoteserver3') is None:
                self.module.fail_json(msg="Need at least one remote syslog server when remote logging is enabled")
            else:
                for param in remote_params:
                    self._validate_syslog_server(params.get(param), param)

        if params.get('nentries') is not None:
            nentries = int(params.get('nentries'))
            if nentries < 5 or nentries > 200000:
                self.module.fail_json(msg="nentries must be an integer from 5 to 200000")

        if params.get('logfilesize') is not None:
            logfilesize = int(params.get('logfilesize'))
            if logfilesize < 100000:
                self.module.fail_json(msg="logfilesize must be an integer greater or equal than 100000")
            elif logfilesize >= (2 ** 32) / 2:
                self.module.fail_json(msg="logfilesize is too large: {logfilesize}".format(logfilesize=logfilesize))

        if params.get('rotatecount') is not None:
            rotatecount = int(params.get('rotatecount'))
            if rotatecount < 0 or rotatecount > 99:
                self.module.fail_json(msg="rotatecount must be an integer from 0 to 99")

    ##############################
    # XML processing
    #
    def _remove_deleted_params(self):
        """ Remove from target_elt a few deleted params """
        changed = False
        for param in LOG_SETTINGS_ARGUMENT_SPEC:
            if LOG_SETTINGS_ARGUMENT_SPEC[param]['type'] == 'bool':
                _param = params_map.get(param, param)
                if self.pfsense.remove_deleted_param_from_elt(self.target_elt, _param, self.obj):
                    changed = True

        return changed

    ##############################
    # run
    #
    def run(self, params):
        """ process input params to add/update/delete """
        self.params = params
        self.target_elt = self.root_elt
        self._validate_params()
        self.obj = self._params_to_obj()
        self._add()

    def _update(self):
        """ make the target pfsense reload """
        for cmd in self.route_cmds:
            self.module.run_command(cmd)

        cmd = '''
require_once("filter.inc");
$retval = 0;
$retval |= system_syslogd_start();'''

        for param in ['nologdefaultblock', 'nologdefaultpass', 'nologbogons', 'nologprivatenets']:
            if self.params.get(param) is not None:
                if (self.params[param] and param not in self.before or not self.params[param] and param in self.before):
                    cmd += '$retval |= filter_configure();\n'
                    break

        if self.params.get('nolognginx') is not None:
            if (self.params['nolognginx'] and 'nolognginx' not in self.before or not self.params['nolognginx'] and 'nolognginx' in self.before):
                cmd += 'ob_flush();\n'
                cmd += 'flush();\n'
                cmd += 'send_event("service restart webgui");\n'

        cmd += '$retval |= filter_pflog_start(true);\n'

        return self.pfsense.phpshell(cmd)

    ##############################
    # Logging
    #
    @staticmethod
    def _get_obj_name():
        """ return obj's name """
        return "syslog"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''

        for param in LOG_SETTINGS_ARGUMENT_SPEC:
            _param = params_map.get(param, param)
            if LOG_SETTINGS_ARGUMENT_SPEC[param]['type'] == 'bool':
                values += self.format_updated_cli_field(self.obj, self.before, _param, fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
            else:
                values += self.format_updated_cli_field(self.obj, self.before, _param, add_comma=(values), log_none=False)

        return values


def main():
    module = AnsibleModule(
        argument_spec=LOG_SETTINGS_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseLogSettingsModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
