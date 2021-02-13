#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_setup
version_added: 0.1.0
author: Frederic Bor (@f-bor)
short_description: Manage pfSense general setup
description:
  - Manage pfSense general setup
notes:
options:
  hostname:
    description: Hostname of the firewall host, without domain part
    required: false
    type: str
  domain:
    description: Domain name of the firewall host
    required: false
    type: str
  dns_addresses:
    description: DNS IP addresses, separated by space
    required: false
    type: str
  dns_hostnames:
    description: DNS hostnames, separated by space. You can use none for empty values.
    required: false
    type: str
  dns_gateways:
    description: DNS gateways, separated by space. You can use none for empty values.
    required: false
    type: str
  dnsallowoverride:
    description: Allow DNS server list to be overridden by DHCP/PPP on WAN
    required: false
    type: bool
  dnslocalhost:
    description: Do not use the DNS Forwarder/DNS Resolver as a DNS server for the firewall
    required: false
    type: bool
  timezone:
    description: Select a geographic region name (Continent/Location) to determine the timezone for the firewall.
    required: false
    type: str
  timeservers:
    description: Time servers, separated by space
    required: false
    type: str
  language:
    description: Time servers, separated by space
    required: false
    type: str
    choices: ['bs', 'de_DE', 'en_US', 'es', 'es_AR', 'fr', 'ko', 'nb', 'nl', 'pl', 'pt_PT', 'pt_BR', 'ru', 'zh_CN', 'zh_Hans_CN', 'zh_HK', 'zh_TW']
  webguicss:
    description: Choose an alternative css file (if installed) to change the appearance of the webConfigurator.
    required: false
    type: str
  webguifixedmenu:
    description: When enabled, menu remains visible at top of page
    required: false
    type: bool
  webguihostnamemenu:
    description: Replaces the Help menu title in the Navbar with the system hostname or FQDN.
    required: false
    choices: ['nohost', 'hostonly', 'fqdn']
    type: str
  dashboardcolumns:
    description: Dashboard columns
    required: false
    type: int
  interfacessort:
    description: If selected, lists of interfaces will be sorted by description, otherwise they are listed wan,lan,optn...
    required: false
    type: bool
  dashboardavailablewidgetspanel:
    description: Show the Available Widgets panel on the Dashboard.
    required: false
    type: bool
  systemlogsfilterpanel:
    description: Show the Log Filter panel in System Logs.
    required: false
    type: bool
  systemlogsmanagelogpanel:
    description: Show the Manage Log panel in System Logs.
    required: false
    type: bool
  statusmonitoringsettingspanel:
    description: Show the Settings panel in Status Monitoring.
    required: false
    type: bool
  requirestatefilter:
    description: This option requires a filter to be entered before the states are displayed.
    required: false
    type: bool
  webguileftcolumnhyper:
    description: If selected, clicking a label in the left column will select/toggle the first item of the group.
    required: false
    type: bool
  disablealiaspopupdetail:
    description: If selected, the details in alias popups will not be shown, just the alias description (e.g. in Firewall Rules).
    required: false
    type: bool
  roworderdragging:
    description: Disables dragging rows to allow selecting and copying row contents and avoid accidental changes.
    required: false
    type: bool
  logincss:
    description: Color for the login page
    required: false
    type: str
  loginshowhost:
    description: Show hostname on login banner
    required: false
    type: bool
"""

EXAMPLES = """
- name: setup hostname and domain
  pfsense_setup:
    hostname: acme
    domain: corp.com

- name: setup theme
  pfsense_setup:
    webguicss: pfSense-dark

- name: timezone and language
  pfsense_setup:
    timezone: Europe/Paris
    language: fr
"""

RETURN = """
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["update setup general set hostname='acme', domain='corp.com'"]
"""

import re
from copy import deepcopy
from os import listdir
from os.path import isfile, join
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase


SETUP_ARGUMENT_SPEC = dict(
    hostname=dict(required=False, type='str'),
    domain=dict(required=False, type='str'),
    dns_addresses=dict(required=False, type='str'),
    dns_hostnames=dict(required=False, type='str'),
    dns_gateways=dict(required=False, type='str'),
    dnsallowoverride=dict(required=False, type='bool'),
    dnslocalhost=dict(required=False, type='bool'),
    timezone=dict(required=False, type='str'),
    timeservers=dict(required=False, type='str'),
    language=dict(
        required=False,
        type='str',
        choices=['bs', 'de_DE', 'en_US', 'es', 'es_AR', 'fr', 'ko', 'nb', 'nl', 'pl', 'pt_PT', 'pt_BR', 'ru', 'zh_CN', 'zh_Hans_CN', 'zh_HK', 'zh_TW']
    ),
    webguicss=dict(required=False, type='str'),
    webguifixedmenu=dict(required=False, type='bool'),
    webguihostnamemenu=dict(required=False, type='str', choices=['nohost', 'hostonly', 'fqdn']),
    dashboardcolumns=dict(required=False, type='int'),
    interfacessort=dict(required=False, type='bool'),
    dashboardavailablewidgetspanel=dict(required=False, type='bool'),
    systemlogsfilterpanel=dict(required=False, type='bool'),
    systemlogsmanagelogpanel=dict(required=False, type='bool'),
    statusmonitoringsettingspanel=dict(required=False, type='bool'),
    requirestatefilter=dict(required=False, type='bool'),
    webguileftcolumnhyper=dict(required=False, type='bool'),
    disablealiaspopupdetail=dict(required=False, type='bool'),
    roworderdragging=dict(required=False, type='bool'),
    logincss=dict(required=False, type='str'),
    loginshowhost=dict(required=False, type='bool'),
)


class PFSenseSetupModule(PFSenseModuleBase):
    """ module managing pfsense routes """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return SETUP_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseSetupModule, self).__init__(module, pfsense)
        self.name = "pfsense_setup"
        self.root_elt = self.pfsense.get_element('system')
        self.obj = dict()
        self.before = None
        self.before_elt = None
        self.route_cmds = list()
        self.params_to_delete = list()

    ##############################
    # params processing
    #
    def _dns_params_to_obj(self, params, obj):
        """ set the dns servers from params to obj """
        dns_addresses = None
        dns_hostnames = []
        dns_gateways = []
        idx = 0
        if params.get('dns_addresses') is not None:
            dns_addresses = params['dns_addresses'].split()
        if params.get('dns_hostnames') is not None:
            dns_hostnames = params['dns_hostnames'].split()
        if params.get('dns_gateways') is not None:
            dns_gateways = params['dns_gateways'].split()

        if dns_addresses is not None:
            # set the servers
            obj['dnsserver'] = dns_addresses

            # set the names & gateways
            for address in dns_addresses:
                host = ''
                gateway = 'none'
                if idx < len(dns_hostnames) and dns_hostnames[idx] != 'none':
                    host = dns_hostnames[idx]
                if idx < len(dns_gateways) and dns_gateways[idx] != 'none':
                    gateway = dns_gateways[idx]

                obj['dns{0}host'.format(idx + 1)] = host
                gw_key = 'dns{0}gw'.format(idx + 1)
                if gw_key not in obj or gateway != obj[gw_key]:
                    obj[gw_key] = gateway
                    if self.pfsense.is_ipv4_address(address):
                        self.route_cmds.append('/sbin/route delete {0}'.format(address))
                    elif self.pfsense.is_ipv6_address(address):
                        self.route_cmds.append('/sbin/route delete -inet6 {0}'.format(address))

                idx += 1

        elif 'dnsserver' in obj:
            # no servers
            del obj['dnsserver']

        idx += 1
        # delete everything required
        while True:
            host = 'dns{0}host'.format(idx)
            gateway = 'dns{0}gw'.format(idx)
            if host not in obj and gateway not in obj:
                break
            if host in obj:
                del obj[host]
                self.params_to_delete.append(host)
            if gateway in obj:
                del obj[gateway]
                self.params_to_delete.append(gateway)
            idx += 1

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = self.pfsense.element_to_dict(self.root_elt)
        self.before = deepcopy(obj)
        self.before_elt = deepcopy(self.root_elt)
        self.obj = obj
        webgui = obj['webgui']

        def _set_param(target, param, strip=False):
            if params.get(param) is not None:
                if strip:
                    target[param] = ' '.join(params[param].split())
                elif isinstance(params[param], str):
                    target[param] = params[param]
                else:
                    target[param] = str(params[param])

        def _set_param_bool(target, param):
            if params.get(param) is not None:
                if params[param] and param not in target:
                    target[param] = ''
                elif not params[param] and param in target:
                    del target[param]

        _set_param(obj, 'hostname')
        _set_param(obj, 'domain')
        _set_param(obj, 'timezone')
        _set_param(obj, 'timeservers', True)

        _set_param(obj, 'language')

        _set_param_bool(webgui, 'interfacessort')
        _set_param_bool(webgui, 'webguileftcolumnhyper')
        _set_param_bool(webgui, 'disablealiaspopupdetail')
        _set_param_bool(webgui, 'dashboardavailablewidgetspanel')
        _set_param_bool(webgui, 'systemlogsfilterpanel')
        _set_param_bool(webgui, 'systemlogsmanagelogpanel')
        _set_param_bool(webgui, 'statusmonitoringsettingspanel')

        if params.get('webguicss') is not None:
            webgui['webguicss'] = params['webguicss'] + '.css'

        _set_param_bool(webgui, 'roworderdragging')

        _set_param(webgui, 'logincss')
        _set_param_bool(webgui, 'loginshowhost')
        _set_param_bool(webgui, 'webguifixedmenu')
        _set_param(webgui, 'webguihostnamemenu')
        _set_param(webgui, 'dashboardcolumns')
        _set_param_bool(webgui, 'requirestatefilter')

        _set_param_bool(obj, 'dnsallowoverride')
        _set_param_bool(obj, 'dnslocalhost')

        self._dns_params_to_obj(params, obj)

        return obj

    def _validate_hostname(self, hostname, name, strict=False):
        """ check hostname, if strict is true, check if domain is omitted """
        host = hostname.lower()
        groups = re.match(r'^(?:(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9])\.)*(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9\.])$', host)
        if groups is None:
            self.module.fail_json(msg="The {0} can only contain the characters A-Z, 0-9 and '-'. It may not start or end with '-'".format(name))

        if strict:
            groups = re.match(r'^(?:[a-z0-9_]|[a-z0-9_][a-z0-9_\-]*[a-z0-9_])$', host)
            if groups is None:
                self.module.fail_json(msg='A valid {0} is specified, but the domain name part should be omitted'.format(name))

    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        if params.get('dashboardcolumns') is not None and (params['dashboardcolumns'] < 1 or params['dashboardcolumns'] > 6):
            self.module.fail_json(msg='The submitted Dashboard Columns value is invalid.')

        if params.get('domain') is not None:
            domain = params['domain'].lower()
            groups = re.match(r'^(?:(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9])\.)*(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9\.])$', domain)
            if groups is None:
                self.module.fail_json(msg="The domain may only contain the characters a-z, 0-9, '-' and '.'")

        if params.get('hostname') is not None:
            self._validate_hostname(params['hostname'], 'hostname', True)

        if params.get('logincss') is not None:
            error = False
            try:
                int(params['logincss'], 16)
            except ValueError:
                error = True
            if error or len(params['logincss']) != 6:
                self.module.fail_json(msg="logincss must be a six digits hexadecimal string.")

        if params.get('timezone') is not None:
            self._validate_timezone(params['timezone'])

        if params.get('webguicss') is not None:
            self._validate_webguicss(params['webguicss'])

        if params.get('timeservers') is not None:
            for timeserver in params['timeservers'].split(' '):
                self._validate_hostname(timeserver, 'timeserver')

        # DNS
        ip_types = []
        dns_addresses = []
        if params.get('dns_addresses') is not None:
            dns_addresses = params['dns_addresses'].split()
            for address in dns_addresses:
                if dns_addresses.count(address) > 1:
                    self.module.fail_json(msg='Each configured DNS server must have a unique IP address. Remove the duplicated IP.')

                if self.pfsense.is_ipv4_address(address):
                    ip_types.append(4)
                elif self.pfsense.is_ipv6_address(address):
                    ip_types.append(6)
                else:
                    self.module.fail_json(msg='A valid IP address must be specified for DNS server {0}.'.format(address))

        if params.get('dns_hostnames') is not None:
            for hostname in params['dns_hostnames'].split(' '):
                if hostname != 'none':
                    self._validate_hostname(hostname, 'DNS hostname')

        if params.get('dns_gateways') is not None:
            for idx, address in enumerate(params['dns_gateways'].split(' ')):
                if idx >= len(dns_addresses) or address == 'none':
                    continue

                if self.pfsense.find_gateway_elt(address, protocol='inet') is not None:
                    if ip_types[idx] == 6:
                        self.module.fail_json(msg='The IPv4 gateway "{0}" can not be specified for IPv6 DNS server "{1}".'.format(address, dns_addresses[idx]))
                elif self.pfsense.find_gateway_elt(address, protocol='inet6') is not None:
                    if ip_types[idx] == 4:
                        self.module.fail_json(msg='The IPv6 gateway "{0}" can not be specified for IPv4 DNS server "{1}".'.format(address, dns_addresses[idx]))
                else:
                    self.module.fail_json(msg='The gateway "{0}" does not exist.'.format(address))

                if self.pfsense.is_within_local_networks(dns_addresses[idx]):
                    self.module.fail_json(
                        msg="A gateway can not be assigned to DNS '{0}' server which is on a directly connected network.".format(dns_addresses[idx])
                    )

    def _validate_timezone(self, timezone):
        """ check timezone """
        path = '/usr/share/zoneinfo/'
        if not isfile(path + timezone) or timezone[:1] < 'A' or timezone[:1] > 'Z':
            self.module.fail_json(msg='The submitted timezone is invalid')

    def _validate_webguicss(self, webguicss):
        """ check css style """
        path = '/usr/local/www/css/'
        themes = [f for f in listdir(path) if isfile(join(path, f)) and f.endswith('.css') and f.find('login') == -1 and f.find('logo') == -1]
        themes = map(lambda x: x.replace('.css', ''), themes)
        if webguicss not in themes:
            self.module.fail_json(msg='The submitted Theme could not be found. Pick a different theme.')

    ##############################
    # XML processing
    #
    def _remove_deleted_params(self):
        """ Remove from target_elt a few deleted params """
        changed = False
        params = ['dnsallowoverride', 'dnslocalhost']
        params += self.params_to_delete
        for param in params:
            if self.pfsense.remove_deleted_param_from_elt(self.target_elt, param, self.obj):
                changed = True

        webgui_elt = self.target_elt.find('webgui')
        webgui = self.obj['webgui']

        params = ['interfacessort', 'webguileftcolumnhyper', 'disablealiaspopupdetail', 'dashboardavailablewidgetspanel', 'systemlogsfilterpanel']
        params += ['systemlogsmanagelogpanel', 'statusmonitoringsettingspanel', 'roworderdragging', 'loginshowhost', 'webguifixedmenu']
        params += ['requirestatefilter']
        for param in params:
            if self.pfsense.remove_deleted_param_from_elt(webgui_elt, param, webgui):
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
$retval |= system_hostname_configure();
$retval |= system_hosts_generate();
$retval |= system_resolvconf_generate();
if (isset($config['dnsmasq']['enable'])) {
        $retval |= services_dnsmasq_configure();
} elseif (isset($config['unbound']['enable'])) {
        $retval |= services_unbound_configure();
}
$retval |= system_timezone_configure();
$retval |= system_ntp_configure();'''

        if self.params.get('dnsallowoverride') is not None:
            if (self.params['dnsallowoverride'] and 'dnsallowoverride' not in self.before or
                    not self.params['dnsallowoverride'] and 'dnsallowoverride' in self.before):
                cmd += '$retval |= send_event("service reload dns");\n'

        cmd += '$retval |= filter_configure();\n'

        return self.pfsense.phpshell(cmd)

    ##############################
    # Logging
    #
    @staticmethod
    def _get_obj_name():
        """ return obj's name """
        return "general"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        bwebgui = self.before['webgui']
        webgui = self.obj['webgui']

        obj_before = self._prepare_dns_log(self.before)
        obj_after = self._prepare_dns_log(self.obj)

        values = ''
        values += self.format_updated_cli_field(self.obj, self.before, 'hostname', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, self.before, 'domain', add_comma=(values), log_none=False)

        values += self.format_updated_cli_field(obj_after, obj_before, 'dns_addresses', add_comma=(values), log_none=True)
        values += self.format_updated_cli_field(obj_after, obj_before, 'dns_hostnames', add_comma=(values), log_none=True)
        values += self.format_updated_cli_field(obj_after, obj_before, 'dns_gateways', add_comma=(values), log_none=True)

        values += self.format_updated_cli_field(self.obj, self.before, 'timezone', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, self.before, 'timeservers', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, self.before, 'language', add_comma=(values), log_none=False)

        values += self.format_updated_cli_field(self.obj, self.before, 'dnsallowoverride', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(self.obj, self.before, 'dnslocalhost', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)

        values += self.format_updated_cli_field(obj_after, obj_before, 'webguicss', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, 'webguifixedmenu', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, 'webguihostnamemenu', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, 'dashboardcolumns', add_comma=(values), log_none=False)

        values += self.format_updated_cli_field(webgui, bwebgui, 'interfacessort', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, 'dashboardavailablewidgetspanel', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, 'systemlogsfilterpanel', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, 'systemlogsmanagelogpanel', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, 'statusmonitoringsettingspanel', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, 'requirestatefilter', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, 'webguileftcolumnhyper', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, 'disablealiaspopupdetail', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, 'roworderdragging', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, 'logincss', add_comma=(values), log_none=False)
        values += self.format_updated_cli_field(webgui, bwebgui, 'loginshowhost', fvalue=self.fvalue_bool, add_comma=(values), log_none=False)

        return values

    @staticmethod
    def _prepare_dns_log(obj):
        """ construct dict for logging """
        ret = dict()
        webgui = obj['webgui']

        ret['webguicss'] = webgui['webguicss'].replace('.css', '') if 'webguicss' in webgui else None

        if 'dnsserver' in obj:
            ret['dns_addresses'] = ' '.join(obj['dnsserver'])
        else:
            ret['dns_addresses'] = None

        ret['dns_hostnames'] = None
        ret['dns_gateways'] = None
        idx = 1
        hosts = list()
        gateways = list()
        while True:
            host = 'dns{0}host'.format(idx)
            gateway = 'dns{0}gw'.format(idx)
            if host not in obj or gateway not in obj:
                break

            hosts.append(obj[host] if obj[host] != '' else 'none')
            gateways.append(obj[gateway] if obj[gateway] != '' else 'none')

            idx += 1

        # we have multiple string that can give the same configuration
        # we remove the ending nones (assuming the user won't specify them for nothing)
        while True:
            if len(hosts) and hosts[-1] == 'none':
                hosts.pop()
                continue
            if len(gateways) and gateways[-1] == 'none':
                gateways.pop()
                continue
            break
        if len(hosts):
            ret['dns_hostnames'] = ' '.join(hosts)
        if len(gateways):
            ret['dns_gateways'] = ' '.join(gateways)
        return ret


def main():
    module = AnsibleModule(
        argument_spec=SETUP_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseSetupModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
