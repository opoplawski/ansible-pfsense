# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from ansible.modules.network.pfsense import pfsense_setup
from .pfsense_module import TestPFSenseModule
from units.compat.mock import patch


class TestPFSenseSetupModule(TestPFSenseModule):

    module = pfsense_setup

    def __init__(self, *args, **kwargs):
        super(TestPFSenseSetupModule, self).__init__(*args, **kwargs)
        self.config_file = 'pfsense_setup_config.xml'
        self.pfmodule = pfsense_setup.PFSenseSetupModule

    def setUp(self):
        """ mocking up """

        super(TestPFSenseSetupModule, self).setUp()

        self.mock_validate_webguicss = patch('ansible.modules.network.pfsense.pfsense_setup.PFSenseSetupModule._validate_webguicss')
        self.validate_webguicss = self.mock_validate_webguicss.start()

    ##############
    # tests utils
    #
    def get_target_elt(self, setup, absent=False):
        """ get the generated xml definition """
        return self.assert_find_xml_elt(self.xml_result, 'system')

    def check_target_elt(self, setup, setup_elt):
        """ test the xml definition of setup elt """
        webgui_elt = self.assert_find_xml_elt(setup_elt, 'webgui')

        def check_param(param, elt):
            if setup.get(param) is not None:
                self.assert_xml_elt_equal(elt, param, setup[param])

        def check_bool_param(param, elt):
            if setup.get(param) is not None:
                if setup[param]:
                    self.assert_xml_elt_is_none_or_empty(elt, param)
                else:
                    self.assert_not_find_xml_elt(elt, param)

        check_param('hostname', setup_elt)
        check_param('domain', setup_elt)
        check_bool_param('dnsallowoverride', setup_elt)
        check_bool_param('dnslocalhost', setup_elt)
        check_param('timezone', setup_elt)
        check_param('timeservers', setup_elt)
        check_param('language', setup_elt)

        if setup.get('webguicss') is not None:
            self.assert_xml_elt_equal(webgui_elt, 'webguicss', setup['webguicss'] + '.css')

        check_bool_param('webguifixedmenu', webgui_elt)
        check_param('webguihostnamemenu', webgui_elt)
        check_param('dashboardcolumns', webgui_elt)
        check_bool_param('interfacessort', webgui_elt)
        check_bool_param('dashboardavailablewidgetspanel', webgui_elt)
        check_bool_param('systemlogsfilterpanel', webgui_elt)
        check_bool_param('systemlogsmanagelogpanel', webgui_elt)
        check_bool_param('statusmonitoringsettingspanel', webgui_elt)
        check_bool_param('requirestatefilter', webgui_elt)
        check_bool_param('webguileftcolumnhyper', webgui_elt)
        check_bool_param('disablealiaspopupdetail', webgui_elt)
        check_bool_param('roworderdragging', webgui_elt)
        check_bool_param('loginshowhost', webgui_elt)
        check_param('logincss', webgui_elt)

        # TODO: check dns_addresses, dns_hostnames, dns_gateways

    ##############
    # tests
    #
    def test_setup_hostname(self):
        """ test setup hostname """
        setup = dict(hostname='acme')
        command = "update setup general set hostname='acme'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_hostname_invalid(self):
        """ test setup hostname """
        setup = dict(hostname='acme.corp.com')
        msg = "A valid hostname is specified, but the domain name part should be omitted"
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_hostname_invalid2(self):
        """ test setup hostname """
        setup = dict(hostname='(invalid)')
        msg = "The hostname can only contain the characters A-Z, 0-9 and '-'. It may not start or end with '-'"
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_domain(self):
        """ test setup domain """
        setup = dict(domain='corp.com')
        command = "update setup general set domain='corp.com'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_domain_invalid(self):
        """ test setup domain """
        setup = dict(domain='@invalid.com')
        msg = "The domain may only contain the characters a-z, 0-9, '-' and '.'"
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_dnsallowoverride(self):
        """ test setup general """
        setup = dict(dnsallowoverride=False)
        command = "update setup general set dnsallowoverride=False"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_dnslocalhost(self):
        """ test setup dnslocalhost """
        setup = dict(dnslocalhost=True)
        command = "update setup general set dnslocalhost=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_webguifixedmenu(self):
        """ test setup webguifixedmenu """
        setup = dict(webguifixedmenu=True)
        command = "update setup general set webguifixedmenu=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_interfacessort(self):
        """ test setup interfacessort """
        setup = dict(interfacessort=True)
        command = "update setup general set interfacessort=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_dashboardavailablewidgetspanel(self):
        """ test setup dashboardavailablewidgetspanel """
        setup = dict(dashboardavailablewidgetspanel=True)
        command = "update setup general set dashboardavailablewidgetspanel=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_systemlogsfilterpanel(self):
        """ test setup systemlogsfilterpanel """
        setup = dict(systemlogsfilterpanel=True)
        command = "update setup general set systemlogsfilterpanel=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_systemlogsmanagelogpanel(self):
        """ test setup systemlogsmanagelogpanel """
        setup = dict(systemlogsmanagelogpanel=True)
        command = "update setup general set systemlogsmanagelogpanel=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_statusmonitoringsettingspanel(self):
        """ test setup statusmonitoringsettingspanel """
        setup = dict(statusmonitoringsettingspanel=True)
        command = "update setup general set statusmonitoringsettingspanel=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_requirestatefilter(self):
        """ test setup requirestatefilter """
        setup = dict(requirestatefilter=True)
        command = "update setup general set requirestatefilter=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_webguileftcolumnhyper(self):
        """ test setup webguileftcolumnhyper """
        setup = dict(webguileftcolumnhyper=True)
        command = "update setup general set webguileftcolumnhyper=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_disablealiaspopupdetail(self):
        """ test setup disablealiaspopupdetail """
        setup = dict(disablealiaspopupdetail=True)
        command = "update setup general set disablealiaspopupdetail=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_roworderdragging(self):
        """ test setup roworderdragging """
        setup = dict(roworderdragging=True)
        command = "update setup general set roworderdragging=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_loginshowhost(self):
        """ test setup loginshowhost """
        setup = dict(loginshowhost=True)
        command = "update setup general set loginshowhost=True"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_language(self):
        """ test setup language """
        setup = dict(language='fr')
        command = "update setup general set language='fr'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_timeservers(self):
        """ test setup timeservers """
        setup = dict(timeservers='1.2.3.4 0.pool.ntp.org')
        command = "update setup general set timeservers='1.2.3.4 0.pool.ntp.org'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_timezone(self):
        """ test setup timezone """
        setup = dict(timezone='Europe/Paris')
        command = "update setup general set timezone='Europe/Paris'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_webguicss(self):
        """ test setup webguicss """
        setup = dict(webguicss='pfSense-dark')
        command = "update setup general set webguicss='pfSense-dark'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_webguihostnamemenu(self):
        """ test setup webguihostnamemenu """
        setup = dict(webguihostnamemenu='fqdn')
        command = "update setup general set webguihostnamemenu='fqdn'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_dashboardcolumns(self):
        """ test setup dashboardcolumns """
        setup = dict(dashboardcolumns='3')
        command = "update setup general set dashboardcolumns='3'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_dashboardcolumns_invalid(self):
        """ test setup dashboardcolumns """
        setup = dict(dashboardcolumns='0')
        msg = "The submitted Dashboard Columns value is invalid."
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_logincss(self):
        """ test setup logincss """
        setup = dict(logincss='ff0000')
        command = "update setup general set logincss='ff0000'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_logincss_invalid(self):
        """ test setup logincss """
        setup = dict(logincss='gg0000')
        msg = "logincss must be a six digits hexadecimal string."
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_dns_addresses(self):
        """ test setup dns """
        setup = dict(dns_addresses='8.8.4.4 8.8.8.8', dns_hostnames='acme1 acme2', dns_gateways='none GW_WAN')
        command = "update setup general set dns_addresses='8.8.4.4 8.8.8.8', dns_hostnames='acme1 acme2', dns_gateways='none GW_WAN'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_dns_addresses_invalid(self):
        """ test setup dns """
        setup = dict(dns_addresses='8.8.4.4 8.8.8.8 256.255.254.253', dns_hostnames='acme1 acme2', dns_gateways='none GW_WAN')
        msg = 'A valid IP address must be specified for DNS server 256.255.254.253.'
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_dns_addresses_ipv6(self):
        """ test setup dns """
        setup = dict(dns_addresses='2001::8 8.8.4.4', dns_hostnames='acme1 acme2', dns_gateways='none GW_WAN')
        command = "update setup general set dns_addresses='2001::8 8.8.4.4', dns_hostnames='acme1 acme2', dns_gateways='none GW_WAN'"
        self.do_module_test(setup, command=command, state=None)

    def test_setup_dns_addresses_invalid_ipv4(self):
        """ test setup dns """
        setup = dict(dns_addresses='8.8.4.4 8.8.8.8', dns_hostnames='acme1 acme2', dns_gateways='none GW_LAN6')
        msg = 'The IPv6 gateway "GW_LAN6" can not be specified for IPv4 DNS server "8.8.8.8".'
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_dns_addresses_invalid_ipv6(self):
        """ test setup dns """
        setup = dict(dns_addresses='8.8.4.4 2001::8', dns_hostnames='acme1 acme2', dns_gateways='none GW_WAN')
        msg = 'The IPv4 gateway "GW_WAN" can not be specified for IPv6 DNS server "2001::8".'
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_dns_addresses_invalid_gw(self):
        """ test setup dns """
        setup = dict(dns_addresses='8.8.4.4 8.8.8.8', dns_hostnames='acme1 acme2', dns_gateways='none GW_ACME')
        msg = 'The gateway "GW_ACME" does not exist.'
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_dns_addresses_invalid_gw2(self):
        """ test setup dns """
        setup = dict(dns_addresses='8.8.4.4 192.168.1.1', dns_hostnames='acme1 acme2', dns_gateways='none GW_WAN')
        msg = "A gateway can not be assigned to DNS '192.168.1.1' server which is on a directly connected network."
        self.do_module_test(setup, msg=msg, state=None, failed=True)

    def test_setup_dns_addresses_duplicates(self):
        """ test setup dns """
        setup = dict(dns_addresses='8.8.8.8 8.8.8.8', dns_hostnames='acme1 acme2', dns_gateways='none GW_WAN')
        msg = "Each configured DNS server must have a unique IP address. Remove the duplicated IP."
        self.do_module_test(setup, msg=msg, state=None, failed=True)
