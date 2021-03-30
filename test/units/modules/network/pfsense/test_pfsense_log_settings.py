# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from copy import copy
import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from units.modules.utils import set_module_args
from ansible.modules.network.pfsense import pfsense_log_settings

from .pfsense_module import TestPFSenseModule


class TestPFSenseLogSettingsModule(TestPFSenseModule):

    module = pfsense_log_settings

    def __init__(self, *args, **kwargs):
        super(TestPFSenseLogSettingsModule, self).__init__(*args, **kwargs)
        self.config_file = 'pfsense_syslog_config.xml'
        self.pfmodule = pfsense_log_settings.PFSenseLogSettingsModule
        self.defaults = {
            'filterdescriptions': 1,
            'reverse': True,
            'nentries': 50,
            'sourceip': None,
            'ipproto': 'ipv4',
        }

    ##############
    # tests utils
    #
    def get_target_elt(self, obj, absent=False):
        """ get the generated xml definition """
        return self.assert_find_xml_elt(self.xml_result, 'syslog')

    def check_target_elt(self, params, target_elt):
        """ test the xml definition of target elt """
        def check_param(param, xml_field=None):
            if params is not None:
                if xml_field is None:
                    xml_field = param

                if param in params:
                    # Special handling for sourceip
                    # Given as ip or descr but set as internal interface id
                    interface_map = {
                        '192.168.240.137': 'wan',
                        'wan': 'wan',
                        '192.168.1.242': 'lan',
                        '10.255.2.254': '_vip5c0a4b6139b05',
                        '127.0.0.1': 'lo0',
                        'Localhost': 'lo0',
                    }
                    if param == 'sourceip':
                        self.assert_xml_elt_equal(target_elt, xml_field, interface_map.get(params[param], params[param]))
                    else:
                        self.assert_xml_elt_equal(target_elt, xml_field, params[param])
                else:
                    if param in self.defaults:
                        self.assert_xml_elt_equal(target_elt, xml_field, self.defaults[param])
                    else:
                        self.assert_not_find_xml_elt(target_elt, xml_field)

        def check_bool_param(param, xml_field=None):
            if params is not None:
                if xml_field is None:
                    xml_field = param

                if param in params:
                    # Special handling for inverted field
                    # When nologdefaultpass is present in xml, value is False
                    if param == 'nologdefaultpass':
                        if params[param]:
                            self.assert_not_find_xml_elt(target_elt, param)
                        else:
                            self.assert_xml_elt_equal(target_elt, xml_field, '')
                    else:
                        self.check_param_bool(params, target_elt, param, xml_field=xml_field)
                else:
                    if param in self.defaults:
                        if self.defaults[param]:
                            self.assert_xml_elt_equal(target_elt, xml_field, None)
                        else:
                            self.assert_xml_elt_is_none_or_empty(target_elt, xml_field)
                    else:
                        self.assert_not_find_xml_elt(target_elt, xml_field)

        check_param('logformat', xml_field='format')
        check_bool_param('reverse')
        check_param('nentries')
        check_bool_param('nologdefaultblock')
        check_bool_param('nologdefaultpass')
        check_bool_param('nologbogons')
        check_bool_param('nologprivatenets')
        check_bool_param('nolognginx')
        check_bool_param('rawfilter')
        check_param('filterdescriptions')
        check_bool_param('disablelocallogging')
        check_param('logfilesize')
        check_param('logcompressiontype')
        check_param('rotatecount')
        check_bool_param('enable')
        check_param('sourceip')
        check_param('ipproto')
        check_param('remoteserver')
        check_param('remoteserver2')
        check_param('remoteserver3')
        check_bool_param('logall')
        check_bool_param('system')
        check_bool_param('logfilter', xml_field='filter')
        check_bool_param('resolver')
        check_bool_param('dhcp')
        check_bool_param('ppp')
        check_bool_param('auth')
        check_bool_param('portalauth')
        check_bool_param('vpn')
        check_bool_param('dpinger')
        check_bool_param('routing')
        check_bool_param('ntpd')
        check_bool_param('hostapd')

    def test_syslog_logformat_rfc5424(self):
        """ test syslog format rfc5424 """
        syslog = dict(logformat='rfc5424')
        command = "update log_settings syslog set format='rfc5424'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_logformat_rfc3164(self):
        """ test syslog format rfc3164 """
        syslog = dict(logformat='rfc3164')
        command = "update log_settings syslog set format='rfc3164'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_logformat_invalid(self):
        """ test syslog format invalid """
        syslog = dict(logformat='rfc1149')
        msg = 'value of logformat must be one of: rfc3164, rfc5424, got: rfc1149'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_reverse(self):
        """ test log_settings reverse=False """
        syslog = dict(reverse=False)
        command = "update log_settings syslog set reverse=False"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_reverse_true(self):
        """ test log_settings reverse=True """
        syslog = dict(reverse=True)
        self.do_module_test(syslog, changed=False, state=None)

    def test_syslog_nentries_valid(self):
        """ test log_settings nentries """
        syslog = dict(nentries='5')
        command = "update log_settings syslog set nentries='5'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_nentries_valid2(self):
        """ test log_settings nentries """
        syslog = dict(nentries='500')
        command = "update log_settings syslog set nentries='500'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_nentries_valid3(self):
        """ test log_settings nentries """
        syslog = dict(nentries='200000')
        command = "update log_settings syslog set nentries='200000'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_nentries_invalid1(self):
        """ test log_settings nentries """
        syslog = dict(nentries='-1')
        msg = 'nentries must be an integer from 5 to 200000'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_nentries_invalid2(self):
        """ test log_settings nentries """
        syslog = dict(nentries='4')
        msg = 'nentries must be an integer from 5 to 200000'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_nentries_invalid3(self):
        """ test log_settings nentries """
        syslog = dict(nentries='200001')
        msg = 'nentries must be an integer from 5 to 200000'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_nologdefaultblock_false(self):
        """ test log_settings nologdefaultblock=False """
        syslog = dict(nologdefaultblock=False)
        self.do_module_test(syslog, changed=False, state=None)

    def test_syslog_nologdefaultblock_true(self):
        """ test log_settings nologdefaultblock=True """
        syslog = dict(nologdefaultblock=True)
        command = "update log_settings syslog set nologdefaultblock=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_nologdefaultpass_false(self):
        """ test log_settings nologdefaultpass=False """
        syslog = dict(nologdefaultpass=False)
        # different bool values are correct, logic is inverted
        command = "update log_settings syslog set nologdefaultpass=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_nologdefaultpass_true(self):
        """ test log_settings nologdefaultpass=True """
        syslog = dict(nologdefaultpass=True)
        self.do_module_test(syslog, changed=False, state=None)

    def test_syslog_nologbogons_false(self):
        """ test log_settings nologbogons=False """
        syslog = dict(nologbogons=False)
        self.do_module_test(syslog, changed=False, state=None)

    def test_syslog_nologbogons_true(self):
        """ test log_settings nologbogons=True """
        syslog = dict(nologbogons=True)
        command = "update log_settings syslog set nologbogons=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_nologprivatenets_false(self):
        """ test log_settings nologprivatenets=False """
        syslog = dict(nologprivatenets=False)
        self.do_module_test(syslog, changed=False, state=None)

    def test_syslog_nologprivatenets_true(self):
        """ test log_settings nologprivatenets=True """
        syslog = dict(nologprivatenets=True)
        command = "update log_settings syslog set nologprivatenets=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_nolognginx_false(self):
        """ test log_settings nolognginx=False """
        syslog = dict(nolognginx=False)
        self.do_module_test(syslog, changed=False, state=None)

    def test_syslog_nolognginx_true(self):
        """ test log_settings nolognginx=True """
        syslog = dict(nolognginx=True)
        command = "update log_settings syslog set nolognginx=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_rawfilter_false(self):
        """ test log_settings rawfilter=False """
        syslog = dict(rawfilter=False)
        self.do_module_test(syslog, changed=False, state=None)

    def test_syslog_rawfilter_true(self):
        """ test log_settings rawfilter=True """
        syslog = dict(rawfilter=True)
        command = "update log_settings syslog set rawfilter=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_filterdescriptions_valid0(self):
        """ test log_settings filterdescriptions = 0 """
        syslog = dict(filterdescriptions='0')
        command = "update log_settings syslog set filterdescriptions='0'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_filterdescriptions_valid1(self):
        """ test log_settings filterdescriptions = 1 """
        syslog = dict(filterdescriptions='1')
        self.do_module_test(syslog, changed=False, state=None)

    def test_syslog_filterdescriptions_valid2(self):
        """ test log_settings filterdescriptions = 2 """
        syslog = dict(filterdescriptions='2')
        command = "update log_settings syslog set filterdescriptions='2'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_filterdescriptions_invalid3(self):
        """ test log_settings filterdescriptions = 3 """
        syslog = dict(filterdescriptions='3')
        msg = "value of filterdescriptions must be one of: 0, 1, 2, got: 3"
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_disablelocallogging_false(self):
        """ test log_settings disablelocallogging=False """
        syslog = dict(disablelocallogging=False)
        self.do_module_test(syslog, changed=False, state=None)

    def test_syslog_disablelocallogging_true(self):
        """ test log_settings disablelocallogging=True """
        syslog = dict(disablelocallogging=True)
        command = "update log_settings syslog set disablelocallogging=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_logfilesize_valid1(self):
        """ test log_settings logfilesize """
        syslog = dict(logfilesize='512000')
        command = "update log_settings syslog set logfilesize='512000'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_logfilesize_valid2(self):
        """ test log_settings logfilesize """
        syslog = dict(logfilesize='100000')
        command = "update log_settings syslog set logfilesize='100000'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_logfilesize_valid3(self):
        """ test log_settings logfilesize """
        syslog = dict(logfilesize=int((2**32) / 2) - 1)
        command = "update log_settings syslog set logfilesize='2147483647'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_logfilesize_invalid1(self):
        """ test log_settings logfilesize """
        syslog = dict(logfilesize='-1')
        msg = 'logfilesize must be an integer greater or equal than 100000'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_logfilesize_invalid2(self):
        """ test log_settings logfilesize """
        syslog = dict(logfilesize='99999')
        msg = 'logfilesize must be an integer greater or equal than 100000'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_logfilesize_invalid3(self):
        """ test log_settings logfilesize """
        syslog = dict(logfilesize='0')
        msg = 'logfilesize must be an integer greater or equal than 100000'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_logfilesize_invalid4(self):
        """ test log_settings logfilesize """
        syslog = dict(logfilesize=int(((2**32) / 2) + 1))
        msg = 'logfilesize is too large: 2147483649'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_logcompressiontype_valid_xz(self):
        """ test syslog logcompression = xz """
        syslog = dict(logcompressiontype='xz')
        command = "update log_settings syslog set logcompressiontype='xz'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_logcompressiontype_valid_gzip(self):
        """ test syslog logcompression = gzip """
        syslog = dict(logcompressiontype='gzip')
        command = "update log_settings syslog set logcompressiontype='gzip'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_rotatecount_valid0(self):
        """ test log_settings rotatecount """
        syslog = dict(rotatecount='0')
        command = "update log_settings syslog set rotatecount='0'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_rotatecount_valid1(self):
        """ test log_settings rotatecount """
        syslog = dict(rotatecount='7')
        command = "update log_settings syslog set rotatecount='7'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_rotatecount_valid2(self):
        """ test log_settings rotatecount """
        syslog = dict(rotatecount='31')
        command = "update log_settings syslog set rotatecount='31'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_rotatecount_valid3(self):
        """ test log_settings rotatecount """
        syslog = dict(rotatecount='99')
        command = "update log_settings syslog set rotatecount='99'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_rotatecount_invalid1(self):
        """ test log_settings rotatecount """
        syslog = dict(rotatecount='-1')
        msg = 'rotatecount must be an integer from 0 to 99'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_rotatecount_invalid2(self):
        """ test log_settings rotatecount """
        syslog = dict(rotatecount='100')
        msg = 'rotatecount must be an integer from 0 to 99'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_enable_true(self):
        """ test syslog format enable=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', logall=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_enable_false(self):
        """ test syslog format logall=false """
        syslog = dict(enable=False)
        self.do_module_test(syslog, changed=False, state=None)

    def test_syslog_ipproto_ipv4(self):
        """ test syslog ipproto ipv4 """
        syslog = dict(ipproto='ipv4')
        command = "update log_settings syslog set ipproto='ipv4'"
        self.do_module_test(syslog, command=command, state=None, changed=False)

    def test_syslog_ipproto_ipv6(self):
        """ test syslog ipproto ipv6 """
        syslog = dict(ipproto='ipv6')
        command = "update log_settings syslog set ipproto='ipv6'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_sourceip_wan_ip(self):
        """ test log_settings sourceip=wan """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, sourceip='192.168.240.137')
        command = "update log_settings syslog set enable=True, sourceip='wan', remoteserver='1.2.3.4', logall=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_sourceip_wan_descr(self):
        """ test log_settings sourceip=wan """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, sourceip='wan')
        command = "update log_settings syslog set enable=True, sourceip='wan', remoteserver='1.2.3.4', logall=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_sourceip_lan(self):
        """ test log_settings sourceip=lan """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, sourceip='192.168.1.242')
        command = "update log_settings syslog set enable=True, sourceip='lan', remoteserver='1.2.3.4', logall=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_sourceip_lo0(self):
        """ test log_settings sourceip=lan """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, sourceip='127.0.0.1')
        command = "update log_settings syslog set enable=True, sourceip='lo0', remoteserver='1.2.3.4', logall=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_sourceip_descr(self):
        """ test log_settings sourceip=lan """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, sourceip='Localhost')
        command = "update log_settings syslog set enable=True, sourceip='lo0', remoteserver='1.2.3.4', logall=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_sourceip_valid_empty(self):
        """ test log_settings sourceip='' """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, sourceip=None)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', logall=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_sourceip_valid_vip_ip(self):
        """ test log_settings sourceip=_vip5c0a4b6139b05 """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, sourceip='10.255.2.254')
        command = "update log_settings syslog set enable=True, sourceip='_vip5c0a4b6139b05', remoteserver='1.2.3.4', logall=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_sourceip_invalid_vip(self):
        """ test log_settings sourceip=_vip5c0a4b6139b06 """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, sourceip='_vip5c0a4b6139b05')
        msg = "sourceip: Invalid address _vip5c0a4b6139b05!"
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_sourceip_invalid_opt4(self):
        """ test log_settings sourceip=opt4 """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, sourceip='opt4')
        msg = "sourceip: Invalid address opt4!"
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_remoteserver_hostname(self):
        """ test log_settings remoteserver_hostname """
        syslog = dict(enable=True, remoteserver='2001:0db8:cafe:affe:0000:0000:0000:0001', logall=True)
        command = "update log_settings syslog set enable=True, remoteserver='2001:0db8:cafe:affe:0000:0000:0000:0001', logall=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_remoteserver_fqdn(self):
        """ test log_settings remoteserver_fqdn """
        syslog = dict(enable=True, remoteserver='logserver.example.com', logall=True)
        command = "update log_settings syslog set enable=True, remoteserver='logserver.example.com', logall=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_remoteserver_fqdn_port(self):
        """ test log_settings remoteserver_fqdn_port """
        syslog = dict(enable=True, remoteserver='logserver.example.com:514', logall=True)
        command = "update log_settings syslog set enable=True, remoteserver='logserver.example.com:514', logall=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_remoteserver_ipv6(self):
        """ test log_settings remoteserver_ipv6 """
        syslog = dict(enable=True, remoteserver='2001:0db8:cafe:affe:0000:0000:0000:0001', logall=True)
        command = "update log_settings syslog set enable=True, remoteserver='2001:0db8:cafe:affe:0000:0000:0000:0001', logall=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_remoteserver_ipv6_port(self):
        """ test log_settings remoteserver_ipv6 """
        syslog = dict(enable=True, remoteserver='[2001:0db8:cafe:affe:0000:0000:0000:0001]:514', logall=True)
        command = "update log_settings syslog set enable=True, remoteserver='[2001:0db8:cafe:affe:0000:0000:0000:0001]:514', logall=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_remoteserver_ipv4_invalid_port1(self):
        """ test log_settings remoteserver_ipv4_invalid_port1 """
        syslog = dict(enable=True, remoteserver='1234:0', logall=True)
        msg = "Invalid port 0"
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_remoteserver_ipv4_invalid_port2(self):
        """ test log_settings remoteserver_ipv4_invalid_port1 """
        syslog = dict(enable=True, remoteserver='1234:65536', logall=True)
        msg = "Invalid port 65536"
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_ipproto_invalid(self):
        """ test syslog ipproto invalid """
        syslog = dict(ipproto='ipv5')
        msg = 'value of ipproto must be one of: ipv4, ipv6, got: ipv5'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_logall_true(self):
        """ test syslog format logall=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', logall=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_logall_false(self):
        """ test syslog format logall=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=False)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_system_true(self):
        """ test syslog format system=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', system=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', system=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_system_false(self):
        """ test syslog format system=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', system=False)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_system_invalid_with_logall(self):
        """ test syslog format system=true, logall=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, system=True)
        msg = 'system = True is invalid when logall is True'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_system_valid_with_logall(self):
        """ test syslog format system=true, logall=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=False, system=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', system=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_logfilter_true(self):
        """ test syslog format logfilter=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logfilter=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', filter=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_logfilter_false(self):
        """ test syslog format logfilter=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logfilter=False)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_logfilter_invalid_with_logall(self):
        """ test syslog format logfilter=true, logall=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, logfilter=True)
        msg = 'logfilter = True is invalid when logall is True'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_logfilter_valid_with_logall(self):
        """ test syslog format logfilter=true, logall=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=False, logfilter=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', filter=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_resolver_true(self):
        """ test syslog format resolver=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', resolver=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', resolver=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_resolver_false(self):
        """ test syslog format resolver=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', resolver=False)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_resolver_invalid_with_logall(self):
        """ test syslog format resolver=true, logall=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, resolver=True)
        msg = 'resolver = True is invalid when logall is True'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_resolver_valid_with_logall(self):
        """ test syslog format resolver=true, logall=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=False, resolver=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', resolver=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_dhcp_true(self):
        """ test syslog format dhcp=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', dhcp=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', dhcp=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_dhcp_false(self):
        """ test syslog format dhcp=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', dhcp=False)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_dhcp_invalid_with_logall(self):
        """ test syslog format dhcp=true, logall=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, dhcp=True)
        msg = 'dhcp = True is invalid when logall is True'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_dhcp_valid_with_logall(self):
        """ test syslog format dhcp=true, logall=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=False, dhcp=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', dhcp=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_ppp_true(self):
        """ test syslog format ppp=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', ppp=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', ppp=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_ppp_false(self):
        """ test syslog format ppp=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', ppp=False)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_ppp_invalid_with_logall(self):
        """ test syslog format ppp=true, logall=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, ppp=True)
        msg = 'ppp = True is invalid when logall is True'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_ppp_valid_with_logall(self):
        """ test syslog format ppp=true, logall=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=False, ppp=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', ppp=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_auth_true(self):
        """ test syslog format auth=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', auth=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', auth=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_auth_false(self):
        """ test syslog format auth=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', auth=False)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_auth_invalid_with_logall(self):
        """ test syslog format auth=true, logall=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, auth=True)
        msg = 'auth = True is invalid when logall is True'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_auth_valid_with_logall(self):
        """ test syslog format auth=true, logall=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=False, auth=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', auth=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_portalauth_true(self):
        """ test syslog format portalauth=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', portalauth=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', portalauth=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_portalauth_false(self):
        """ test syslog format portalauth=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', portalauth=False)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_portalauth_invalid_with_logall(self):
        """ test syslog format portalauth=true, logall=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, portalauth=True)
        msg = 'portalauth = True is invalid when logall is True'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_portalauth_valid_with_logall(self):
        """ test syslog format portalauth=true, logall=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=False, portalauth=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', portalauth=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_vpn_true(self):
        """ test syslog format vpn=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', vpn=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', vpn=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_vpn_false(self):
        """ test syslog format vpn=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', vpn=False)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_vpn_invalid_with_logall(self):
        """ test syslog format vpn=true, logall=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, vpn=True)
        msg = 'vpn = True is invalid when logall is True'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_vpn_valid_with_logall(self):
        """ test syslog format vpn=true, logall=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=False, vpn=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', vpn=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_dpinger_true(self):
        """ test syslog format dpinger=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', dpinger=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', dpinger=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_dpinger_false(self):
        """ test syslog format dpinger=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', dpinger=False)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_dpinger_invalid_with_logall(self):
        """ test syslog format dpinger=true, logall=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, dpinger=True)
        msg = 'dpinger = True is invalid when logall is True'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_dpinger_valid_with_logall(self):
        """ test syslog format dpinger=true, logall=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=False, dpinger=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', dpinger=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_routing_true(self):
        """ test syslog format routing=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', routing=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', routing=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_routing_false(self):
        """ test syslog format routing=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', routing=False)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_routing_invalid_with_logall(self):
        """ test syslog format routing=true, logall=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, routing=True)
        msg = 'routing = True is invalid when logall is True'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_routing_valid_with_logall(self):
        """ test syslog format routing=true, logall=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=False, routing=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', routing=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_ntpd_true(self):
        """ test syslog format ntpd=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', ntpd=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', ntpd=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_ntpd_false(self):
        """ test syslog format ntpd=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', ntpd=False)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_ntpd_invalid_with_logall(self):
        """ test syslog format ntpd=true, logall=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, ntpd=True)
        msg = 'ntpd = True is invalid when logall is True'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_ntpd_valid_with_logall(self):
        """ test syslog format ntpd=true, logall=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=False, ntpd=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', ntpd=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_hostapd_true(self):
        """ test syslog format hostapd=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', hostapd=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', hostapd=True"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_hostapd_false(self):
        """ test syslog format hostapd=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', hostapd=False)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4'"
        self.do_module_test(syslog, command=command, state=None)

    def test_syslog_hostapd_invalid_with_logall(self):
        """ test syslog format hostapd=true, logall=true """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=True, hostapd=True)
        msg = 'hostapd = True is invalid when logall is True'
        self.do_module_test(syslog, msg=msg, state=None, failed=True)

    def test_syslog_hostapd_valid_with_logall(self):
        """ test syslog format hostapd=true, logall=false """
        syslog = dict(enable=True, remoteserver='1.2.3.4', logall=False, hostapd=True)
        command = "update log_settings syslog set enable=True, remoteserver='1.2.3.4', hostapd=True"
        self.do_module_test(syslog, command=command, state=None)
