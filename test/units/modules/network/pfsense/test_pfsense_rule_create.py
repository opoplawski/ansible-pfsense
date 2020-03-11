# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from .test_pfsense_rule import TestPFSenseRuleModule


class TestPFSenseRuleCreateModule(TestPFSenseRuleModule):

    ############################
    # rule creation tests
    #
    def test_rule_create_one_rule(self):
        """ test creation of a new rule """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any'"
        self.do_module_test(obj, command=command)

    def test_rule_create_log(self):
        """ test creation of a new rule with logging """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', log='yes')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', log=True"
        self.do_module_test(obj, command=command)

    def test_rule_create_nolog(self):
        """ test creation of a new rule without logging """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', log='no')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any'"
        self.do_module_test(obj, command=command)

    def test_rule_create_pass(self):
        """ test creation of a new rule explictly passing """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', action='pass')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any'"
        self.do_module_test(obj, command=command)

    def test_rule_create_block(self):
        """ test creation of a new rule blocking """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', action='block')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', action='block'"
        self.do_module_test(obj, command=command)

    def test_rule_create_reject(self):
        """ test creation of a new rule rejecting """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', action='reject')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', action='reject'"
        self.do_module_test(obj, command=command)

    def test_rule_create_disabled(self):
        """ test creation of a new disabled rule """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', disabled=True)
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', disabled=True"
        self.do_module_test(obj, command=command)

    def test_rule_create_floating(self):
        """ test creation of a new floating rule """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', floating='yes', direction='any')
        command = "create rule 'one_rule' on 'floating(lan)', source='any', destination='any', direction='any'"
        self.do_module_test(obj, command=command)

    def test_rule_create_nofloating(self):
        """ test creation of a new non-floating rule """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', floating='no')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any'"
        self.do_module_test(obj, command=command)

    def test_rule_create_floating_interfaces(self):
        """ test creation of a floating rule on three interfaces """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan,wan,vt1', floating='yes', direction='any')
        command = "create rule 'one_rule' on 'floating(lan,wan,vt1)', source='any', destination='any', direction='any'"
        self.do_module_test(obj, command=command)

    def test_rule_create_inet46(self):
        """ test creation of a new rule using ipv4 and ipv6 """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', ipprotocol='inet46')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', ipprotocol='inet46'"
        self.do_module_test(obj, command=command)

    def test_rule_create_inet6(self):
        """ test creation of a new rule using ipv6 """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', ipprotocol='inet6')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', ipprotocol='inet6'"
        self.do_module_test(obj, command=command)

    def test_rule_create_tcp(self):
        """ test creation of a new rule for tcp protocol """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', protocol='tcp')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', protocol='tcp'"
        self.do_module_test(obj, command=command)

    def test_rule_create_udp(self):
        """ test creation of a new rule for udp protocol """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', protocol='udp')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', protocol='udp'"
        self.do_module_test(obj, command=command)

    def test_rule_create_tcp_udp(self):
        """ test creation of a new rule for tcp/udp protocols """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', protocol='tcp/udp')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', protocol='tcp/udp'"
        self.do_module_test(obj, command=command)

    def test_rule_create_icmp(self):
        """ test creation of a new rule for icmp protocol """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', protocol='icmp')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', protocol='icmp'"
        self.do_module_test(obj, command=command)

    def test_rule_create_icmp_redir(self):
        """ test creation of a new rule for icmp protocol """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', protocol='icmp', icmptype='redir', action='block')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', protocol='icmp', icmptype='redir', action='block'"
        self.do_module_test(obj, command=command)

    def test_rule_create_icmp_invalid_inet(self):
        """ test creation of a new rule for icmp protocol """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', protocol='icmp', icmptype='neighbradv')
        msg = 'ICMP types neighbradv are invalid with IP type inet'
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_icmp_invalid_inet6(self):
        """ test creation of a new rule for icmp protocol """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', protocol='icmp', ipprotocol='inet6', icmptype='trace')
        msg = 'ICMP types trace are invalid with IP type inet6'
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_icmp_invalid_inet46(self):
        """ test creation of a new rule for icmp protocol """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', protocol='icmp', ipprotocol='inet46', icmptype='trace')
        msg = 'ICMP types trace are invalid with IP type inet46'
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_icmp_invalid_empty(self):
        """ test creation of a new rule for icmp protocol """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', protocol='icmp', icmptype='')
        msg = 'You must specify at least one icmptype or any for all of them'
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_protocol_any(self):
        """ test creation of a new rule for (self) """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', protocol='any')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any'"
        self.do_module_test(obj, command=command)

    def test_rule_create_state_keep(self):
        """ test creation of a new rule with explicit keep state """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', statetype='keep state')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any'"
        self.do_module_test(obj, command=command)

    def test_rule_create_state_sloppy(self):
        """ test creation of a new rule with sloppy state """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', statetype='sloppy state')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', statetype='sloppy state'"
        self.do_module_test(obj, command=command)

    def test_rule_create_state_synproxy(self):
        """ test creation of a new rule with synproxy state """
        # todo: synproxy is only valid with tcp
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', statetype='synproxy state')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', statetype='synproxy state'"
        self.do_module_test(obj, command=command)

    def test_rule_create_state_none(self):
        """ test creation of a new rule with no state """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', statetype='none')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', statetype='none'"
        self.do_module_test(obj, command=command)

    def test_rule_create_state_invalid(self):
        """ test creation of a new rule with invalid state """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', statetype='acme state')
        msg = "value of statetype must be one of: keep state, sloppy state, synproxy state, none, got: acme state"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_after(self):
        """ test creation of a new rule after another """
        obj = dict(name='one_rule', source='any', destination='any', interface='vpn', after='admin_bypass')
        command = "create rule 'one_rule' on 'vpn', source='any', destination='any', after='admin_bypass'"
        self.do_module_test(obj, command=command)
        self.check_rule_idx(obj, 13)

    def test_rule_create_after_top(self):
        """ test creation of a new rule at top """
        obj = dict(name='one_rule', source='any', destination='any', interface='wan', after='top')
        command = "create rule 'one_rule' on 'wan', source='any', destination='any', after='top'"
        self.do_module_test(obj, command=command)
        self.check_rule_idx(obj, 0)

    def test_rule_create_after_invalid(self):
        """ test creation of a new rule after an invalid rule """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', after='admin_bypass')
        msg = "Failed to insert after rule=admin_bypass interface=lan"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_before(self):
        """ test creation of a new rule before another """
        obj = dict(name='one_rule', source='any', destination='any', interface='vpn', before='admin_bypass')
        command = "create rule 'one_rule' on 'vpn', source='any', destination='any', before='admin_bypass'"
        self.do_module_test(obj, command=command)
        self.check_rule_idx(obj, 12)

    def test_rule_create_before_bottom(self):
        """ test creation of a new rule at bottom """
        obj = dict(name='one_rule', source='any', destination='any', interface='wan', before='bottom')
        command = "create rule 'one_rule' on 'wan', source='any', destination='any', before='bottom'"
        self.do_module_test(obj, command=command)
        self.check_rule_idx(obj, 4)

    def test_rule_create_before_bottom_default(self):
        """ test creation of a new rule at bottom (default) """
        obj = dict(name='one_rule', source='any', destination='any', interface='wan', action='pass')
        command = "create rule 'one_rule' on 'wan', source='any', destination='any'"
        self.do_module_test(obj, command=command)
        self.check_rule_idx(obj, 4)

    def test_rule_create_before_invalid(self):
        """ test creation of a new rule before an invalid rule """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', before='admin_bypass')
        msg = "Failed to insert before rule=admin_bypass interface=lan"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_source_alias(self):
        """ test creation of a new rule with a valid source alias """
        obj = dict(name='one_rule', source='srv_admin', destination='any', interface='lan')
        command = "create rule 'one_rule' on 'lan', source='srv_admin', destination='any'"
        self.do_module_test(obj, command=command)

    def test_rule_create_source_alias_invalid(self):
        """ test creation of a new rule with an invalid source alias """
        obj = dict(name='one_rule', source='acme', destination='any', interface='lan')
        msg = "Cannot parse address acme, not IP or alias"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_invalid_ports(self):
        """ test creation of a new rule with an invalid use of ports """
        obj = dict(name='one_rule', source='192.193.194.195', destination='any:22', interface='lan', protocol='icmp')
        msg = "you can't use ports on protocols other than tcp, udp or tcp/udp"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_source_ip_invalid(self):
        """ test creation of a new rule with an invalid source ip """
        obj = dict(name='one_rule', source='192.193.194.195.196', destination='any', interface='lan')
        msg = "Cannot parse address 192.193.194.195.196, not IP or alias"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_source_net_invalid(self):
        """ test creation of a new rule with an invalid source network """
        obj = dict(name='one_rule', source='192.193.194.195/256', destination='any', interface='lan')
        msg = "Cannot parse address 192.193.194.195/256, not IP or alias"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_destination_alias(self):
        """ test creation of a new rule with a valid destination alias """
        obj = dict(name='one_rule', source='any', destination='srv_admin', interface='lan')
        command = "create rule 'one_rule' on 'lan', source='any', destination='srv_admin'"
        self.do_module_test(obj, command=command)

    def test_rule_create_destination_alias_invalid(self):
        """ test creation of a new rule with an invalid destination alias """
        obj = dict(name='one_rule', source='any', destination='acme', interface='lan')
        msg = "Cannot parse address acme, not IP or alias"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_destination_ip_invalid(self):
        """ test creation of a new rule with an invalid destination ip """
        obj = dict(name='one_rule', source='any', destination='192.193.194.195.196', interface='lan')
        msg = "Cannot parse address 192.193.194.195.196, not IP or alias"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_destination_net_invalid(self):
        """ test creation of a new rule with an invalid destination network """
        obj = dict(name='one_rule', source='any', destination='192.193.194.195/256', interface='lan')
        msg = "Cannot parse address 192.193.194.195/256, not IP or alias"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_source_self_lan(self):
        """ test creation of a new rule with self"""
        obj = dict(name='one_rule', source='(self)', destination='any', interface='lan')
        command = "create rule 'one_rule' on 'lan', source='(self)', destination='any'"
        self.do_module_test(obj, command=command)

    def test_rule_create_ip_to_ip(self):
        """ test creation of a new rule with valid ips """
        obj = dict(name='one_rule', source='10.10.1.1', destination='10.10.10.1', interface='lan')
        command = "create rule 'one_rule' on 'lan', source='10.10.1.1', destination='10.10.10.1'"
        self.do_module_test(obj, command=command)

    def test_rule_create_net_to_net(self):
        """ test creation of a new rule valid networks """
        obj = dict(name='one_rule', source='10.10.1.0/24', destination='10.10.10.0/24', interface='lan')
        command = "create rule 'one_rule' on 'lan', source='10.10.1.0/24', destination='10.10.10.0/24'"
        self.do_module_test(obj, command=command)

    def test_rule_create_net_interface(self):
        """ test creation of a new rule with valid interface """
        obj = dict(name='one_rule', source='NET:lan', destination='any', interface='lan')
        command = "create rule 'one_rule' on 'lan', source='NET:lan', destination='any'"
        self.do_module_test(obj, command=command)

    def test_rule_create_net_interface_invalid(self):
        """ test creation of a new rule with invalid interface """
        obj = dict(name='one_rule', source='NET:invalid_lan', destination='any', interface='lan')
        msg = "invalid_lan is not a valid interface"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_net_interface_invalid2(self):
        """ test creation of a new rule with invalid interface """
        obj = dict(name='one_rule', source='NET:', destination='any', interface='lan')
        msg = "Cannot parse address NET:"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_ip_interface(self):
        """ test creation of a new rule with valid interface """
        obj = dict(name='one_rule', source='IP:vt1', destination='any', interface='lan')
        command = "create rule 'one_rule' on 'lan', source='IP:vt1', destination='any'"
        self.do_module_test(obj, command=command)

    def test_rule_create_ip_interface_with_port(self):
        """ test creation of a new rule with valid interface """
        obj = dict(name='one_rule', source='IP:vt1:22', destination='any', interface='lan', protocol='tcp')
        command = "create rule 'one_rule' on 'lan', source='IP:vt1:22', destination='any', protocol='tcp'"
        self.do_module_test(obj, command=command)

    def test_rule_create_ip_interface_invalid(self):
        """ test creation of a new rule with invalid interface """
        obj = dict(name='one_rule', source='IP:invalid_lan', destination='any', interface='lan')
        msg = "invalid_lan is not a valid interface"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_interface(self):
        """ test creation of a new rule with valid interface """
        obj = dict(name='one_rule', source='vpn', destination='any', interface='lan')
        command = "create rule 'one_rule' on 'lan', source='vpn', destination='any'"
        self.do_module_test(obj, command=command)

    def test_rule_create_port_number(self):
        """ test creation of a new rule with port """
        obj = dict(name='one_rule', source='10.10.1.1', destination='10.10.10.1:80', interface='lan', protocol='tcp')
        command = "create rule 'one_rule' on 'lan', source='10.10.1.1', destination='10.10.10.1:80', protocol='tcp'"
        self.do_module_test(obj, command=command)

    def test_rule_create_port_alias(self):
        """ test creation of a new rule with port alias """
        obj = dict(name='one_rule', source='10.10.1.1', destination='10.10.10.1:port_http', interface='lan', protocol='tcp')
        command = "create rule 'one_rule' on 'lan', source='10.10.1.1', destination='10.10.10.1:port_http', protocol='tcp'"
        self.do_module_test(obj, command=command)

    def test_rule_create_port_range(self):
        """ test creation of a new rule with range of ports """
        obj = dict(name='one_rule', source='10.10.1.1:30000-40000', destination='10.10.10.1', interface='lan', protocol='tcp')
        command = "create rule 'one_rule' on 'lan', source='10.10.1.1:30000-40000', destination='10.10.10.1', protocol='tcp'"
        self.do_module_test(obj, command=command)

    def test_rule_create_port_alias_range(self):
        """ test creation of a new rule with range of alias ports """
        obj = dict(name='one_rule', source='10.10.1.1:port_ssh-port_http', destination='10.10.10.1', interface='lan', protocol='tcp')
        command = "create rule 'one_rule' on 'lan', source='10.10.1.1:port_ssh-port_http', destination='10.10.10.1', protocol='tcp'"
        self.do_module_test(obj, command=command)

    def test_rule_create_port_alias_range_invalid_1(self):
        """ test creation of a new rule with range of invalid alias ports """
        obj = dict(name='one_rule', source='10.10.1.1:port_ssh-openvpn_port', destination='10.10.10.1', interface='lan')
        msg = "Cannot parse port openvpn_port, not port number or alias"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_port_alias_range_invalid_2(self):
        """ test creation of a new rule with range of invalid alias ports """
        obj = dict(name='one_rule', source='10.10.1.1:-openvpn_port', destination='10.10.10.1', interface='lan')
        msg = "Cannot parse port -openvpn_port"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_port_alias_range_invalid_3(self):
        """ test creation of a new rule with range of invalid alias ports """
        obj = dict(name='one_rule', source='10.10.1.1:port_ssh-65537', destination='10.10.10.1', interface='lan')
        msg = "Cannot parse port 65537, not port number or alias"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_port_number_invalid(self):
        """ test creation of a new rule with invalid port number """
        obj = dict(name='one_rule', source='10.10.1.1:65536', destination='10.10.10.1', interface='lan', protocol='tcp')
        msg = "Cannot parse port 65536, not port number or alias"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_port_alias_invalid(self):
        """ test creation of a new rule with invalid port alias """
        obj = dict(name='one_rule', source='10.10.1.1:openvpn_port', destination='10.10.10.1', interface='lan')
        msg = "Cannot parse port openvpn_port, not port number or alias"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_negate_source(self):
        """ test creation of a new rule with a not source """
        obj = dict(name='one_rule', source='!srv_admin', destination='any', interface='lan')
        command = "create rule 'one_rule' on 'lan', source='!srv_admin', destination='any'"
        self.do_module_test(obj, command=command)

    def test_rule_create_negate_destination(self):
        """ test creation of a new rule with a not destination """
        obj = dict(name='one_rule', source='any', destination='!srv_admin', interface='lan')
        command = "create rule 'one_rule' on 'lan', source='any', destination='!srv_admin'"
        self.do_module_test(obj, command=command)

    def test_rule_create_separator_top(self):
        """ test creation of a new rule at top """
        obj = dict(name='one_rule', source='any', destination='any', interface='vt1', after='top')
        command = "create rule 'one_rule' on 'vt1', source='any', destination='any', after='top'"
        self.do_module_test(obj, command=command)
        self.check_rule_idx(obj, 0)
        self.check_separator_idx(obj['interface'], 'test_sep1', 1)
        self.check_separator_idx(obj['interface'], 'test_sep2', 4)

    def test_rule_create_separator_bottom(self):
        """ test creation of a new rule at bottom """
        obj = dict(name='one_rule', source='any', destination='any', interface='vt1', before='bottom')
        command = "create rule 'one_rule' on 'vt1', source='any', destination='any', before='bottom'"
        self.do_module_test(obj, command=command)
        self.check_rule_idx(obj, 3)
        self.check_separator_idx(obj['interface'], 'test_sep1', 0)
        self.check_separator_idx(obj['interface'], 'test_sep2', 3)

    def test_rule_create_separator_before_first(self):
        """ test creation of a new rule before first rule """
        obj = dict(name='one_rule', source='any', destination='any', interface='vt1', before='r1')
        command = "create rule 'one_rule' on 'vt1', source='any', destination='any', before='r1'"
        self.do_module_test(obj, command=command)
        self.check_rule_idx(obj, 0)
        self.check_separator_idx(obj['interface'], 'test_sep1', 0)
        self.check_separator_idx(obj['interface'], 'test_sep2', 4)

    def test_rule_create_separator_after_third(self):
        """ test creation of a new rule after third rule """
        obj = dict(name='one_rule', source='any', destination='any', interface='vt1', after='r3')
        command = "create rule 'one_rule' on 'vt1', source='any', destination='any', after='r3'"
        self.do_module_test(obj, command=command)
        self.check_rule_idx(obj, 3)
        self.check_separator_idx(obj['interface'], 'test_sep1', 0)
        self.check_separator_idx(obj['interface'], 'test_sep2', 4)

    def test_rule_create_queue(self):
        """ test creation of a new rule with default queue """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', queue='one_queue')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', queue='one_queue'"
        self.do_module_test(obj, command=command)

    def test_rule_create_queue_ack(self):
        """ test creation of a new rule with default queue and ack queue """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', queue='one_queue', ackqueue='another_queue')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', queue='one_queue', ackqueue='another_queue'"
        self.do_module_test(obj, command=command)

    def test_rule_create_queue_ack_without_default(self):
        """ test creation of a new rule with ack queue and without default queue """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', ackqueue='another_queue')
        msg = "A default queue must be selected when an acknowledge queue is also selected"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_queue_same(self):
        """ test creation of a new rule with same default queue and ack queue """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', queue='one_queue', ackqueue='one_queue')
        msg = "Acknowledge queue and default queue cannot be the same"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_queue_invalid(self):
        """ test creation of a new rule with invalid default queue """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', queue='acme_queue')
        msg = "Failed to find enabled queue=acme_queue"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_queue_invalid_ack(self):
        """ test creation of a new rule with default queue and invalid ack queue """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', queue='one_queue', ackqueue='acme_queue')
        msg = "Failed to find enabled ackqueue=acme_queue"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_limiter(self):
        """ test creation of a new rule with in_queue """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', in_queue='one_limiter')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', in_queue='one_limiter'"
        self.do_module_test(obj, command=command)

    def test_rule_create_limiter_out(self):
        """ test creation of a new rule with in_queue and out_queue """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', in_queue='one_limiter', out_queue='another_limiter')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', in_queue='one_limiter', out_queue='another_limiter'"
        self.do_module_test(obj, command=command)

    def test_rule_create_limiter_disabled(self):
        """ test creation of a new rule with disabled in_queue """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', in_queue='disabled_limiter')
        msg = "Failed to find enabled in_queue=disabled_limiter"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_limiter_out_without_in(self):
        """ test creation of a new rule with out_queue and without in_queue """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', out_queue='another_limiter')
        msg = "A queue must be selected for the In direction before selecting one for Out too"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_limiter_same(self):
        """ test creation of a new rule with same in_queue and out_queue """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', in_queue='one_limiter', out_queue='one_limiter')
        msg = "In and Out Queue cannot be the same"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_limiter_invalid(self):
        """ test creation of a new rule with invalid in_queue """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', in_queue='acme_queue')
        msg = "Failed to find enabled in_queue=acme_queue"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_limiter_invalid_out(self):
        """ test creation of a new rule with in_queue and invalid out_queue """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', in_queue='one_limiter', out_queue='acme_queue')
        msg = "Failed to find enabled out_queue=acme_queue"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_limiter_floating_any(self):
        """ test creation of a new rule with in_queue and invalid out_queue """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', in_queue='one_limiter', floating='yes', direction='any')
        msg = "Limiters can not be used in Floating rules without choosing a direction"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_gateway(self):
        """ test creation of a new rule with gateway """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', gateway='GW_LAN')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', gateway='GW_LAN'"
        self.do_module_test(obj, command=command)

    def test_rule_create_gateway_invalid(self):
        """ test creation of a new rule with invalid gateway """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', gateway='GW_WLAN')
        msg = 'Gateway "GW_WLAN" does not exist or does not match target rule ip protocol.'
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_gateway_invalid_ipprotocol(self):
        """ test creation of a new rule with gateway """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', ipprotocol='inet6', gateway='GW_LAN')
        msg = 'Gateway "GW_LAN" does not exist or does not match target rule ip protocol.'
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_gateway_floating(self):
        """ test creation of a new floating rule with gateway """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', floating='yes', direction='in', gateway='GW_LAN')
        command = "create rule 'one_rule' on 'floating(lan)', source='any', destination='any', direction='in', gateway='GW_LAN'"
        self.do_module_test(obj, command=command)

    def test_rule_create_gateway_floating_any(self):
        """ test creation of a new floating rule with gateway """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', floating='yes', direction='any', gateway='GW_LAN')
        msg = "Gateways can not be used in Floating rules without choosing a direction"
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_gateway_group(self):
        """ test creation of a new rule with gateway group """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', gateway='GWGroup')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', gateway='GWGroup'"
        self.do_module_test(obj, command=command)

    def test_rule_create_gateway_group_invalid_ipprotocol(self):
        """ test creation of a new rule with gateway group """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', ipprotocol='inet6', gateway='GWGroup')
        msg = 'Gateway "GWGroup" does not exist or does not match target rule ip protocol.'
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_tracker(self):
        """ test creation of a new rule with tracker """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', tracker='1234')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', tracker=1234"
        self.do_module_test(obj, command=command)

    def test_rule_create_tracker_invalid(self):
        """ test creation of a new rule with invalid tracker """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', tracker='-1234')
        msg = 'tracker -1234 must be a positive integer'
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_create_schedule(self):
        """ test creation of a new rule with schedule """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', sched='workdays')
        command = "create rule 'one_rule' on 'lan', source='any', destination='any', sched='workdays'"
        self.do_module_test(obj, command=command)

    def test_rule_create_schedule_invalid(self):
        """ test creation of a new rule with invalid schedule """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan', sched='acme')
        msg = 'Schedule acme does not exist'
        self.do_module_test(obj, failed=True, msg=msg)
