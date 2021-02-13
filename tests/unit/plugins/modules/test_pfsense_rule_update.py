# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from .test_pfsense_rule import TestPFSenseRuleModule


class TestPFSenseRuleUpdateModule(TestPFSenseRuleModule):

    ############################
    # rule update tests
    #
    def test_rule_update_action(self):
        """ test updating action of a rule to block """
        obj = dict(name='test_rule', source='any', destination='any', interface='wan', action='block', protocol='tcp')
        command = "update rule 'test_rule' on 'wan' set action='block'"
        self.do_module_test(obj, command=command)

    def test_rule_update_disabled(self):
        """ test updating disabled of a rule to True """
        obj = dict(name='test_rule', source='any', destination='any', interface='wan', disabled='True', protocol='tcp')
        command = "update rule 'test_rule' on 'wan' set disabled=True"
        self.do_module_test(obj, command=command)

    def test_rule_update_enabled(self):
        """ test updating disabled of a rule to False """
        obj = dict(name='test_lan_100_1', source='any', destination='any', interface='lan_100', disabled='False', protocol='tcp')
        command = "update rule 'test_lan_100_1' on 'lan_100' set disabled=False"
        self.do_module_test(obj, command=command)

    def test_rule_update_enabled_default(self):
        """ test updating disabled of a rule to default """
        obj = dict(name='test_lan_100_1', source='any', destination='any', interface='lan_100', protocol='tcp')
        command = "update rule 'test_lan_100_1' on 'lan_100' set disabled=False"
        self.do_module_test(obj, command=command)

    def test_rule_update_floating_interface(self):
        """ test updating interface of a floating rule """
        obj = dict(name='test_rule_floating', source='any', destination='any', interface='lan', floating='yes', direction='any', protocol='tcp')
        command = "update rule 'test_rule_floating' on 'floating(wan)' set interface='lan'"
        self.do_module_test(obj, command=command)

    def test_rule_update_floating_interfaces(self):
        """ test updating interfaces of a floating rule """
        obj = dict(name='test_rule_floating', source='any', destination='any', interface='lan,lan_100', floating='yes', direction='any', protocol='tcp')
        command = "update rule 'test_rule_floating' on 'floating(wan)' set interface='lan,lan_100'"
        self.do_module_test(obj, command=command)

    def test_rule_update_floating_direction(self):
        """ test updating direction of a rule to out """
        obj = dict(name='test_rule_floating', source='any', destination='any', interface='wan', floating='yes', direction='out', protocol='tcp')
        command = "update rule 'test_rule_floating' on 'floating(wan)' set direction='out'"
        self.do_module_test(obj, command=command)

    def test_rule_update_floating_quick(self):
        """ test updating quick match of a floating rule """
        obj = dict(name='test_rule_floating', source='any', destination='any', interface='wan', floating='yes', direction='any', protocol='tcp', quick='yes')
        command = "update rule 'test_rule_floating' on 'floating(wan)' set quick=True"
        self.do_module_test(obj, command=command)

    def test_rule_update_floating_remove_quick(self):
        """ test updating quick match of a floating rule """
        obj = dict(name='test_rule_floating_quick', source='any', destination='any', interface='wan', floating='yes', direction='any', protocol='tcp')
        command = "update rule 'test_rule_floating_quick' on 'floating(wan)' set quick=False"
        self.do_module_test(obj, command=command)

    def test_rule_update_floating_yes(self):
        """ test updating floating of a rule to yes
            Since you can't change the floating mode of a rule, it should create a new rule
        """
        obj = dict(name='test_rule', source='any', destination='any', interface='wan', floating='yes', direction='any', protocol='tcp')
        command = "create rule 'test_rule' on 'floating(wan)', source='any', destination='any', protocol='tcp', direction='any'"
        self.do_module_test(obj, command=command)

        other_rule = dict(name='test_rule', source='any', destination='any', interface='wan', floating='no', protocol='tcp')
        other_rule_elt = self.get_target_elt(other_rule)
        self.check_target_elt(other_rule, other_rule_elt)

    def test_rule_update_floating_no(self):
        """ test updating floating of a rule to no
            Since you can't change the floating mode of a rule, it should create a new rule
        """
        obj = dict(name='test_rule_floating', source='any', destination='any', interface='wan', floating='no', direction='any', protocol='tcp')
        command = "create rule 'test_rule_floating' on 'wan', source='any', destination='any', protocol='tcp', direction='any'"
        self.do_module_test(obj, command=command)

        other_rule = dict(name='test_rule_floating', source='any', destination='any', interface='wan', floating='yes', direction='any', protocol='tcp')
        other_rule_elt = self.get_target_elt(other_rule)
        self.check_target_elt(other_rule, other_rule_elt)

    def test_rule_update_floating_default(self):
        """ test updating floating of a rule to default (no)
            Since you can't change the floating mode of a rule, it should create a new rule
        """
        obj = dict(name='test_rule_floating', source='any', destination='any', interface='wan', protocol='tcp')
        command = "create rule 'test_rule_floating' on 'wan', source='any', destination='any', protocol='tcp'"
        self.do_module_test(obj, command=command)

        other_rule = dict(name='test_rule_floating', source='any', destination='any', interface='wan', floating='yes', direction='any', protocol='tcp')
        other_rule_elt = self.get_target_elt(other_rule)
        self.check_target_elt(other_rule, other_rule_elt)

    def test_rule_update_inet(self):
        """ test updating ippprotocol of a rule to ipv4 and ipv6 """
        obj = dict(name='test_rule', source='any', destination='any', interface='wan', ipprotocol='inet46', protocol='tcp')
        command = "update rule 'test_rule' on 'wan' set ipprotocol='inet46'"
        self.do_module_test(obj, command=command)

    def test_rule_update_protocol_udp(self):
        """ test updating protocol of a rule to udp """
        obj = dict(name='test_rule', source='any', destination='any', interface='wan', protocol='udp')
        command = "update rule 'test_rule' on 'wan' set protocol='udp'"
        self.do_module_test(obj, command=command)

    def test_rule_update_protocol_any(self):
        """ test updating protocol of a rule to udp """
        obj = dict(name='r2', source='any', destination='any', interface='vt1', protocol='any')
        command = "update rule 'r2' on 'vt1' set protocol='any'"
        self.do_module_test(obj, command=command)

    def test_rule_update_protocol_tcp_udp(self):
        """ test updating protocol of a rule to tcp/udp """
        obj = dict(name='test_rule', source='any', destination='any', interface='wan', protocol='tcp/udp')
        command = "update rule 'test_rule' on 'wan' set protocol='tcp/udp'"
        self.do_module_test(obj, command=command)

    def test_rule_update_log_yes(self):
        """ test updating log of a rule to yes """
        obj = dict(name='test_rule', source='any', destination='any', interface='wan', log='yes', protocol='tcp')
        command = "update rule 'test_rule' on 'wan' set log=True"
        self.do_module_test(obj, command=command)

    def test_rule_update_log_no(self):
        """ test updating log of a rule to no """
        obj = dict(name='test_rule_2', source='any', destination='any', interface='wan', log='no', protocol='tcp')
        command = "update rule 'test_rule_2' on 'wan' set log=False"
        self.do_module_test(obj, command=command)

    def test_rule_update_tcpflags_any_yes(self):
        """ test updating log of a rule to yes """
        obj = dict(name='test_rule', source='any', destination='any', interface='wan', protocol='tcp', tcpflags_any='yes')
        command = "update rule 'test_rule' on 'wan' set tcpflags_any=True"
        self.do_module_test(obj, command=command)

    def test_rule_update_tcpflags_any_no(self):
        """ test updating log of a rule to no """
        obj = dict(name='test_rule_4', source='any', destination='any', interface='lan_100', tcpflags_any='no')
        command = "update rule 'test_rule_4' on 'lan_100' set tcpflags_any=False"
        self.do_module_test(obj, command=command)

    def test_rule_update_log_default(self):
        """ test updating log of a rule to default """
        obj = dict(name='test_rule_2', source='any', destination='any', interface='wan', protocol='tcp')
        command = "update rule 'test_rule_2' on 'wan' set log=False"
        self.do_module_test(obj, command=command)

    def test_rule_update_negate_add_source(self):
        """ test updating source of a rule with a not """
        obj = dict(name='test_rule_2', source='!srv_admin', destination='any', interface='wan', protocol='tcp', log=True)
        command = "update rule 'test_rule_2' on 'wan' set source='!srv_admin'"
        self.do_module_test(obj, command=command)

    def test_rule_update_negate_add_destination(self):
        """ test updating destination of a rule with a not """
        obj = dict(name='test_rule_2', source='any', destination='!srv_admin', interface='wan', protocol='tcp', log=True)
        command = "update rule 'test_rule_2' on 'wan' set destination='!srv_admin'"
        self.do_module_test(obj, command=command)

    def test_rule_update_negate_remove_source(self):
        """ test updating source of a rule remove the not """
        obj = dict(name='not_rule_src', source='srv_admin', destination='any:port_ssh', interface='lan', protocol='tcp')
        command = "update rule 'not_rule_src' on 'lan' set source='srv_admin'"
        self.do_module_test(obj, command=command)

    def test_rule_update_negate_remove_destination(self):
        """ test updating destination of a rule remove the not """
        obj = dict(name='not_rule_dst', source='any', destination='srv_admin:port_ssh', interface='lan', protocol='tcp')
        command = "update rule 'not_rule_dst' on 'lan' set destination='srv_admin'"
        self.do_module_test(obj, command=command)

    def test_rule_update_before(self):
        """ test updating position of a rule to before another """
        obj = dict(name='test_rule_3', source='any', destination='any:port_http', interface='wan', protocol='tcp', before='test_rule')
        command = "update rule 'test_rule_3' on 'wan' set before='test_rule'"
        self.do_module_test(obj, command=command)
        self.check_rule_idx(obj, 0)

    def test_rule_update_before_bottom(self):
        """ test updating position of a rule to bottom """
        obj = dict(name='test_rule_3', source='any', destination='any:port_http', interface='wan', protocol='tcp', before='bottom')
        command = "update rule 'test_rule_3' on 'wan' set before='bottom'"
        self.do_module_test(obj, command=command)
        self.check_rule_idx(obj, 3)

    def test_rule_update_after(self):
        """ test updating position of a rule to after another rule """
        obj = dict(name='test_rule_3', source='any', destination='any:port_http', interface='wan', protocol='tcp', after='antilock_out_3')
        command = "update rule 'test_rule_3' on 'wan' set after='antilock_out_3'"
        self.do_module_test(obj, command=command)
        self.check_rule_idx(obj, 3)

    def test_rule_update_after_self(self):
        """ test updating position of a rule to after same rule """
        obj = dict(name='test_rule_3', source='any', destination='any', interface='wan', protocol='tcp', after='test_rule_3')
        msg = 'Cannot specify the current rule in after'
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_update_before_self(self):
        """ test updating position of a rule to before same rule """
        obj = dict(name='test_rule_3', source='any', destination='any', interface='wan', protocol='tcp', before='test_rule_3')
        msg = 'Cannot specify the current rule in before'
        self.do_module_test(obj, failed=True, msg=msg)

    def test_rule_update_after_top(self):
        """ test updating position of a rule to top """
        obj = dict(name='test_rule_3', source='any', destination='any:port_http', interface='wan', protocol='tcp', after='top')
        command = "update rule 'test_rule_3' on 'wan' set after='top'"
        self.do_module_test(obj, command=command)
        self.check_rule_idx(obj, 0)

    def test_rule_update_separator_top(self):
        """ test updating position of a rule to top """
        obj = dict(name='r2', source='any', destination='any', interface='vt1', protocol='tcp', after='top')
        command = "update rule 'r2' on 'vt1' set after='top'"
        self.do_module_test(obj, command=command)
        self.check_rule_idx(obj, 0)
        self.check_separator_idx(obj['interface'], 'test_sep1', 1)
        self.check_separator_idx(obj['interface'], 'test_sep2', 3)

    def test_rule_update_separator_bottom(self):
        """ test updating position of a rule to bottom """
        obj = dict(name='r1', source='any', destination='any', interface='vt1', protocol='tcp', before='bottom')
        command = "update rule 'r1' on 'vt1' set before='bottom'"
        self.do_module_test(obj, command=command)
        self.check_rule_idx(obj, 2)
        self.check_separator_idx(obj['interface'], 'test_sep1', 0)
        self.check_separator_idx(obj['interface'], 'test_sep2', 2)

    def test_rule_update_separator_before_first(self):
        """ test creation of a new rule at bottom """
        obj = dict(name='r3', source='any', destination='any', interface='vt1', protocol='tcp', before='r1')
        command = "update rule 'r3' on 'vt1' set before='r1'"
        self.do_module_test(obj, command=command)
        self.check_rule_idx(obj, 0)
        self.check_separator_idx(obj['interface'], 'test_sep1', 0)
        self.check_separator_idx(obj['interface'], 'test_sep2', 3)

    def test_rule_update_separator_after_third(self):
        """ test creation of a new rule at bottom """
        obj = dict(name='r1', source='any', destination='any', interface='vt1', protocol='tcp', after='r3')
        command = "update rule 'r1' on 'vt1' set after='r3'"
        self.do_module_test(obj, command=command)
        self.check_rule_idx(obj, 2)
        self.check_separator_idx(obj['interface'], 'test_sep1', 0)
        self.check_separator_idx(obj['interface'], 'test_sep2', 3)

    def test_rule_update_queue_set(self):
        """ test updating queue of a rule """
        obj = dict(name='test_rule', source='any', destination='any', interface='wan', queue='one_queue', protocol='tcp')
        command = "update rule 'test_rule' on 'wan' set queue='one_queue'"
        self.do_module_test(obj, command=command)

    def test_rule_update_queue_set_ack(self):
        """ test updating queue and ackqueue of a rule """
        obj = dict(name='test_rule', source='any', destination='any', interface='wan', queue='one_queue', ackqueue='another_queue', protocol='tcp')
        command = "update rule 'test_rule' on 'wan' set queue='one_queue', ackqueue='another_queue'"
        self.do_module_test(obj, command=command)

    def test_rule_update_queue_unset_ack(self):
        """ test updating ackqueue of a rule """
        obj = dict(name='test_lan_100_2', source='any', destination='any', interface='lan_100', queue='one_queue', protocol='tcp')
        command = "update rule 'test_lan_100_2' on 'lan_100' set ackqueue=none"
        self.do_module_test(obj, command=command)

    def test_rule_update_queue_unset(self):
        """ test updating queue of a rule """
        obj = dict(name='test_lan_100_3', source='any', destination='any', interface='lan_100', protocol='tcp')
        command = "update rule 'test_lan_100_3' on 'lan_100' set queue=none"
        self.do_module_test(obj, command=command)

    def test_rule_update_limiter_set(self):
        """ test updating limiter of a rule """
        obj = dict(name='test_rule', source='any', destination='any', interface='wan', in_queue='one_limiter', protocol='tcp')
        command = "update rule 'test_rule' on 'wan' set in_queue='one_limiter'"
        self.do_module_test(obj, command=command)

    def test_rule_update_limiter_set_out(self):
        """ test updating limiter in and out of a rule """
        obj = dict(name='test_rule', source='any', destination='any', interface='wan', in_queue='one_limiter', out_queue='another_limiter', protocol='tcp')
        command = "update rule 'test_rule' on 'wan' set in_queue='one_limiter', out_queue='another_limiter'"
        self.do_module_test(obj, command=command)

    def test_rule_update_limiter_unset_out(self):
        """ test updating limiter out of a rule """
        obj = dict(name='test_lan_100_4', source='any', destination='any', interface='lan_100', in_queue='one_limiter', protocol='tcp')
        command = "update rule 'test_lan_100_4' on 'lan_100' set out_queue=none"
        self.do_module_test(obj, command=command)

    def test_rule_update_limiter_unset(self):
        """ test updating limiter of a rule """
        obj = dict(name='test_lan_100_5', source='any', destination='any', interface='lan_100', protocol='tcp')
        command = "update rule 'test_lan_100_5' on 'lan_100' set in_queue=none"
        self.do_module_test(obj, command=command)

    def test_rule_update_gateway_set(self):
        """ test updating gateway of a rule """
        obj = dict(name='test_rule_3', source='any', destination='any:port_http', interface='wan', protocol='tcp', gateway='GW_WAN')
        command = "update rule 'test_rule_3' on 'wan' set gateway='GW_WAN'"
        self.do_module_test(obj, command=command)

    def test_rule_update_gateway_unset(self):
        """ test updating gateway of a rule """
        obj = dict(name='antilock_out_1', source='any', destination='any:port_ssh', interface='lan', protocol='tcp', log=True)
        command = "update rule 'antilock_out_1' on 'lan' set gateway=none"
        self.do_module_test(obj, command=command)

    def test_rule_update_tracker(self):
        """ test updating tracker of a rule """
        obj = dict(name='test_lan_100_5', source='any', destination='any', interface='lan_100', in_queue='one_limiter', protocol='tcp', tracker='1234')
        command = "update rule 'test_lan_100_5' on 'lan_100' set tracker='1234'"
        self.do_module_test(obj, command=command)

    def test_rule_update_icmp(self):
        """ test updating ipprotocol to icmptype """
        obj = dict(name='r1', source='any', destination='any', interface='vt1', protocol='icmp', icmptype='echorep,echoreq')
        command = "update rule 'r1' on 'vt1' set protocol='icmp', icmptype='echorep,echoreq'"
        self.do_module_test(obj, command=command)

    def test_rule_update_port_old_syntax(self):
        """ test updating gateway of a rule """
        obj = dict(name='test_rule_3', source='any', destination='any:port_ssh', interface='wan', protocol='tcp')
        command = "update rule 'test_rule_3' on 'wan' set destination_port='port_ssh'"
        self.do_module_test(obj, command=command)

    def test_rule_update_port_new_syntax(self):
        """ test updating gateway of a rule """
        obj = dict(name='test_rule_3', source='any', destination='any', destination_port='port_ssh', interface='wan', protocol='tcp')
        command = "update rule 'test_rule_3' on 'wan' set destination_port='port_ssh'"
        self.do_module_test(obj, command=command)

    def test_rule_update_schedule(self):
        """ test updating scheduling of a rule """
        obj = dict(name='test_rule', source='any', destination='any', interface='wan', action='pass', protocol='tcp', sched='workdays')
        command = "update rule 'test_rule' on 'wan' set sched='workdays'"
        self.do_module_test(obj, command=command)

    def test_rule_update_remove_schedule(self):
        """ test updating scheduling of a rule """
        obj = dict(name='test_rule_sched', source='any', destination='any', interface='lan_100', action='pass', protocol='tcp')
        command = "update rule 'test_rule_sched' on 'lan_100' set sched=none"
        self.do_module_test(obj, command=command)
