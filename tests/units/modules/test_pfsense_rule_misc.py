# Copyright: (c) 2018, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from units.modules.utils import set_module_args
from .test_pfsense_rule import TestPFSenseRuleModule


class TestPFSenseRuleMiscModule(TestPFSenseRuleModule):

    ##############
    # delete
    #
    def test_rule_delete(self):
        """ test deleting a rule """
        obj = dict(name='test_rule_3', source='any', destination='any', interface='wan', protocol='tcp')
        command = "delete rule 'test_rule_3' on 'wan'"
        self.do_module_test(obj, command=command, delete=True)

    ##############
    # misc
    #
    def test_check_mode(self):
        """ test check mode """
        obj = dict(name='one_rule', source='any', destination='any', interface='lan')
        set_module_args(self.args_from_var(obj, _ansible_check_mode=True))
        self.execute_module(changed=True)
        self.assertFalse(self.load_xml_result())
