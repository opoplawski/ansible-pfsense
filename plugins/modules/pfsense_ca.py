#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018-2020, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_ca
version_added: 0.1.0
short_description: Manage pfSense Certificate Authorities
description:
  >
    Manage pfSense Certificate Authorities
author: Orion Poplawski (@opoplawski)
notes:
options:
  name:
    description: The name of the Certificate Authority
    required: true
    type: str
  state:
    description: State in which to leave the Certificate Authority
    default: present
    choices: [ "present", "absent" ]
    type: str
  certificate:
    description:
      >
        The certificate for the Certificate Authority.  This can be in PEM form or Base64
        encoded PEM as a single string (which is how pfSense stores it).
    type: str
  crl:
    description:
      >
        The Certificate Revocation List for the Certificate Authority.  This can be in PEM
        form or Base64 encoded PEM as a single string (which is how pfSense stores it).
    required: false
    type: str
"""

EXAMPLES = """
- name: Add AD Certificate Authority
  pfsense_ca:
    name: AD CA
    certificate: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlGcXpDQ0E1T2dB...
    crl: |
      -----BEGIN X509 CRL-----
      MIICazCCAVMCAQEwDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAxMPTldSQSBPcGVu
      ...
      r0hUUy3w1trKtymlyhmd5XmYzINYp8p/Ws+boST+Fcw3chWTep/J8nKMeKESO0w=
      -----END X509 CRL-----
    state: present

- name: Remove AD Certificate Authority
  pfsense_ca:
    name: AD CA
    state: absent
"""

RETURN = """

"""

import base64
import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase


class PFSenseCAModule(PFSenseModuleBase):
    """ module managing pfsense certificate authorities """

    def __init__(self, module, pfsense=None):
        super(PFSenseCAModule, self).__init__(module, pfsense)
        self.name = "pfsense_ca"
        self.root_elt = self.pfsense.root
        self.cas = self.pfsense.get_elements('ca')
        self.refresh_crls = False

    ##############################
    # params processing
    #
    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        if params['state'] == 'absent':
            return

        # TODO - Make sure certificate purpose includes CA
        cert = params['certificate']
        lines = cert.splitlines()
        if lines[0] == '-----BEGIN CERTIFICATE-----' and lines[-1] == '-----END CERTIFICATE-----':
            params['certificate'] = base64.b64encode(cert.encode()).decode()
        elif not re.match('LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t', cert):
            self.module.fail_json(msg='Could not recognize certificate format: %s' % (cert))

        if params['crl'] is not None:
            crl = params['crl']
            lines = crl.splitlines()
            if lines[0] == '-----BEGIN X509 CRL-----' and lines[-1] == '-----END X509 CRL-----':
                params['crl'] = base64.b64encode(crl.encode()).decode()
            elif not re.match('LS0tLS1CRUdJTiBYNTA5IENSTC0tLS0t', crl):
                self.module.fail_json(msg='Could not recognize CRL format: %s' % (crl))

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()
        self.obj = obj

        obj['descr'] = params['name']
        if params['state'] == 'present':
            if 'certificate' in params and params['certificate'] is not None:
                obj['crt'] = params['certificate']
            if 'crl' in params and params['crl'] is not None:
                obj['crl'] = params['crl']

        return obj

    ##############################
    # XML processing
    #
    def _find_target(self):
        result = self.root_elt.findall("ca[descr='{0}']".format(self.obj['descr']))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple certificate authorities for name {0}.'.format(self.obj['descr']))
        else:
            return None

    def _find_this_ca_index(self):
        return self.cas.index(self.target_elt)

    def _find_last_ca_index(self):
        if len(self.cas):
            return list(self.root_elt).index(self.cas[len(self.cas) - 1])
        else:
            return len(list(self.root_elt))

    def _find_crl(self, caref):
        result = self.root_elt.findall("crl[caref='{0}']".format(caref))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple CRLs for caref {0}.'.format(caref))
        else:
            return None

    def _create_target(self):
        """ create the XML target_elt """
        return self.pfsense.new_element('ca')

    def _copy_and_add_target(self):
        """ populate the XML target_elt """
        obj = self.obj
        crl = {}
        if 'crl' in obj:
            crl['method'] = 'existing'
            crl['text'] = obj.pop('crl')

        obj['refid'] = self.pfsense.uniqid()
        self.pfsense.copy_dict_to_element(obj, self.target_elt)
        self.diff['after'] = self.pfsense.element_to_dict(self.target_elt)
        self.root_elt.insert(self._find_last_ca_index(), self.target_elt)
        if 'text' in crl:
            crl_elt = self.pfsense.new_element('crl')
            crl['refid'] = self.pfsense.uniqid()
            crl['descr'] = obj['descr'] + ' CRL'
            crl['caref'] = obj['refid']
            self.pfsense.copy_dict_to_element(crl, crl_elt)
            self.diff['after']['crl'] = crl['text']
            self.pfsense.root.append(crl_elt)
            self.refresh_crls = True

    def _copy_and_update_target(self):
        """ update the XML target_elt """
        obj = self.obj
        before = self.pfsense.element_to_dict(self.target_elt)
        self.diff['before'] = before

        crl = {}
        if 'crl' in obj:
            crl['method'] = 'existing'
            crl['text'] = obj.pop('crl')

        changed = self.pfsense.copy_dict_to_element(obj, self.target_elt)
        self.diff['after'] = self.pfsense.element_to_dict(self.target_elt)

        if 'text' in crl:
            crl_elt = self._find_crl(self.target_elt.find('refid').text)
            if crl_elt is None:
                changed = True
                crl_elt = self.pfsense.new_element('crl')
                crl['refid'] = self.pfsense.uniqid()
                crl['descr'] = obj['descr'] + ' CRL'
                crl['caref'] = self.target_elt.find('refid').text
                self.pfsense.copy_dict_to_element(crl, crl_elt)
                # Add after the existing ca entry
                self.pfsense.root.insert(self._find_this_ca_index() + 1, crl_elt)
                self.refresh_crls = True
            else:
                before['crl'] = crl_elt.find('text').text
                if self.pfsense.copy_dict_to_element(crl, crl_elt):
                    changed = True
                    self.refresh_crls = True
            self.diff['after']['crl'] = crl['text']

        return (before, changed)

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return self.obj['descr']

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        return values

    ##############################
    # run
    #
    def _update(self):
        if self.params['state'] == 'present':
            # ca_import will base64 encode the cert + key  and will fix 'caref' for CAs that reference each other
            # $ca needs to be an existing reference (particularly 'refid' must be set) before calling ca_import
            # key and serial are optional arguments.  TODO - handle key and serial
            (dummy, stdout, stderr) = self.pfsense.phpshell("""
                init_config_arr(array('ca'));
                $ca =& lookup_ca('{refid}');
                ca_import($ca, '{cert}');
                print_r($ca);
                print_r($config['ca']);
                write_config('Update CA reference');""".format(refid=self.target_elt.find('refid').text,
                                                               cert=base64.b64decode(self.target_elt.find('crt').text.encode()).decode()))

            crl_stdout = ''
            crl_stderr = ''
            if self.refresh_crls:
                (dummy, crl_stdout, crl_stderr) = self.pfsense.phpshell("""
                    require_once("openvpn.inc");
                    openvpn_refresh_crls();
                    require_once("vpn.inc");
                    vpn_ipsec_configure();""")
                return (dummy, stdout + crl_stdout, stderr + crl_stderr)

            return (dummy, stdout + crl_stdout, stderr + crl_stderr)
        else:
            return (None, '', '')

    def _pre_remove_target_elt(self):
        self.diff['after'] = {}
        if self.target_elt is not None:
            self.diff['before'] = self.pfsense.element_to_dict(self.target_elt)
            crl_elt = self._find_crl(self.target_elt.find('refid').text)
            self.cas.remove(self.target_elt)
            if crl_elt is not None:
                self.diff['before']['crl'] = crl_elt.find('text').text
                self.root_elt.remove(crl_elt)
        else:
            self.diff['before'] = {}


def main():
    module = AnsibleModule(
        argument_spec={
            'name': {'required': True, 'type': 'str'},
            'state': {
                'type': 'str',
                'default': 'present',
                'choices': ['present', 'absent']
            },
            'certificate': {'type': 'str'},
            'crl': {'default': None, 'type': 'str'},
        },
        required_if=[
            ["state", "present", ["certificate"]],
        ],
        supports_check_mode=True)

    pfmodule = PFSenseCAModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
