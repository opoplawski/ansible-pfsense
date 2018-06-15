#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_ca
short_description: Manage pfSense Certificate Authorities
description:
  >
    Manage pfSense LDAP Certificate Authorities
author: Orion Poplawski (@opoplawski)
notes:
options:
  name:
    description: The name of the Certificate Authority
    required: true
  state:
    description: State in which to leave the Certificate Authority
    required: true
    choices: [ "present", "absent" ]
  certificate:
    description: The certificate for the Certificate Authority
    required: true
"""

EXAMPLES = """
- name: Add AD Certificate Authority
  pfsense_ca:
    name: AD CA
    certificate: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlGcXpDQ0E1T2dBd0lCQWdJUVBreXdY
dWRkZnFOR2h2aWExVDVYZ3pBTkJna3Foa2lHOXcwQkFRMEZBREJjDQpNUk13RVFZS0NaSW1pWlB5TEdRQkdSWURZMjl0T
VJRd0VnWUtDWkltaVpQeUxHUUJHUllFYm5keVlURVNNQkFHDQpDZ21TSm9tVDhpeGtBUmtXQW1Ga01Sc3dHUVlEVlFRRE
V4SmhaQzFCUkMxVFJVRlVWRXhGTURFdFEwRXdIaGNODQpNVFl3TkRBM01UWTBOVEE0V2hjTk1qWXdOREEzTVRZMU5UQTN
XakJjTVJNd0VRWUtDWkltaVpQeUxHUUJHUllEDQpZMjl0TVJRd0VnWUtDWkltaVpQeUxHUUJHUllFYm5keVlURVNNQkFH
Q2dtU0pvbVQ4aXhrQVJrV0FtRmtNUnN3DQpHUVlEVlFRREV4SmhaQzFCUkMxVFJVRlVWRXhGTURFdFEwRXdnZ0lpTUEwR
0NTcUdTSWIzRFFFQkFRVUFBNElDDQpEd0F3Z2dJS0FvSUNBUUNWdGM0dzBnY0h5aFkzRkVpUENVMmZLYXAyWnFHb0ROL1
VuRkVRRVBqZ1R4NmE4UEF5DQpqWjRMS2o2N1AybkRLTFA0ZVFQSFFzQmRkTVNneVl1RzdCQTlycmNCaFIzY0VlZ1RmNm9
CSjdKUG1zZTJTS3dtDQp6QnhT....
    state: present

- name: Remove AD Certificate Authority
  pfsense_ca:
    name: AD CA
    state: absent
"""

from ansible.module_utils.pfsense.pfsense import pfSenseModule

class pfSenseCA(object):

    def __init__(self, module):
        self.module = module
        self.pfsense = pfSenseModule(module)
        self.cas = self.pfsense.get_elements('ca')

    def _find_ca(self, name):
        found = None
        i = 0
        for ca in self.cas:
            i = self.pfsense.get_index(ca)
            if ca.find('descr').text == name:
                found = ca
                break
        return (found, i)

    def add(self, ca):
        caEl, i = self._find_ca(ca['descr'])
        changed = False
        rc = 0
        stdout = ''
        stderr = ''
        if caEl is None:
            changed = True
            if self.module.check_mode:
                self.module.exit_json(changed=True)
            caEl = self.pfsense.new_element('ca')
            ca['refid'] = self.pfsense.uniqid()
            self.pfsense.copy_dict_to_element(ca, caEl)
            self.pfsense.root.insert(i+1, caEl)
            self.pfsense.write_config(descr='ansible pfsense_ca added %s' % (ca['descr']))
        else:
            changed = self.pfsense.copy_dict_to_element(ca, caEl)
            if self.module.check_mode:
                self.module.exit_json(changed=changed)
            if changed:
                self.pfsense.write_config(descr='ansible pfsense_ca updated "%s"' % (ca['descr']))
        self.module.exit_json(stdout=stdout, stderr=stderr, changed=changed)

    def remove(self, ca):
        caEl, i = self._find_ca(ca['descr'])
        changed = False
        rc = 0
        stdout = ''
        stderr = ''
        if caEl is not None:
            if self.module.check_mode:
                self.module.exit_json(changed=True)
            self.cas.remove(caEl)
            changed = True
            self.pfsense.write_config(descr='ansible pfsense_ca removed "%s"' % (ca['descr']))
        self.module.exit_json(stdout=stdout, stderr=stderr, changed=changed)


def main():
    module = AnsibleModule(
        argument_spec={
            'name': {'required': True, 'type': 'str'},
            'state': {
                'required': True,
                'choices': ['present', 'absent']
            },
            'certificate': {'required': True, 'type': 'str'},
        },
        supports_check_mode=True)

    pfca = pfSenseCA(module)

    ca = dict()
    ca['descr'] = module.params['name']
    state = module.params['state']
    if state == 'absent':
        pfca.remove(ca)
    elif state == 'present':
        ca['crt'] = module.params['certificate']
        pfca.add(ca)


# import module snippets
from ansible.module_utils.basic import AnsibleModule

main()
