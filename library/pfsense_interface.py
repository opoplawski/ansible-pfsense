#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Orion Poplawski <orion@nwra.com>, Benjamin Boukhers <madgicsmail@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_interface
short_description: Manage pfSense interfaces
description:
  >
    Manage pfSense interfaces
author: Benjamin Boukhers (@madgics)
notes:
options:
  if:
    description: The system interface
    required: true
    default: null
  ipaddr:
    description: The interface IP address
    required: true
    default: null
  enable:
    description: Enable the interface or not
    required: false
    default: yes
    choices: [ "yes", "no" ]
  descr:
    description: The interface description
    required: true
    default: false
  subnet:
    description: The interface subnet mask
    required: true
    default: null
  gateway:
    description: The interface gateway IP
    required: false
    default: null
  state:
    description: Add or delete the interface
    required: true
    default: present
    choices: [ "present", "absent" ]
"""

EXAMPLES = """
- name: "Add NAT interface"
    pfsense_interface:
      if: 'vmx1'
      ipaddr: '192.168.1.1'
      descr: 'NAT'
      subnet: '24'
      state: present

- name: "Del NAT interface"
    pfsense_interface:
      if: 'vmx1'
      ipaddr: '192.168.1.1'
      descr: 'NAT'
      subnet: '24'
      state: absent
"""

from ansible.module_utils.pfsense.pfsense import pfSenseModule
from subprocess import call

class pfSenseInterface(object):
    def __init__(self, module):
        self.module = module
        self.pfsense = pfSenseModule(module)
        self.interfaces = self.pfsense.get_element('interfaces')

    # determines if system interface exist on pfsense
    # TODO improve this with module or sockets ?
    def _is_interface_exist_on_system(self, name):
        rcode = call("ifconfig |grep '^"+name+"' 1>/dev/null 2>&1", shell=True)
        if rcode == 0:
            return True
        else:
            return False

    # get system interface with indice according to xml conf
    def _get_interface_elem_with_indice(self, name):
        found = None
        i = 0
        for interface in self.interfaces:
            i+=1
            interfaceEl = interface.find('if').text
            if interfaceEl.strip() == name:
                found = interface
                break
        return (found, i)

    # get the new interface name <optx>
    def _get_new_interface_pfsense(self):
        for interface in self.interfaces:
            interfaceEl = interface.tag
        if interfaceEl == "lan" or interfaceEl == "wan":
            intnew = "opt1"
        else:
            intnew = "opt"+str(int(interfaceEl[-1])+1)
        return intnew

    # set ip address on system interface
    # TODO improve this with module or sockets ?
    def set_system_ip(self, interface, ip, mask):
        broadcast = self.pfsense.get_broadcast_addr(ip, mask)
        netmask = self.pfsense.get_cidr_netmask(ip, mask)
        rcode = call("ifconfig %s %s netmask %s broadcast %s 2>/dev/null" % (interface, ip, netmask, broadcast), shell=True)
        if rcode != 0:
            self.module.fail_json(msg='Interface %s: IP configuration failed!' % (interface))

    # unset ip adress on system interface
    # TODO improve this with module or sockets ?
    def unset_system_ip(self, interface, ip):
        rcode = call("ifconfig %s delete %s" % (interface, ip), shell=True)
        if rcode != 0:
            self.module.fail_json(msg='Interface %s: unset IP failed!' % (interface))

    # Check if networks infos are valid
    def check_infos(self, ip, mask, gateway):
        if not self.pfsense.is_ip(ip):
            self.module.fail_json(msg='Cannot parse address %s, not IP' % (ip))
        if not 0 < int(mask) < 33:
            self.module.fail_json(msg='Subnet mask %s not valid, please set a value between 1 and 32' % (mask))
        if gateway is not None:
            if not self.pfsense.is_ip(gateway):
                self.module.fail_json(msg='Cannot parse address %s, not IP' % (gateway))

    def add(self, interface):
        interfaceEl, i = self._get_interface_elem_with_indice(interface['if'])
        changed = False
        stdout = ''
        stderr = ''
        if not self._is_interface_exist_on_system(interface['if']):
            self.module.fail_json(msg="Interface %s not found on pfsense" % (interface['if']))
        elif interfaceEl is None:
            changed = True
            if self.module.check_mode:
                self.module.exit_json(changed=True)
            interfaceEl = self.pfsense.new_element(self._get_new_interface_pfsense())
            self.pfsense.copy_dict_to_element(interface, interfaceEl)
            self.interfaces.insert(i+1, interfaceEl)
            self.pfsense.write_config(descr='ansible pfsense_interface added %s' % (interface['if']))
        else:
            changed = self.pfsense.copy_dict_to_element(interface, interfaceEl)
            if self.module.check_mode:
                self.module.exit_json(changed=changed)
            if changed:
                self.pfsense.write_config(descr='ansible pfsense_interface updated "%s"' % (interface['if']))
        self.module.exit_json(stdout=stdout, stderr=stderr, changed=changed)

    def remove(self, interface):
        interfaceEl, i = self._get_interface_elem_with_indice(interface['if'])
        changed = False
        stdout = ''
        stderr = ''
        if interfaceEl is not None:
            if interfaceEl.tag == "lan" or interfaceEl.tag == "wan":
                interfaceEl = None
            if self.module.check_mode:
                self.module.exit_json(changed=True)
            self.interfaces.remove(interfaceEl)
            changed = True
            self.pfsense.write_config(descr='ansible pfsense_interface removed "%s"' % (interface['if']))
        self.module.exit_json(stdout=stdout, stderr=stderr, changed=changed)

def main():
    module = AnsibleModule(
    argument_spec={
        'if': {'required': True, 'type': 'str'},
        'state': {
            'required': True,
            'choices': ['present', 'absent']
        },
        'enable': {
            'required': False,
            'default': 'yes',
            'choices': ['yes', 'no']
        },
        'descr': {'required': True, 'type': 'str'},
        'ipaddr': {'required': True, 'type': 'str'},
        'subnet': {'required': True, 'type': 'str'},
        'gateway': {'required': False, 'type': 'str'},
    },
    supports_check_mode=True)

    pfinterface = pfSenseInterface(module)

    interface = dict()
    state = module.params['state']
    interface['if'] = module.params['if']
    interface['ipaddr'] = module.params['ipaddr']
    if module.params['enable'] == 'yes':
        interface['enable'] = ''
    interface['descr'] = module.params['descr']
    interface['subnet'] = module.params['subnet']
    interface['gateway'] = module.params['gateway']
    interface['spoofmac'] = ''
    if state == 'absent':
        pfinterface.check_infos(interface['ipaddr'], interface['subnet'], interface['gateway'])
        pfinterface.unset_system_ip(interface['if'], interface['ipaddr'])
        pfinterface.remove(interface)
    if state == 'present':
        pfinterface.check_infos(interface['ipaddr'], interface['subnet'], interface['gateway'])
        pfinterface.set_system_ip(interface['if'], interface['ipaddr'], interface['subnet'])
        pfinterface.add(interface)

# import module snippets
from ansible.module_utils.basic import AnsibleModule

main()
