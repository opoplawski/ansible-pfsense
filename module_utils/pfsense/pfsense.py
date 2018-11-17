# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import ipaddress
import shutil
import os
import pwd
import time
import xml.etree.ElementTree as ET

class pfSenseModule(object):

    def __init__(self, module):
        self.module = module
        # set config file
        self.config = '/cf/conf/config.xml'
        self.tree = ET.parse(self.config)
        self.root = self.tree.getroot()
        self.aliases = self.get_element('aliases')
        self.interfaces = self.get_element('interfaces')
        self.debug = open('/tmp/pfsense.debug','w')
        # add descr on lan and wan interfaces if no descr
        if not self.is_interface_descr('lan'):
            self.add_interface_descr('lan', 'LAN')
        if not self.is_interface_descr('wan'):
            self.add_interface_descr('wan', 'WAN')

    def get_element(self, node):
        return self.root.find(node)

    def get_elements(self, node):
        return self.root.findall(node)

    def get_index(self, el):
        return list(self.root).index(el)

    def new_element(self, tag):
        el = ET.Element(tag)
        # Attempt to preserve some of the formatting of pfSense's config.xml
        el.text = '\n\t\t\t'
        el.tail = '\n\t\t'
        return el

    def copy_dict_to_element(self, d, topEl, sub=0):
        changed = False
        for (key, value) in d.items():
            self.debug.write('changed=%s key=%s value=%s\n' % (changed, key, value))
            thisEl = topEl.find(key)
            if thisEl is None:
                changed = True
                if isinstance(value,dict):
                    self.debug.write('calling copy_dict_to_element()\n')
                    # Create a new element
                    newEl = ET.Element(key)
                    newEl.text = '\n%s' % ('\t' * (sub + 4))
                    newEl.tail = '\n%s' % ('\t' * (sub + 3))
                    self.copy_dict_to_element(value, newEl, sub=sub+1)
                    topEl.append(newEl)
                elif isinstance(value,list):
                    for item in value:
                        newEl = self.new_element(key)
                        newEl.text = item
                        topEl.append(newEl)
                else:
                    # Create a new element
                    newEl = ET.Element(key)
                    newEl.text = value
                    newEl.tail = '\n%s' % ('\t' * (sub + 3))
                    topEl.append(newEl)
                self.debug.write('changed=%s added key=%s value=%s tag=%s\n' % (changed, key, value, topEl.tag))
            else:
                if isinstance(value,dict):
                    self.debug.write('calling copy_dict_to_element()\n')
                    subchanged = self.copy_dict_to_element(value, thisEl, sub=sub+1)
                    if subchanged:
                        changed = True
                elif isinstance(value,list):
                    thisList = value
                    # Remove existing items not in the new list
                    for listEl in topEl.findall(key):
                        if listEl.text in thisList:
                            thisList.remove(listEl.text)
                        else:
                            topEl.remove(listEl)
                            changed = True
                    # Add any remaining items in the new list
                    for item in thisList:
                        newEl = self.new_element(key)
                        newEl.text = item
                        topEl.append(newEl)
                        changed = True
                elif thisEl.text != value:
                        thisEl.text = value
                        changed = True
                self.debug.write('changed=%s thisEl.text=%s value=%s\n' % (changed, thisEl.text, value))
        # Sub-elements must be completely described, so remove any missing elements
        if sub:
            for childEl in list(topEl):
                if childEl.tag not in d:
                    changed = True
                    self.debug.write('changed=%s removed tag=%s\n' % (changed, childEl.tag))
                    topEl.remove(childEl)

        return changed

    def get_caref(self, name):
        caref = None
        cas = self.get_elements('ca')
        for ca in cas:
            if ca.find('descr').text == name:
                caref = ca.find('refid').text
                break
        return caref

    def get_username(self):
        username = pwd.getpwuid(os.getuid()).pw_name
        if os.environ.get('SUDO_USER'):
            username = os.environ.get('SUDO_USER')
        # sudo masks this
        sshclient = os.environ.get('SSH_CLIENT')
        if sshclient:
             username = username + '@' + sshclient
        return username

    def find_alias(self, name, aliastype):
        found = None
        for alias in self.aliases:
            if alias.find('name').text == name and alias.find('type').text == aliastype:
                found = alias
                break
        return found

    def is_ip_or_alias(self, address):
        # Is it an alias?
        if self.find_alias(address, 'host'):
            return True
        if self.find_alias(address, 'urltable'):
            return True
        # Is it an IP address?
        try:
            dummy_address = ipaddress.ip_address(unicode(address))
        except ValueError:
            dummy_address = None
        if dummy_address is not None:
            return True
        # Is it an IP network?
        try:
            dummy_network = ipaddress.ip_network(unicode(address))
        except ValueError:
            dummy_network = None
        if dummy_network is not None:
            return True
        # None of the above
        return False

    def is_ip(self, address):
        # Is it an IP address?
        try:
            dummy_address = ipaddress.ip_address(unicode(address))
        except ValueError:
            dummy_address = None
        if dummy_address is not None:
            return True
        # Is it an IP network?
        try:
            dummy_network = ipaddress.ip_network(unicode(address))
        except ValueError:
            dummy_network = None
        if dummy_network is not None:
            return True
        # None of the above
        return False

    def is_port_or_alias(self, port):
        if self.find_alias(port, 'port'):
            return True
        try:
            if int(port) > 0 and int(port) < 65536:
                return True
        except:
            return False
        return False

    def uniqid(self, prefix = ''):
        return prefix + hex(int(time.time()))[2:10] + hex(int(time.time()*1000000) % 0x100000)[2:7]

    # Run a command in the php developer shell
    def phpshell(self, command):
        command = command + "\nexec\nexit"
        # Dummy argument suppresses displaying help message
        return self.module.run_command('/usr/local/sbin/pfSsh.php dummy', data=command)

    # add an interface description
    def add_interface_descr(self, name, descr):
        interfaceEl = self.interfaces.find(name)
        descrEl = ET.Element('descr')
        interfaceEl.append(descrEl)
        descrEl.text = descr
        self.write_config(descr='ansible pfsense added %s descr interface' % (descr))

    # determines if arg interface have a descr or not
    def is_interface_descr(self, name):
        interfaceEl = self.interfaces.find(name)
        descr = interfaceEl.find('descr')
        if descr != None:
            return True
        return False

    # determines if arg is an interface name or not
    def is_interface_name(self, name):
        for interface in self.interfaces:
            descrEl = interface.find('descr')
            if descrEl != None:
                if descrEl.text.strip() == name:
                    return True
        return False

    # determines if arg is a system interface or not
    def is_interface_system(self, name):
        for interface in self.interfaces:
            interfaceEl = interface.find('if').text.strip()
            if interfaceEl == name:
                return True
        return False

    # determines if arg is a pfsense interface or not
    def is_interface_pfsense(self, name):
        for interface in self.interfaces:
            interfaceEl = interface.tag.strip()
            if interfaceEl == name:
                return True
        return False

    # return pfsense interface by name
    def get_interface_pfsense_by_name(self, name):
        for interface in self.interfaces:
            interface_name = interface.find('descr').text
            if interface_name.strip() == name:
                return interface.tag
        return None

    # return system interface by name
    def get_interface_system_by_name(self, name):
        for interface in self.interfaces:
            interfaceEl = interface.find('descr').text.strip()
            if interfaceEl == name:
                return interface.find('if').text.strip()
        return None

    # return broadcast address with ipaddr and short mask
    def get_broadcast_addr(self, ip, mask):
        net = ipaddress.IPv4Network(unicode(ip) + '/' + unicode(mask), False)
        return net.broadcast_address

    # return cidr netmask with ipaddr and short mask
    def get_cidr_netmask(self, ip, mask):
        net = ipaddress.IPv4Network(unicode(ip) + '/' + unicode(mask), False)
        return net.netmask

    def write_config(self, descr='Updated by ansible pfsense module'):
        revision = self.get_element('revision')
        revision.find('time').text = '%d' % time.time()
        revdescr = revision.find('description')
        if revdescr == None:
            revdescr = ET.Element('description')
            revision.append(revdescr)
        revdescr.text = descr
        username = self.get_username()
        revision.find('username').text = username
        # Use 'html' to have explicit close tags - 3.4 has short_empty_elements
        # xml_declaration does not appear to be working
        self.tree.write('/tmp/config.xml', xml_declaration=True, method='html')
        #shutil.move('/tmp/config.xml', '/cf/conf/config.xml')
        shutil.move('/tmp/config.xml', self.config)
        try:
            os.remove('/tmp/config.cache')
        except OSError, e:
            if e.errno == 2:
                # suppress "No such file or directory error
                pass
            else:
                raise
