# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import shutil
import os
import pwd
import time
import xml.etree.ElementTree as ET 

class pfSenseModule(object):

    def __init__(self, module):
        self.module = module
        self.tree = ET.parse('/cf/conf/config.xml')
        self.root = self.tree.getroot()
        self.debug = open('/tmp/pfsense.debug','w')

    def get_element(self, node):
        return self.root.find(node)

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
                # Create a new element
                newEl = ET.Element(key)
                changed = True
                if isinstance(value,dict):
                    self.debug.write('calling copy_dict_to_element()\n')
                    newEl.text = '\n%s' % ('\t' * (sub + 4))
                    newEl.tail = '\n%s' % ('\t' * (sub + 3))
                    self.copy_dict_to_element(value, newEl, sub=sub+1)
                else:
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

    def get_username(self):
        username = pwd.getpwuid(os.getuid()).pw_name
        if os.environ.get('SUDO_USER'):
            username = os.environ.get('SUDO_USER')
        # sudo masks this
        sshclient = os.environ.get('SSH_CLIENT')
        if sshclient:
             username = username + '@' + sshclient
        return username

    # Run a command in the php developer shell
    def phpshell(self, command):
        command = command + "\nexec\nexit"
        # Dummy argument suppresses displaying help message
        return self.module.run_command('/usr/local/sbin/pfSsh.php dummy', data=command)

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
        shutil.move('/tmp/config.xml', '/cf/conf/config.xml')
        os.remove('/tmp/config.cache')
