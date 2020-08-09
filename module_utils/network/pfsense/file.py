# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
from ansible.module_utils.network.pfsense.module_base import PFSenseModuleBase
import base64
import hashlib
import os
import re


FILE_ARGUMENT_SPEC = dict(
    state=dict(default='present', choices=['present', 'absent']),
    name=dict(required=True, type='str'),
    content=dict(required=False, type='str'),
    permissions=dict(required=False, type='str'),
)

FILE_REQUIRED_IF = [
    ["state", "present", ["content"]],
]


class PFSenseFileModule(PFSenseModuleBase):
    """ module managing pfsense files """

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseFileModule, self).__init__(module, pfsense)
        self.name = "pfsense_file"
        self.obj = dict()

    ##############################
    # params processing
    #
    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()

        obj['name'] = params['name']
        if params['state'] == 'present':
            obj['content'] = base64.b64decode(params['content'])
            obj['md5'] = hashlib.md5(obj['content']).hexdigest()

        return obj

    def _validate_params(self):
        """ do some extra checks on input parameters """
        if self.params.get('permissions'):
            if re.match('^[0-7]{4}$', self.params['permissions']) is None:
                self.module.fail_json(msg="permissions must be in 4 octal format (got '{0}')".format(self.params['permissions']))

    ##############################
    # XML processing
    #
    @staticmethod
    def _find_target():
        """ find the XML target_elt """
        return None

    ##############################
    # run
    #
    def _add(self):
        """ add or update obj """
        if os.path.isfile(self.obj['name']):
            oldmd5 = self._md5(self.obj['name'])
            if oldmd5 != self.obj['md5']:
                self._write_file()
                self.result['commands'].append('update {0}'.format(self.obj['name']))
        else:
            self._write_file()
            self.result['commands'].append('create {0}'.format(self.obj['name']))

        if self.params.get('permissions'):
            current = self._get_permissions(self.obj['name'])
            if current != self.params['permissions']:
                self._set_permissions()
                self.result['commands'].append('set {0} permissions from {1} to {2}'.format(self.obj['name'], current, self.params['permissions']))

    def commit_changes(self):
        """ apply changes and exit module """
        self.result['stdout'] = ''
        self.result['stderr'] = ''
        self.module.exit_json(**self.result)

    @staticmethod
    def _get_permissions(fname):
        """ get the file permissions """
        res = os.stat(fname)
        return str(oct(res.st_mode)[-4:])

    @staticmethod
    def _md5(fname):
        """ compute md5 of file """
        hash_md5 = hashlib.md5()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def _remove(self):
        """ delete obj """
        if os.path.isfile(self.obj['name']):
            self.result['changed'] = True
            self.result['commands'].append('delete {0}'.format(self.obj['name']))
            if not self.module.check_mode:
                os.remove(self.obj['name'])

    def _set_permissions(self):
        """ set the file permissions """
        self.result['changed'] = True
        if not self.module.check_mode:
            os.chmod(self.obj['name'], int(self.params['permissions'], base=8))

    def _write_file(self):
        """ write the file content """
        self.result['changed'] = True
        if not self.module.check_mode:
            content = bytearray(self.obj['content'])
            target = open(self.obj['name'], "wb")
            target.write(content)
            target.close()
