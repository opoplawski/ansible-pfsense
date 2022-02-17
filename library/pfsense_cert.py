#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Carlos Rodrigues <cmarodrigues@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: pfsense_cert
version_added: 0.5.0
author: Carlos Rodrigues (@cmarodrigues)
short_description: Manage pfSense certificates
description:
  - Manage pfSense certificates
notes:
options:
  name:
    description: The name of the certificate
    required: true
    type: str
  ca:
    description: The Certificate Authority
    type: str
  keytype:
    description: The type of key to generate
    default: 'RSA'
    choices: [ 'RSA', 'ECDSA' ]
    type: str
  digestalg:
    description: The digest method used when the certificate is signed
    default: 'sha256'
    choices: ['sha1', 'sha224', 'sha256', 'sha384', 'sha512']
    type: str
  ecname:
    description: The Elliptic Curve Name to use when generating a new ECDSA key
    default: 'prime256v1'
    choices: ['secp112r1', 'secp112r2', 'secp128r1', 'secp128r2', 'secp160k1', 'secp160r1', 'secp160r2', 'secp192k1', 'secp224k1', 'secp224r1',
        'secp256k1', 'secp384r1', 'secp521r1', 'prime192v1', 'prime192v2', 'prime192v3', 'prime239v1', 'prime239v2', 'prime239v3', 'prime256v1',
        'sect113r1', 'sect113r2', 'sect131r1', 'sect131r2', 'sect163k1', 'sect163r1', 'sect163r2', 'sect193r1', 'sect193r2', 'sect233k1', 'sect233r1',
        'sect239k1', 'sect283k1', 'sect283r1', 'sect409k1', 'sect409r1', 'sect571k1', 'sect571r1', 'c2pnb163v1', 'c2pnb163v2', 'c2pnb163v3', 'c2pnb176v1',
        'c2tnb191v1', 'c2tnb191v2', 'c2tnb191v3', 'c2pnb208w1', 'c2tnb239v1', 'c2tnb239v2', 'c2tnb239v3', 'c2pnb272w1', 'c2pnb304w1', 'c2tnb359v1',
        'c2pnb368w1', 'c2tnb431r1', 'wap-wsg-idm-ecid-wtls1', 'wap-wsg-idm-ecid-wtls3', 'wap-wsg-idm-ecid-wtls4', 'wap-wsg-idm-ecid-wtls5',
        'wap-wsg-idm-ecid-wtls6', 'wap-wsg-idm-ecid-wtls7', 'wap-wsg-idm-ecid-wtls8', 'wap-wsg-idm-ecid-wtls9', 'wap-wsg-idm-ecid-wtls10',
        'wap-wsg-idm-ecid-wtls11', 'wap-wsg-idm-ecid-wtls12', 'Oakley-EC2N-3', 'Oakley-EC2N-4', 'brainpoolP160r1', 'brainpoolP160t1', 'brainpoolP192r1',
        'brainpoolP192t1', 'brainpoolP224r1', 'brainpoolP224t1', 'brainpoolP256r1', 'brainpoolP256t1', 'brainpoolP320r1', 'brainpoolP320t1',
        'brainpoolP384r1', 'brainpoolP384t1', 'brainpoolP512r1', 'brainpoolP512t1', 'SM2']
    type: str
  keylen:
    description: The length to use when generating a new RSA key, in bits
    default: 2048
    type: str
  lifetime:
    description: The length of time the signed certificate will be valid, in days
    default: 3650
    type: str
  dn_country:
    description: The Country Code
    type: str
  dn_state:
    description: The State or Province
    type: str
  dn_city:
    description: The City
    type: str
  dn_organization:
    description: The Organization
    type: str
  dn_organizationalunit:
    description: The Organizational Unit
    type: str
  altnames:
    description:
      >
        The Alternative Names.  A list of aditional identifiers for the certificate.
        A comma separed values with format: DNS:hostname,IP:X.X.X.X,email:user@mail,URI:url
    type: str
  certificate:
    description:
      >
        The certificate to import.  This can be in PEM form or Base64
        encoded PEM as a single string (which is how pfSense stores it).
    type: str
  key:
    description:
      >
        The key to import.  This can be in PEM form or Base64
        encoded PEM as a single string (which is how pfSense stores it).
    type: str
  state:
    description: State in which to leave the certificate
    default: 'present'
    choices: [ 'present', 'absent' ]
    type: str
  method:
    description: Method of the certificate created
    default: 'internal'
    choices: [ 'internal', 'import' ]
    type: str
  certtype:
    description: Type of the certificate ('user' is a certificate for the user)
    default: 'user'
    choices: [ 'user', 'server' ]
    type: str
"""

EXAMPLES = """
- name: Generate new internal certificate
  pfsense_cert:
    method: "internal"
    name: "test"
    ca: "internal-ca"
    keytype: "RSA"
    keylen: 2048
    lifetime: 3650
    dn_country: "PT"
    dn_organization: "Dummy"
    certtype: "user"
    state: present

- name: Import certificate
  pfsense_cert:
    method: "import"
    name: "test"
    certificate: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUUxVENDQXIyZ0F3...
    key: |
      -----BEGIN PRIVATE KEY-----
      MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC4yY0SI8lWNN2B
      ...
      i0LiJ+QOek6Qy+51kMK3rXNsQQ==
      -----END PRIVATE KEY-----
    certtype: "user"
    state: present

- name: Remove certificate
  pfsense_cert:
    name: "test"
    state: absent
"""

RETURN = """

"""

import base64
import re

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.pfsense.module_base import PFSenseModuleBase

CERT_ARGUMENT_SPEC = dict(
    name=dict(required=True, type='str'),
    ca=dict(type='str'),
    keytype=dict(type='str', default='RSA', choices=['RSA', 'ECDSA']),
    digestalg=dict(type='str', default='sha256', choices=['sha1', 'sha224', 'sha256', 'sha384', 'sha512']),
    ecname=dict(
        type='str',
        default='prime256v1',
        choices=[
            'secp112r1', 'secp112r2', 'secp128r1', 'secp128r2', 'secp160k1', 'secp160r1', 'secp160r2',
            'secp192k1', 'secp224k1', 'secp224r1', 'secp256k1', 'secp384r1', 'secp521r1', 'prime192v1', 'prime192v2', 'prime192v3', 'prime239v1',
            'prime239v2', 'prime239v3', 'prime256v1', 'sect113r1', 'sect113r2', 'sect131r1', 'sect131r2', 'sect163k1', 'sect163r1', 'sect163r2',
            'sect193r1', 'sect193r2', 'sect233k1', 'sect233r1', 'sect239k1', 'sect283k1', 'sect283r1', 'sect409k1', 'sect409r1', 'sect571k1', 'sect571r1',
            'c2pnb163v1', 'c2pnb163v2', 'c2pnb163v3', 'c2pnb176v1', 'c2tnb191v1', 'c2tnb191v2', 'c2tnb191v3', 'c2pnb208w1', 'c2tnb239v1', 'c2tnb239v2',
            'c2tnb239v3', 'c2pnb272w1', 'c2pnb304w1', 'c2tnb359v1', 'c2pnb368w1', 'c2tnb431r1', 'wap-wsg-idm-ecid-wtls1', 'wap-wsg-idm-ecid-wtls3',
            'wap-wsg-idm-ecid-wtls4', 'wap-wsg-idm-ecid-wtls5', 'wap-wsg-idm-ecid-wtls6', 'wap-wsg-idm-ecid-wtls7', 'wap-wsg-idm-ecid-wtls8',
            'wap-wsg-idm-ecid-wtls9', 'wap-wsg-idm-ecid-wtls10', 'wap-wsg-idm-ecid-wtls11', 'wap-wsg-idm-ecid-wtls12', 'Oakley-EC2N-3', 'Oakley-EC2N-4',
            'brainpoolP160r1', 'brainpoolP160t1', 'brainpoolP192r1', 'brainpoolP192t1', 'brainpoolP224r1', 'brainpoolP224t1', 'brainpoolP256r1',
            'brainpoolP256t1', 'brainpoolP320r1', 'brainpoolP320t1', 'brainpoolP384r1', 'brainpoolP384t1', 'brainpoolP512r1', 'brainpoolP512t1', 'SM2']),
    keylen=dict(type='str', default='2048'),
    lifetime=dict(type='str', default='3650'),
    dn_country=dict(type='str'),
    dn_state=dict(type='str'),
    dn_city=dict(type='str'),
    dn_organization=dict(type='str'),
    dn_organizationalunit=dict(type='str'),
    altnames=dict(type='str'),
    certificate=dict(type='str'),
    key=dict(type='str'),
    state=dict(type='str', default='present', choices=['present', 'absent']),
    method=dict(type='str', default='internal', choices=['internal', 'import']),
    certtype=dict(type='str', default='user', choices=['user', 'server']),
)

CERT_PHP_COMMAND_PREFIX = """
require_once('certs.inc');
init_config_arr(array('system', 'cert'));
"""


class PFSenseCertModule(PFSenseModuleBase):
    """ module managing pfsense certificates """

    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return CERT_ARGUMENT_SPEC

    ##############################
    # init
    #
    def __init__(self, module, pfsense=None):
        super(PFSenseCertModule, self).__init__(module, pfsense)
        self.name = "pfsense_cert"
        self.root_elt = self.pfsense.root
        self.certs = self.pfsense.get_elements('cert')

    ##############################
    # params processing
    #
    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        if params['state'] == 'absent':
            return

        if params['method'] == 'internal':
            # CA is required for internal certificate
            if params['ca'] is None:
                self.module.fail_json(msg='CA is required.')

        # validate Certificate
        if params['certificate'] is not None:
            cert = params['certificate']
            lines = cert.splitlines()
            if lines[0] == '-----BEGIN CERTIFICATE-----' and lines[-1] == '-----END CERTIFICATE-----':
                params['certificate'] = base64.b64encode(cert.encode()).decode()
            elif not re.match('LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t', cert):
                self.module.fail_json(msg='Could not recognize certificate format: %s' % (cert))

        # validate key
        if params['key'] is not None:
            key = params['key']
            lines = key.splitlines()
            if lines[0] == '-----BEGIN PRIVATE KEY-----' and lines[-1] == '-----END PRIVATE KEY-----':
                params['key'] = base64.b64encode(key.encode()).decode()
            elif not re.match('LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t', key):
                self.module.fail_json(msg='Could not recognize key format: %s' % (key))

    def _params_to_obj(self):
        """ return a dict from module params """
        params = self.params

        obj = dict()
        self.obj = obj

        # certificate description
        obj['descr'] = params['name']
        if params['state'] == 'present':

            if params['ca'] is not None:
                # found CA
                ca = self._find_ca(params['ca'])
                if ca is not None:
                    # get CA refid
                    obj['caref'] = ca.find('refid').text
                else:
                    self.module.fail_json(msg='CA (%s) not found' % params['ca'])

            if 'certificate' in params and params['certificate'] is not None:
                obj['crt'] = params['certificate']
            if 'key' in params and params['key'] is not None:
                obj['prv'] = params['key']

        return obj

    ##############################
    # XML processing
    #
    def _find_target(self):
        result = self.root_elt.findall("cert[descr='{0}']".format(self.obj['descr']))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple certificates for descr {0}.'.format(self.obj['descr']))
        else:
            return None

    def _find_this_cert_index(self):
        return self.certs.index(self.target_elt)

    def _find_last_cert_index(self):
        return list(self.root_elt).index(self.certs[len(self.certs) - 1])

    def _find_ca(self, caref):
        result = self.root_elt.findall("ca[descr='{0}']".format(caref))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.module.fail_json(msg='Found multiple CAs for caref {0}.'.format(caref))
        else:
            result = self.root_elt.findall("ca[refid='{0}']".format(caref))
            if len(result) == 1:
                return result[0]
            elif len(result) > 1:
                self.module.fail_json(msg='Found multiple CAs for caref {0}.'.format(caref))
            else:
                return None

    def _create_target(self):
        """ create the XML target_elt """
        return self.pfsense.new_element('cert')

    def _copy_and_add_target(self):
        """ populate the XML target_elt """
        obj = self.obj

        obj['refid'] = self.pfsense.uniqid()
        self.diff['after'] = obj
        self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.root_elt.insert(self._find_last_cert_index(), self.target_elt)
        # Reset certs list
        self.certs = self.root_elt.findall('cert')

    def _copy_and_update_target(self):
        """ update the XML target_elt """

        before = self.pfsense.element_to_dict(self.target_elt)
        self.diff['before'] = before

        changed = self.pfsense.copy_dict_to_element(self.obj, self.target_elt)
        self.diff['after'] = self.pfsense.element_to_dict(self.target_elt)

        return (before, changed)

    ##############################
    # Logging
    #
    def _get_obj_name(self):
        """ return obj's name """
        return "'" + self.obj['descr'] + "'"

    def _log_fields(self, before=None):
        """ generate pseudo-CLI command fields parameters to create an obj """
        values = ''
        if before is None:
            values += self.format_cli_field(self.params, 'descr')
        else:
            values += self.format_updated_cli_field(self.obj, before, 'descr', add_comma=(values))
        return values

    ##############################
    # run
    #
    def _update(self):
        if self.params['state'] == 'present':
            if self.params['method'] == 'import':
                # import certificate
                return self.pfsense.phpshell("""
                    require_once('certs.inc');
                    init_config_arr(array('cert'));
                    $cert =& lookup_cert('{refid}');
                    cert_import($cert, '{cert}', '{key}');
                    $savemsg = sprintf(gettext("Imported certificate %s"), $cert['descr']);
                    write_config($savemsg);""".format(refid=self.target_elt.find('refid').text,
                                                      cert=base64.b64decode(self.target_elt.find('crt').text.encode()).decode(),
                                                      key=base64.b64decode(self.target_elt.find('prv').text.encode()).decode()))
            else:
                # generate internal certificate
                return self.pfsense.phpshell("""
                    require_once('certs.inc');
                    init_config_arr(array('cert'));
                    $cert =& lookup_cert('{refid}');

                    $pconfig = array( 'dn_commonname'         => '{dn_commonname}',
                                      'dn_country'            => '{dn_country}',
                                      'dn_state'              => '{dn_state}',
                                      'dn_city'               => '{dn_city}',
                                      'dn_organization'       => '{dn_organization}',
                                      'dn_organizationalunit' => '{dn_organizationalunit}',
                                      'dn_altnames'           => '{altnames}' );

                    /* Create an internal certificate */
                    $dn = array('commonName' => $pconfig['dn_commonname']);
                    if (!empty($pconfig['dn_country']) && ($pconfig['dn_country']!=='None')) {{
                        $dn['countryName'] = $pconfig['dn_country'];
                    }}
                    if (!empty($pconfig['dn_state']) && ($pconfig['dn_state']!=='None')) {{
                        $dn['stateOrProvinceName'] = $pconfig['dn_state'];
                    }}
                    if (!empty($pconfig['dn_city']) && ($pconfig['dn_city']!=='None')) {{
                        $dn['localityName'] = $pconfig['dn_city'];
                    }}
                    if (!empty($pconfig['dn_organization']) && ($pconfig['dn_organization']!=='None')) {{
                        $dn['organizationName'] = $pconfig['dn_organization'];
                    }}
                    if (!empty($pconfig['dn_organizationalunit']) && ($pconfig['dn_organizationalunit']!=='None')) {{
                        $dn['organizationalUnitName'] = $pconfig['dn_organizationalunit'];
                    }}
                    $altnames_tmp = array();
                    $cn_altname = cert_add_altname_type($pconfig['dn_commonname']);
                    if (!empty($cn_altname)) {{
                        $altnames_tmp[] = $cn_altname;
                    }}
                    if (!empty($pconfig['dn_altnames']) && ($pconfig['dn_altnames']!=='None')) {{
                        $altnames_tmp[] = $pconfig['dn_altnames'];
                    }}
                    if (!empty($altnames_tmp)) {{
                        $dn['subjectAltName'] = implode(",", $altnames_tmp);
                    }}

                    if (!cert_create($cert, '{caref}', '{keylen}', '{lifetime}', $dn, '{certtype}', '{digest_alg}', '{keytype}', '{ecname}')) {{
                        $input_errors = array();
                        while ($ssl_err = openssl_error_string()) {{
                            if (strpos($ssl_err, 'NCONF_get_string:no value') === false) {{
                                $input_errors[] = sprintf(gettext("OpenSSL Library Error: %s"), $ssl_err);
                            }}
                        }}
                        print_r($input_errors);
                    }}
                    $savemsg = sprintf(gettext("Created internal certificate %s"), $cert['descr']);
                    write_config($savemsg);""".format(refid=self.target_elt.find('refid').text,
                                                      dn_commonname=self.params['name'],
                                                      dn_country=self.params['dn_country'],
                                                      dn_state=self.params['dn_state'],
                                                      dn_city=self.params['dn_city'],
                                                      dn_organization=self.params['dn_organization'],
                                                      dn_organizationalunit=self.params['dn_organizationalunit'],
                                                      altnames=self.params['altnames'],
                                                      caref=self.target_elt.find('caref').text,
                                                      keylen=self.params['keylen'],
                                                      lifetime=self.params['lifetime'],
                                                      certtype=self.params['certtype'],
                                                      keytype=self.params['keytype'],
                                                      digest_alg=self.params['digestalg'],
                                                      ecname=self.params['ecname']))
        else:
            return (None, '', '')

    def _pre_remove_target_elt(self):
        self.diff['after'] = {}
        if self.target_elt is not None:
            self.diff['before'] = self.pfsense.element_to_dict(self.target_elt)
            self.certs.remove(self.target_elt)
        else:
            self.diff['before'] = {}


def main():
    module = AnsibleModule(
        argument_spec=CERT_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseCertModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
