# Copyright: (c) 2022, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest
import sys

if sys.version_info < (2, 7):
    pytestmark = pytest.mark.skip("pfSense Ansible modules require Python >= 2.7")

from xml.etree.ElementTree import fromstring, ElementTree
from units.compat.mock import patch
from ansible.modules.network.pfsense import pfsense_openvpn_server
from .pfsense_module import TestPFSenseModule, load_fixture

CERTIFICATE = (
    "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlFQ0RDQ0F2Q2dBd0lCQWdJSUZqRk9oczFuTXpRd0RRWUpLb1pJaHZjTkFRRUxCUUF3WERFVE1CRUdBMVVFDQpBeE1LYjNCbGJuWndiaTFqWVRF"
    "TE1Ba0dBMVVFQmhNQ1ZWTXhFVEFQQmdOVkJBZ1RDRU52Ykc5eVlXUnZNUkF3DQpEZ1lEVlFRSEV3ZENiM1ZzWkdWeU1STXdFUVlEVlFRS0V3cHdabE5sYm5OcFlteGxNQjRYRFRJeU1ESXhOREExDQpN"
    "RGd6TVZvWERUTXlNREl4TWpBMU1EZ3pNVm93WERFVE1CRUdBMVVFQXhNS2IzQmxiblp3YmkxallURUxNQWtHDQpBMVVFQmhNQ1ZWTXhFVEFQQmdOVkJBZ1RDRU52Ykc5eVlXUnZNUkF3RGdZRFZRUUhF"
    "d2RDYjNWc1pHVnlNUk13DQpFUVlEVlFRS0V3cHdabE5sYm5OcFlteGxNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDDQpBUUVBbXN2aUpNRTFFVGVkNGZPdGJrSHBGM2Q5ZU0r"
    "NjQwOFhQbmE4dEpHZEJxM1VBQ3hFem9hQktSdDJ5MWN0DQo2elFEZTVGRjRBQXZ0VjF1Y1pwc2w1bzREUy9JR1NibjZkM1lNaytqOGpBUTNFbXpSOEdPb2huZ2YxUTlBWEM2DQpvaDRyQlA1c1g0WTh1"
    "WThrSjNZclg1cVRwRlk1S0hMVTFBb1BleVE3eXlNWkhMb2t0OW5jK0ZGWnd3VTdSQ0dTDQpjTkxaaVZ4Q1FRSzVwOGs5bUE4Ymd4bHFZa2YwbUF5Qk53OU1BZlBVY1VrcUY2UDBnV1BIbElySFovdWhn"
    "N2RVDQorMjJhb2NLVUVOaXY5bXFhK0I2Y1VnTFRGVDZzMFZTRXNYL2RBZWg2MllMZ2ZtWEpnNmROSFFJK01nNlNrZWxwDQprOVZSVGVqaUVUSUVWOEpnZHYyTjdSU201d0lEQVFBQm80SE5NSUhLTUIw"
    "R0ExVWREZ1FXQkJSazVvQS8wcWEyDQpLUHdnb1hKcUtNdCtBb0tKZ1RDQmpRWURWUjBqQklHRk1JR0NnQlJrNW9BLzBxYTJLUHdnb1hKcUtNdCtBb0tKDQpnYUZncEY0d1hERVRNQkVHQTFVRUF4TUti"
    "M0JsYm5ad2JpMWpZVEVMTUFrR0ExVUVCaE1DVlZNeEVUQVBCZ05WDQpCQWdUQ0VOdmJHOXlZV1J2TVJBd0RnWURWUVFIRXdkQ2IzVnNaR1Z5TVJNd0VRWURWUVFLRXdwd1psTmxibk5wDQpZbXhsZ2dn"
    "V01VNkd6V2N6TkRBTUJnTlZIUk1FQlRBREFRSC9NQXNHQTFVZER3UUVBd0lCQmpBTkJna3Foa2lHDQo5dzBCQVFzRkFBT0NBUUVBVUg5S0NkbUpkb0FKbFUwd0JKSFl4akxyS2xsUFk2T05ienI1SmJo"
    "Q002OUh4eFlODQpCa2lpbXd1N09mRmFGZkZDT25NSjhvcStKVGxjMG9vREoxM2xCdHRONkdybnZrUTNQMXdZYkNFTmJuaWxPYVVCDQpUSXJpSHl0TkRRYW91TmEvS1dzN0ZhdW9iY3RCbDF3OWF0b0ha"
    "c041b2VoVDNyQVR2MUNDQXRqcGFUSklmSlIzDQowSVFPWWtlNG9ZNkRrSXdIcDJ2UFBtb29HZ0l0YlR3M1UrRTQxWVplN3FDbUUvN3pMVFNaa0lNMmx4NnpENDZqDQpEZjRyZ044TVVMNnhpd09Mbzly"
    "QUp5ckRNM2JEeTJ1QjY0QkVzRFFMa2huUE92ZWtETjQ1NnV6TmpYS0E3VnE4DQpoMS9nekRaSURpK1dYQ1lBY2JnTGhaVkJxdG42MnVtRnBNUkl1dz09DQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t"
    "DQo=")

TLSKEY = (
    "IwojIDIwNDggYml0IE9wZW5WUE4gc3RhdGljIGtleQojCi0tLS0tQkVHSU4gT3BlblZQTiBTdGF0aWMga2V5IFYxLS0tLS0KNjFiY2E4MDk0ZmM4YjA3ZTZlMjE3NzRmNTI0YTIyOWYKNGMzZGZhMDVjZ"
    "Tc2ODVlN2NkNDc1N2I0OGM3ZmMzZDcKYzQzMjhjYzBmMWQ4Yjc2OTk2MjVjNzAwYmVkNzNhNWYKY2RjMjYzMTY2YThlMzVmYTk4NGU0OWVkZDg5MDNkZmMKMDc1ZTQyY2ZlOTM5NzUwYzhmMjc1YTY3MT"
    "kzMGRmMzEKMDY2Mzk1MjM2ZWRkYWQ3NDc3YmVjZjJmNDgyNzBlMjUKODM1N2JlMGE1MGUzY2Y0ZjllZTEyZTdkMmM4YTY2YzEKODUwNjBlODM5ZWUyMzdjNTZkZmUzNjA4NjU0NDhhYzgKNjhmM2JhYWQ"
    "4ODNjNDU3NTdlZTVjMWQ4ZDk5ZjM4ZjcKZGNiZDAwZmI3Nzc2ZWFlYjQ1ZmQwOTBjNGNlYTNmMGMKMzgzNDE0ZTJlYmU4MWNiZGIxZmNlN2M2YmFhMDlkMWYKMTU4OGUzNGRkYzUxY2NjOTE5NDNjNTFh"
    "OTI2OTE3NWQKNzZiZjdhOWI1ZmM3NDAyNmE3MTVkNGVmODVkYzY2Y2UKMWE5MWQwNjNhODIwZDY4MTc0ODlmYjJkZjNmYzY2MmMKMmU2OWZiMzNiMzM5MjdjYjUyNThkZDQ4M2NkNDE0Y2QKMDJhZWE3Z"
    "jA3MmNhZmEwOTY5Yjg5NWVjYzNiYmExNGQKLS0tLS1FTkQgT3BlblZQTiBTdGF0aWMga2V5IFYxLS0tLS0K")


class TestPFSenseOpenVPNServerModule(TestPFSenseModule):

    module = pfsense_openvpn_server

    def __init__(self, *args, **kwargs):
        super(TestPFSenseOpenVPNServerModule, self).__init__(*args, **kwargs)
        self.config_file = 'pfsense_openvpn_config.xml'
        self.pfmodule = pfsense_openvpn_server.PFSenseOpenVPNServerModule

    @staticmethod
    def runTest():
        """ dummy function needed to instantiate this test module from another in python 2.7 """
        pass

    def get_target_elt(self, obj, absent=False):
        """ return target elt from XML """
        root_elt = self.xml_result.getroot().find('openvpn')
        result = root_elt.findall("openvpn-server[description='{0}']".format(obj['name']))
        if len(result) == 1:
            return result[0]
        elif len(result) > 1:
            self.fail('Found multiple OpenVPN servers for name {0}.'.format(obj['name']))
        else:
            return None

    @staticmethod
    def caref(descr):
        """ return refid for ca """
        if descr == 'OpenVPN CA':
            return '6209e3cef1e81'
        return ''

    @staticmethod
    def crlref(descr):
        """ return refid for crl """
        if descr == 'OpenVPN CRL':
            return '6209e3cef1e81'
        return None

    @staticmethod
    def certref(descr):
        """ return refid for cert """
        if descr == 'OpenVPN CERT':
            return '6209e3cef1e81'
        return None

    def check_target_elt(self, params, target_elt):
        """ check XML definition of target elt """

        self.check_param_equal(params, target_elt, 'name', xml_field='description')
        self.check_param_equal(params, target_elt, 'custom_options')
        self.check_param_equal(params, target_elt, 'mode', default='ptp_tls')
        if params['mode'] == 'server_tls_user':
            self.check_list_param_equal(params, target_elt, 'authmode')
        if params['mode'] == 'p2p_shared_key':
            self.check_param_equal(params, target_elt, 'shared_key')
        self.check_param_equal(params, target_elt, 'dev_mode', default='tun')
        self.check_param_bool(params, target_elt, 'disabled')
        self.check_param_equal(params, target_elt, 'interface', default='wan')
        self.check_param_equal(params, target_elt, 'local_port', default=1194)
        self.check_param_equal(params, target_elt, 'protocol', default='UDP4')
        if 'tls' in params['mode']:
            self.check_param_equal(params, target_elt, 'tls')
            self.check_param_equal(params, target_elt, 'tls_type')
            self.assert_xml_elt_equal(target_elt, 'caref', self.caref(params['ca']))
            if 'crl' in params:
                self.assert_xml_elt_equal(target_elt, 'crlref', self.crlref(params['crl']))
            if 'cert' in params:
                self.assert_xml_elt_equal(target_elt, 'certref', self.certref(params['cert']))
            self.check_param_equal(params, target_elt, 'cert_depth', default=1)
        else:
            self.assert_not_find_xml_elt('tls')
            self.assert_not_find_xml_elt('tls_type')
        self.check_param_bool(params, target_elt, 'strictuserdn')
        self.check_param_equal(params, target_elt, 'dh_length', default=2048)
        self.check_param_equal(params, target_elt, 'ecdh_curve', default='none')
        self.check_param_equal(params, target_elt, 'data_ciphers_fallback', default='AES-256-CBC')
        self.check_param_equal(params, target_elt, 'data_ciphers', default='AES-256-GCM,AES-128-GCM,CHACHA20-POLY1305')
        self.check_param_bool(params, target_elt, 'ncp_enable', default=True, value_true='enabled')
        self.check_param_equal(params, target_elt, 'digest', default='SHA256')
        self.check_param_equal(params, target_elt, 'ecdh_curve', default='none')
        self.check_param_equal(params, target_elt, 'allow_compression', default='no')
        self.check_param_equal(params, target_elt, 'compression', default=None)
        self.check_param_bool(params, target_elt, 'compression_push', default=False, value_true='yes')
        self.check_param_equal(params, target_elt, 'ecdh_curve', default='none')
        self.check_param_equal(params, target_elt, 'tunnel_network')
        self.check_param_equal(params, target_elt, 'tunnel_networkv6')
        self.check_param_equal(params, target_elt, 'local_network')
        self.check_param_equal(params, target_elt, 'local_networkv6')
        self.check_param_equal(params, target_elt, 'remote_network')
        self.check_param_equal(params, target_elt, 'remote_networkv6')
        self.check_param_bool(params, target_elt, 'gwredir', default=False, value_true='yes')
        self.check_param_bool(params, target_elt, 'gwredir6', default=False, value_true='yes')
        self.check_param_equal(params, target_elt, 'maxclients')

    ##############
    # tests
    #
    def test_openvpn_server_create(self):
        """ test creation of a new OpenVPN server """
        obj = dict(name='ovpns3', mode='p2p_tls', ca='OpenVPN CA', local_port=1196)
        self.do_module_test(obj, command="create openvpn_server 'ovpns3', description='ovpns3'")

    def test_openvpn_server_delete(self):
        """ test deletion of a OpenVPN server """
        obj = dict(name='ovpns2')
        self.do_module_test(obj, command="delete openvpn_server 'ovpns2'", delete=True)

    def test_openvpn_server_update_noop(self):
        """ test not updating a OpenVPN server """
        obj = dict(name='ovpns2', mode='p2p_tls', ca='OpenVPN CA', local_port=1195, tls=TLSKEY, tls_type='auth')
        self.do_module_test(obj, changed=False)

    def test_openvpn_server_update_network(self):
        """ test updating network of a OpenVPN server """
        obj = dict(name='ovpns2', mode='p2p_tls', ca='OpenVPN CA', local_port=1195, tls=TLSKEY, tls_type='auth', tunnel_network='10.10.10.10/24')
        self.do_module_test(obj, command="update openvpn_server 'ovpns2' set ")

    ##############
    # misc
    #
    def test_create_openvpn_server_duplicate_port(self):
        """ test creation of a new OpenVPN server with duplicate port """
        obj = dict(name='ovpns3', mode='p2p_tls', ca='OpenVPN CA')
        self.do_module_test(obj, failed=True, msg='The specified local_port (1194) is in use by vpn ID 1')

    def test_create_openvpn_server_invalid_certificate(self):
        """ test creation of a new OpenVPN server with invalid certificate """
        obj = dict(name='ovpns2', mode='p2p_tls', ca='OpenVPN CA', cert='blah')
        self.do_module_test(obj, failed=True, msg='blah is not a valid certificate')

    def test_delete_nonexistent_openvpn_server(self):
        """ test deletion of an nonexistent OpenVPN server """
        obj = dict(name='novpn')
        self.do_module_test(obj, commmand=None, state='absent', changed=False)
