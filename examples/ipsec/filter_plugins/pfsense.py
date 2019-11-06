# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Frederic Bor <frederic.bor@wanadoo.fr>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.errors import AnsibleFilterError
from ipaddress import ip_network
import re

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()


def format_ipsec_aggregate_ipsecs(all_tunnels, pfname):
    """ format ipsecs for format_ipsec_aggregate """
    res = list()
    for name, ipsec in all_tunnels.items():
        pfsenses = ipsec['pfsenses']
        if pfname not in pfsenses:
            continue
        local = pfsenses[pfname]

        for remote_name, remote_options in pfsenses.items():
            if remote_name == pfname:
                continue

            params = dict()
            res.append(params)

            params['descr'] = name + ' to ' + remote_name
            params['state'] = 'present'
            for option in ipsec:
                if option in ['pfsenses', 'phase1', 'phase2']:
                    continue
                params[option] = ipsec[option]

            for option in remote_options:
                if option in ['sharing', 'myid_data']:
                    continue
                params[option] = remote_options[option]

            if 'peerid_type' in params and params['peerid_type'] == 'keyid tag':
                params['peerid_data'] = remote_options['myid_data']

            if 'myid_data' in local:
                params['myid_data'] = local['myid_data']
    return res


def format_ipsec_aggregate_proposals(all_tunnels, pfname):
    """ format proposals for format_ipsec_aggregate """
    res = list()

    for name, ipsec in all_tunnels.items():
        pfsenses = ipsec['pfsenses']
        if pfname not in pfsenses:
            continue

        if 'phase1' not in ipsec:
            raise AnsibleFilterError("phase1 is missing in {0}".format(name))

        phase1 = ipsec['phase1']
        p1s = list()

        if 'encryptions' not in phase1:
            raise AnsibleFilterError("encryptions is missing in phase1 of {0}".format(name))

        if 'hashes' not in phase1:
            raise AnsibleFilterError("hashes is missing in phase1 of {0}".format(name))

        encryptions = phase1['encryptions']
        hashes = phase1['hashes'].split(' ')

        for remote_name in pfsenses:
            if remote_name == pfname:
                continue

            for encryption in encryptions:
                for hash_option in hashes:
                    params = dict()
                    p1s.append(params)
                    params['descr'] = name + ' to ' + remote_name
                    params['state'] = 'present'
                    params['hash'] = hash_option
                    params['encryption'] = encryption
                    if encryptions[encryption] is not None and encryptions[encryption] != 'None':
                        params['key_length'] = encryptions[encryption]
        for p1_option in phase1:
            if p1_option in ['encryptions', 'hashes']:
                continue
            for p1 in p1s:
                p1[p1_option] = phase1[p1_option]
        res.extend(p1s)
    return res


def format_ipsec_aggregate_p2s(all_tunnels, pfname):
    """ format p2s for format_ipsec_aggregate """
    res = list()

    for name, ipsec in all_tunnels.items():
        pfsenses = ipsec['pfsenses']
        if pfname not in pfsenses:
            continue

        if 'phase2' not in ipsec:
            raise AnsibleFilterError("phase2 is missing in {0}".format(name))
        phase2 = ipsec['phase2']

        if 'mode' not in phase2:
            raise AnsibleFilterError("mode is missing in phase2 of {0}".format(name))
        mode = phase2['mode']

        local = pfsenses[pfname]
        if 'sharing' in local:
            local_sharing = local['sharing'].split(' ')
        elif mode != 'transport':
            raise AnsibleFilterError("sharing is missing for {0} in {1}".format(pfname, name))

        p2s = list()

        for remote_name, remote in pfsenses.items():
            if remote_name == pfname:
                continue
            if 'sharing' in remote:
                remote_sharing = remote['sharing'].split(' ')
            elif mode != 'transport':
                raise AnsibleFilterError("sharing is missing for {0} in {1}".format(remote_name, name))

            if mode != 'transport':
                for local_network in local_sharing:
                    for remote_network in remote_sharing:
                        params = dict()
                        p2s.append(params)
                        params['p1_descr'] = name + ' to ' + remote_name
                        params['descr'] = local_network + ' to ' + remote_network
                        params['state'] = 'present'
                        params['local'] = local_network
                        params['remote'] = remote_network
            else:
                params = dict()
                p2s.append(params)
                params['descr'] = name + ' to ' + remote_name
                params['p1_descr'] = name + ' to ' + remote_name
                params['state'] = 'present'

        for p2_option, p2_value in phase2.items():
            for p2 in p2s:
                if p2_option == 'encryptions':
                    for encryption, keylength in p2_value.items():
                        p2[encryption] = True
                        if keylength is not None and keylength != 'None':
                            if isinstance(keylength, str):
                                p2[encryption + '_len'] = keylength
                            else:
                                p2[encryption + '_len'] = str(keylength)
                elif p2_option == 'hashes':
                    hashes = p2_value.split(' ')
                    for hash_option in hashes:
                        p2[hash_option] = True
                else:
                    p2[p2_option] = p2_value
        res.extend(p2s)
    return res


def format_ipsec_aggregate(*terms):
    """ format var for ipsec_aggregate """
    if len(terms) != 2 or not isinstance(terms[0], dict):
        raise AnsibleFilterError("format_ipsec_aggregate expects one dictionnary of ipsec tunnels")

    all_tunnels = terms[0]
    pfname = terms[1]

    res = dict()
    res['aggregated_ipsecs'] = format_ipsec_aggregate_ipsecs(all_tunnels, pfname)
    res['aggregated_ipsec_proposals'] = format_ipsec_aggregate_proposals(all_tunnels, pfname)
    res['aggregated_ipsec_p2s'] = format_ipsec_aggregate_p2s(all_tunnels, pfname)

    return res


class FilterModule(object):
    """ FilterModule """

    @staticmethod
    def filters():
        """ defined functions """
        return {
            'format_ipsec_aggregate': format_ipsec_aggregate,
        }
