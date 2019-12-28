# Ansible-pfsense
Ansible modules for managing pfsense firewalls.

This is a set of modules to allow you to configure pfsense firewalls with ansible.

## Installation

Just checkout the repository and run your playbooks from the ansible-pfsense directory.

## Configuration

The python interpreter is in a non-standard location on pfSense, so you will
need to set:

 ansible_python_interpreter: /usr/local/bin/python2.7

## Modules
The following modules are currently available:

* [pfsense_alias](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_alias) for aliases
* [pfsense_authserver_ldap](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_authserver_ldap) for LDAP authentication servers
* [pfsense_ca](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_ca) for Certificate Authorities
* [pfsense_group](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_group) for groups
* [pfsense_interface](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_interface) for interfaces (EXPERIMENTAL)
* [pfsense_ipsec](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_ipsec) for ipsec tunnels and phase 1 options
* [pfsense_ipsec_proposal](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_ipsec_proposal) for ipsec proposals
* [pfsense_ipsec_p2](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_ipsec_p2) for ipsec tunnels phase 2 options
* [pfsense_nat_outbound](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_nat_outbound) for outbound NAT rules
* [pfsense_nat_port_forward](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_nat_port_forward) for port forward NAT rules
* [pfsense_rule](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_rule) for rules
* [pfsense_rule_separator](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_rule_separator) for rule separators
* [pfsense_user](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_user) for users
* [pfsense_vlan](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_vlan) for vlans

## Bulk modules
These modules allow you to make important changes at once and, using the purge parameters, to keep the targets configuration strictly synchronized with your playbooks:

* [pfsense_aggregate](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_aggregate) for aliases, rules, rule separators, interfaces and vlans
* [pfsense_ipsec_aggregate](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_ipsec_aggregate) for ipsec tunnels, phases 1, phases 2 and proposals

## Third party modules
These modules allow you to manage installed packages:

* [pfsense_haproxy_backend](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_haproxy_backend) for haproxy backends
* [pfsense_haproxy_backend_server](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_haproxy_backend_server) for haproxy backends servers

## Operation

It works by editing /cf/conf/config.xml using xml.etree.ElementTree, then
calling the appropriate php update function via the pfsense php developer
shell.

Some formatting is lost, and CDATA items are converted to normal entries,
but so far no problems with that have been noted.

## License

GPLv3.0 or later
