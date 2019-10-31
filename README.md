# ansible-pfsense
Ansible modules for managing pfsense firewalls.

This is a set of modules to allow you to configure pfsense firewalls with ansible.

## installation

Just checkout the repository and run your playbooks from the ansible-pfsense directory.

## configuration

The python interpreter is in a non-standard location on pfSense, so you will
need to set:

 ansible_python_interpreter: /usr/local/bin/python2.7

## modules
There are currently the following modules:

* [pfsense_alias](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_alias) for managing aliases
* [pfsense_authserver_ldap](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_authserver_ldap) for managing LDAP authentication servers
* [pfsense_ca](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_ca) for managing Certificate Authorities
* [pfsense_group](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_group) for managing groups
* [pfsense_interface](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_interface) for managing interfaces (EXPERIMENTAL)
* [pfsense_ipsec](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_ipsec) for managing ipsec tunnels and phase 1 options
* [pfsense_ipsec_proposal](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_ipsec_proposal) for managing ipsec proposals
* [pfsense_rule](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_rule) for managing rules
* [pfsense_rule_separator](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_rule_separator) for managing rule separators
* [pfsense_user](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_user) for managing users
* [pfsense_vlan](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_vlan) for managing vlans
* [pfsense_aggregate](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_aggregate) for bulk operations

## operation

It works by editing /cf/conf/config.xml using xml.etree.ElementTree, then
calling the appropriate php update function via the pfsense php developer
shell.

Some formatting is lost, and CDATA items are converted to normal entries,
but so far no problems with that have been noted.

## license

GPLv3.0 or later
