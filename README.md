# Ansible-pfsense / pfsensible.core

This is a set of modules to allow you to configure pfSense firewalls with ansible.

## Installation using ansible galaxy

Ansible Galaxy (as of version 2.9) now has an option for collections.  A collection is a distribution
format for delivering all type of Ansible content (not just roles as it was before).  We have renamed
the collection 'pfsensible.core' for galaxy distribution.  To install:

```
ansible-galaxy collection install pfsensible.core
```

Optionally, you can specify the path of the collection installation with the `-p` option.

```
ansible-galaxy collection install pfsensible.core -p ./path_to_collections
```

Additionally, you can set the `collections_paths` option in your `ansible.cfg` file to automatically designate install locations.

```ini
# ansible.cfg
[defaults]
collections_paths=collections
```

## Configuration

The Python interpreter is in a non-standard location on pfSense, so you will
need to set in your playbook vars:

```
ansible_python_interpreter: /usr/local/bin/python2.7
```

## Modules
The following modules are currently available:

* [pfsensible.core.alias](https://github.com/pfsensible/core/wiki/pfsensible.core.alias) for aliases
* [pfsensible.core.authserver_ldap](https://github.com/pfsensible/core/wiki/pfsensible.core.authserver_ldap) for LDAP authentication servers
* [pfsensible.core.ca](https://github.com/pfsensible/core/wiki/pfsensible.core.ca) for Certificate Authorities
* [pfsensible.core.gateway](https://github.com/pfsensible/core/wiki/pfsensible.core.gateway) for routing gateways
* [pfsensible.core.group](https://github.com/pfsensible/core/wiki/pfsensible.core.group) for groups
* [pfsensible.core.interface](https://github.com/pfsensible/core/wiki/pfsensible.core.interface) for interfaces (EXPERIMENTAL)
* [pfsensible.core.ipsec](https://github.com/pfsensible/core/wiki/pfsensible.core.ipsec) for ipsec tunnels and phase 1 options
* [pfsensible.core.ipsec_proposal](https://github.com/pfsensible/core/wiki/pfsensible.core.ipsec_proposal) for ipsec proposals
* [pfsensible.core.ipsec_p2](https://github.com/pfsensible/core/wiki/pfsensible.core.ipsec_p2) for ipsec tunnels phase 2 options
* [pfsensible.core.nat_outbound](https://github.com/pfsensible/core/wiki/pfsensible.core.nat_outbound) for outbound NAT rules
* [pfsensible.core.nat_port_forward](https://github.com/pfsensible/core/wiki/pfsensible.core.nat_port_forward) for port forward NAT rules
* [pfsensible.core.route](https://github.com/pfsensible/core/wiki/pfsensible.core.route) for routes
* [pfsensible.core.rule](https://github.com/pfsensible/core/wiki/pfsensible.core.rule) for rules
* [pfsensible.core.rule_separator](https://github.com/pfsensible/core/wiki/pfsensible.core.rule_separator) for rule separators
* [pfsensible.core.setup](https://github.com/pfsensible/core/wiki/pfsensible.core.setup) for general setup
* [pfsensible.core.user](https://github.com/pfsensible/core/wiki/pfsensible.core.user) for users
* [pfsensible.core.vlan](https://github.com/pfsensible/core/wiki/pfsensible.core.vlan) for vlans

## Bulk modules
These modules allow you to make important changes at once and, using the purge parameters, to keep the targets configuration strictly synchronized with your playbooks:

* [pfsensible.core.aggregate](https://github.com/pfsensible/core/wiki/pfsensible.core.aggregate) for aliases, rules, rule separators, interfaces and vlans
* [pfsensible.core.ipsec_aggregate](https://github.com/pfsensible/core/wiki/pfsensible.core.ipsec_aggregate) for ipsec tunnels, phases 1, phases 2 and proposals

## Operation

Modules in the collection work by editing `/cf/conf/config.xml` using xml.etree.ElementTree, then
calling the appropriate php update function via the pfsense php developer
shell.

Some formatting is lost, and CDATA items are converted to normal entries,
but so far no problems with that have been noted.

## License

GPLv3.0 or later
