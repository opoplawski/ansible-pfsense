# ansible-pfsense
Ansible modules for managing pfsense firewalls.

This is a set of modules to allow you to configure pfsense firewalls with ansible.

## installation using ansible galaxy

Ansible Galaxy now has an option for collections.  A collection is a distribution format for delivering all type of Ansible content (not just roles as it was before).  Ansible-pfsense can be installed using ansible-galaxy.

### requirements

To install `ansible-pfsense` using ansible-galaxy, you must have ansible version `2.9+` installed on your system.

### install command

`ansible-galaxy collection install opoplawski.pfsense`

Optionally, you can specify the path of the collection installation with the `-p` option.

`ansible-galaxy collection install opoplawski.pfsense -p ./collections`

Aditionally, you can set the `collections_paths` option in your `ansible.cfg` file to automatically designate install locations.

```ini
# ansible.cfg
[defaults]
collections_paths=collections
```

## installing using ansible pre-2.9 (not galaxy)

To install this module pre-ansible version 2.9, you need to download one of the [releases](https://github.com/opoplawski/ansible-pfsense/releases) and extract it to the root of your project directory.

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
* [pfsense_ipsec_p2](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_ipsec_p2) for managing ipsec tunnels phase 2 options
* [pfsense_rule](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_rule) for managing rules
* [pfsense_rule_separator](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_rule_separator) for managing rule separators
* [pfsense_user](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_user) for managing users
* [pfsense_vlan](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_vlan) for managing vlans

## bulk modules
These modules allow you to make important changes at once and, using the purge parameters, to keep the targets configuration strictly synchronized with your playbooks:

* [pfsense_aggregate](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_aggregate) for aliases, rules, rule separators, interfaces and vlans
* [pfsense_ipsec_aggregate](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_ipsec_aggregate) for ipsec tunnels, phases 1, phases 2 and proposals

## operation

It works by editing /cf/conf/config.xml using xml.etree.ElementTree, then
calling the appropriate php update function via the pfsense php developer
shell.

Some formatting is lost, and CDATA items are converted to normal entries,
but so far no problems with that have been noted.

## how to use in a task

### ansible galaxy version

Using the ansible-galaxy version of these modules requires you to reference the FQCN of the modules.  This means prefix each module in your task with `opoplawski.pfsense.{module_name}`.

Example:

```yaml
# task.yml
---

- name: 192.168.40.0/24 - Guest WiFi
  opoplawski.pfsense.pfsense_vlan:
    interface: "{{ pfsense_lan_nic }}"
    vlan_id: 40
    descr: 192.168.40.0/24 - Guest WiFi
    state: present
```

### ansible pre-2.9 (non galaxy) version

Using the ansible pre-2.9 version of the plugin you can reference the modules by module name.  There is no need to prefix the module name with the FQCN.

Example:

```yaml
# task.yml
---

- name: 192.168.40.0/24 - Guest WiFi
  pfsense_vlan:
    interface: "{{ pfsense_lan_nic }}"
    vlan_id: 40
    descr: 192.168.40.0/24 - Guest WiFi
    state: present
```

## license

GPLv3.0 or later
