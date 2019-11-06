# Managing ipsec tunnels with ansible-pfsense

This example will demonstrate how to manage your ipsec configuration.

It is designed for people who have multiple pfSense firewalls to setup.

## Description

We want to configure 3 firewalls and setup a fully connected VPN network between them.

We assume a standardized configuration (like each firewall uses it's wan interface),
done with ansible-pfsense indeed.

To easily acheive this goal, I have wrote an ansible filter. It takes a yaml file
for input, describing the desired VPNs properties, and generates output parameters
for the module [pfsense_ipsec_aggregate](https://github.com/opoplawski/ansible-pfsense/wiki/pfsense_ipsec_aggregate).

If you want to add new firewalls and networks to your topology, it only requires
a few more lines in the yaml definition file.

As far as possible, I tried to use the same parameters as for the ansible-pfsense
ipsec modules, in order to make writing the configuration yaml file more natural.

## Files

* ipsecs.yaml: the VPN properties
* hosts: the Ansible file for pfsense hosts
* setup_ipsec.yml: the playbook used to setup all the pfsenses
* filter_plugins/pfsense.py: the formatting plugin
* more.ipsecs.yaml: more VPN properties 

## Installation

You don't need to copy any files. Just adapt your ansible hosts file like the one
provided or adapt the yaml file with your hosts.

To run the test in check mode for all the 3 firewalls, just go into your ansible-pfsense
directory and run:

```
ansible-playbook -C -v examples/ipsec/setup_ipsec.yml
```

## TODO

The filter plugin needs to be improved to support all kind of configuration
(especially regarding authentication parameters).
