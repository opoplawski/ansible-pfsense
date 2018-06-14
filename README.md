# ansible-pfsense
WIP ansible module for managing pfsense firewalls.

This is the very early stages of a module to allow you to configure pfsense
firewalls with ansible.  There are currently two modules:

* pfsense_alias for managing aliases
* pfsense_rule for managing rules

# pfsense_alias
```
> PFSENSE_ALIAS    (/export/home/orion/src/ansible-pfsense/library/pfsense_alias.py)

        Manage pfSense aliases

OPTIONS (= is mandatory):

= address
        The address of the alias
        [Default: None]

- descr
        Description
        [Default: None]

- detail
        Details for items
        [Default: None]

= name
        The name the alias
        [Default: None]

- state
        State in which to leave the alias
        (Choices: present, absent)[Default: present]

= type
        The type of the alias
        (Choices: host, port, urltable)[Default: hostrue]

- updatefreq
        Update frequency in days for urltable
        [Default: (null)]


AUTHOR: Orion Poplawski (@opoplawski)
        METADATA:
          status:
          - preview
          supported_by: community
        

EXAMPLES:
- name: Add adservers alias
  pfsense_alias:
    name: adservers
    address: 10.0.0.1 10.0.0.2
    state: present

- name: Remove adservers alias
  pfsense_rule:
    name: adservers
    state: absent
```
#pfsense-rule
```
> PFSENSE_RULE    (/export/home/orion/src/ansible-pfsense/library/pfsense_rule.py)

        Manage pfSense rules

OPTIONS (= is mandatory):

= action
        The action of the rule
        (Choices: pass, block, reject)[Default: pass]

- after
        Rule to go after, or "top"
        [Default: (null)]

- before
        Rule to go before, or "bottom"
        [Default: (null)]

- descr
        Description
        [Default: None]

= destination
        The destination address
        [Default: None]

- direction
        Direction floating rule applies to
        (Choices: any, in, out)[Default: (null)]

- disabled
        Is the rule disabled
        [Default: False]

- floating
        Is the rule floating
        (Choices: yes, no)[Default: (null)]

= interface
        The interface for the rule


- ipprotocol
        The IP protocol
        (Choices: inet)[Default: inet]

= name
        The name the rule
        [Default: None]

- protocol
        The protocol
        (Choices: any, tcp, udp, tcp/udp, icmp)[Default: any]

= source
        The source address
        [Default: None]

= state
        State in which to leave the rule
        (Choices: present, absent)[Default: present]

- statetype
        State type
        [Default: keep state]


AUTHOR: Orion Poplawski (@opoplawski)
        METADATA:
          status:
          - preview
          supported_by: community
        

EXAMPLES:
- name: "Add Internal DNS out rule"
  pfsense_rule:
    name: 'Allow Internal DNS traffic out'
    action: pass
    interface: lan
    ipprotocol: inet
    protocol: udp
    source: dns_int
    destination: any:53
    after: 'Allow proxies out'
    state: present
```
# operation

It works by editing /cf/conf/config.xml using xml.etree.ElementTree, then
calling the appropriate php update function via the pfsense php developer
shell.

Some formatting is lost, and CDATA items are converted to normal entries,
but so far no problems with that have been noted.

# license

GPLv3.0 or later
