# ansible-pfsense
WIP ansible module for managing pfsense firewalls.

This is the very early stages of a module to allow you to configure pfsense
firewalls with ansible.  There are currently the following modules:

* pfsense_alias for managing aliases
* pfsense_authserver_ldap for managing LDAP authentication servers
* pfsense_ca for managing Certificate Authorities
* pfsense_group for managing groups
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
# pfsense_authserver_ldap
```
> PFSENSE_AUTHSERVER_LDAP    (/export/home/orion/src/ansible-pfsense/library/pfsense_authserver_ldap.py)

        Manage pfSense LDAP authentication servers

OPTIONS (= is mandatory):

- attr_group
        LDAP Group naming attribute
        [Default: cn]

- attr_groupobj
        LDAP Group objectClass naming attribute
        [Default: posixGroup]

- attr_member
        LDAP Group member naming attribute
        [Default: member]

- attr_user
        LDAP User naming attribute
        [Default: cn]

- authcn
        Authentication containers added to basedn
        [Default: (null)]

- basedn
        Search base DN
        [Default: (null)]

- binddn
        Search bind DN
        [Default: (null)]

- bindpw
        Search bind password
        [Default: (null)]

- ca
        Certificat Authority
        [Default: (null)]

= host
        The hostname or IP address of the authentication server


= name
        The name of the authentication server


- port
        Port to connect to
        [Default: 389]

- protver
        LDAP protocol version
        (Choices: 2, 3)[Default: 3]

- scope
        Search scope
        (Choices: one, subtree)[Default: (null)]

= state
        State in which to leave the authentication server
        (Choices: present, absent)

- timeout
        Server timeout in seconds
        [Default: 25]

- transport
        Transport to use
        (Choices: tcp, starttls, ssl)[Default: (null)]


AUTHOR: Orion Poplawski (@opoplawski)
        METADATA:
          status:
          - preview
          supported_by: community
        

EXAMPLES:
- name: Add adservers authentication server
  pfsense_authserver_ldap:
    name: AD
    hostname: adserver.example.com
    port: 636
    transport: ssl
    scope: subtree
    basedn: dc=example,dc=com
    binddb: cn=bind,ou=Service Accounts,dc=example,dc=com
    bindpw: "{{ vaulted_bindpw }}"
    attr_user: samAccountName
    attr_member: memberOf
    attr_groupobj: group
    state: present

- name: Remove LDAP authentication server
  pfsense_authserver_ldap:
    name: AD
    state: absent
```
# pfsense_ca
```
> PFSENSE_CA    (/export/home/orion/src/ansible-pfsense/library/pfsense_ca.py)

        Manage pfSense LDAP Certificate Authorities

OPTIONS (= is mandatory):

= certificate
        The certificate for the Certificate Authority


= name
        The name of the Certificate Authority


= state
        State in which to leave the Certificate Authority
        (Choices: present, absent)


AUTHOR: Orion Poplawski (@opoplawski)
        METADATA:
          status:
          - preview
          supported_by: community
        

EXAMPLES:
- name: Add AD Certificate Authority
  pfsense_ca:
    name: AD CA
    certificate: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlGcXpDQ0E1T2dBd0lCQWdJUVBreXdY
dWRkZnFOR2h2aWExVDVYZ3pBTkJna3Foa2lHOXcwQkFRMEZBREJjDQpNUk13RVFZS0NaSW1pWlB5TEdRQkdSWURZMjl0T
VJRd0VnWUtDWkltaVpQeUxHUUJHUllFYm5keVlURVNNQkFHDQpDZ21TSm9tVDhpeGtBUmtXQW1Ga01Sc3dHUVlEVlFRRE
V4SmhaQzFCUkMxVFJVRlVWRXhGTURFdFEwRXdIaGNODQpNVFl3TkRBM01UWTBOVEE0V2hjTk1qWXdOREEzTVRZMU5UQTN
XakJjTVJNd0VRWUtDWkltaVpQeUxHUUJHUllEDQpZMjl0TVJRd0VnWUtDWkltaVpQeUxHUUJHUllFYm5keVlURVNNQkFH
Q2dtU0pvbVQ4aXhrQVJrV0FtRmtNUnN3DQpHUVlEVlFRREV4SmhaQzFCUkMxVFJVRlVWRXhGTURFdFEwRXdnZ0lpTUEwR
0NTcUdTSWIzRFFFQkFRVUFBNElDDQpEd0F3Z2dJS0FvSUNBUUNWdGM0dzBnY0h5aFkzRkVpUENVMmZLYXAyWnFHb0ROL1
VuRkVRRVBqZ1R4NmE4UEF5DQpqWjRMS2o2N1AybkRLTFA0ZVFQSFFzQmRkTVNneVl1RzdCQTlycmNCaFIzY0VlZ1RmNm9
CSjdKUG1zZTJTS3dtDQp6QnhT....
    state: present

- name: Remove AD Certificate Authority
  pfsense_ca:
    name: AD CA
    state: absent
```
# pfsense_group
```
> PFSENSE_GROUP    (/export/home/orion/src/ansible-pfsense/library/pfsense_group.py)

        Manage pfSense groups

OPTIONS (= is mandatory):

- descr
        Description of the group
        [Default: (null)]

- gid
        GID of the group
        [Default: next available GID]

= name
        The name of the group


- priv
        Priveleges to assign
        (Choices: page-all, user-shell-access)[Default: (null)]

- scope
        Scope of the group ('system' is 'Local')
        (Choices: system, remote)[Default: system]

= state
        State in which to leave the group
        (Choices: present, absent)


AUTHOR: Orion Poplawski (@opoplawski)
        METADATA:
          status:
          - preview
          supported_by: community
        

EXAMPLES:
- name: Add adservers group
  pfsense_group:
    name: Domain Admins
    description: Remote Admins
    scope: remote
    priv: [ 'page-all, 'user-shell-access' ]

- name: Remove group
  pfsense_group:
    name: Domain Admins
    state: absent
```
# pfsense-rule
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
