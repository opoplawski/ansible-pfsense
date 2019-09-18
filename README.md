# ansible-pfsense
WIP ansible module for managing pfsense firewalls.

This is the very early stages of a module to allow you to configure pfsense
firewalls with ansible.

# configuration

The python interpreter is in a non-standard location on pfSense, so you will
need to set:

 ansible_python_interpreter: /usr/local/bin/python2.7

# modules
There are currently the following modules:

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

- address
        The address of the alias. Use a space separator for multiple values
        [Default: None]

- descr
        The description of the alias
        [Default: None]

- detail
        The descriptions of the items. Use || separator between items
        [Default: None]

= name
        The name of the alias


= state
        State in which to leave the alias
        (Choices: present, absent)[Default: present]

- type
        The type of the alias
        (Choices: host, network, port, urltable, urltable_ports)[Default: None]

- updatefreq
        Update frequency in days for urltable
        [Default: None]


AUTHOR: Orion Poplawski (@opoplawski), Frederic Bor (@f-bor)
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
  pfsense_alias:
    name: adservers
    state: absent

RETURN VALUES:


commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["create alias 'adservers', type='host', address='10.0.0.1 10.0.0.2'", "update alias 'one_host' set address='10.9.8.7'", "delete alias 'one_alias'"]
diff:
    description: a pair of dicts, before and after, with alias settings before and after task run
    returned: always
    type: dict
    sample: {}
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

        Manage pfSense Certificate Authorities

OPTIONS (= is mandatory):

= certificate
        The certificate for the Certificate Authority.  This can be in PEM form or Base64
        encoded PEM as a single string (which is how pfSense stores it).


- crl
        The Certificate Revocation List for the Certificate Authority.  This can be in PEM
        form or Base64 encoded PEM as a single string (which is how pfSense stores it).
        [Default: (null)]

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
    certificate: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlGcXpDQ0E1T2dB...
    crl: |
      -----BEGIN X509 CRL-----
      MIICazCCAVMCAQEwDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAxMPTldSQSBPcGVu
      ...
      r0hUUy3w1trKtymlyhmd5XmYzINYp8p/Ws+boST+Fcw3chWTep/J8nKMeKESO0w=
      -----END X509 CRL-----
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
        GID of the group.
        Will use next available GID if not specified.
        [Default: (null)]

= name
        The name of the group


- priv
        A list of privileges to assign.
        Allowed values include page-all, user-shell-access.
        [Default: (null)]
        type: list

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
    priv: [ 'page-all', 'user-shell-access' ]

- name: Remove group
  pfsense_group:
    name: Domain Admins
    state: absent
```
# pfsense_rule
```
> PFSENSE_RULE    (/export/home/orion/src/ansible-pfsense/library/pfsense_rule.py)

        Manage pfSense rules

OPTIONS (= is mandatory):

- ackqueue
        QOS acknowledge queue
        [Default: (null)]

= action
        The action of the rule
        (Choices: pass, block, reject)[Default: pass]

- after
        Rule to go after, or "top"
        [Default: (null)]

- before
        Rule to go before, or "bottom"
        [Default: (null)]

= destination
        The destination address, in [!]{IP,HOST,ALIAS,any,(self)}[:port], IP:INTERFACE or NET:INTERFACE format
        [Default: None]

- direction
        Direction floating rule applies to
        (Choices: any, in, out)[Default: (null)]

- disabled
        Is the rule disabled
        [Default: False]
        type: bool

- floating
        Is the rule floating
        [Default: (null)]
        type: bool

- in_queue
        Limiter queue for traffic coming into the chosen interface
        [Default: (null)]

= interface
        The interface for the rule


- ipprotocol
        The IP protocol
        (Choices: inet, inet46, inet6)[Default: inet]

- log
        Log packets matched by rule
        [Default: (null)]
        type: bool

= name
        The name the rule
        [Default: None]

- out_queue
        Limiter queue for traffic leaving the chosen interface
        [Default: (null)]

- protocol
        The protocol
        (Choices: any, tcp, udp, tcp/udp, icmp)[Default: any]

- queue
        QOS default queue
        [Default: (null)]

= source
        The source address, in [!]{IP,HOST,ALIAS,any,(self)}[:port], IP:INTERFACE or NET:INTERFACE format
        [Default: None]

- state
        State in which to leave the rule
        (Choices: present, absent)[Default: present]

- statetype
        State type
        (Choices: keep state, sloppy state, synproxy state, none)[Default: keep state]


AUTHOR: Orion Poplawski (@opoplawski), Frederic Bor (@f-bor)
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
# pfsense_rule_separator
```
> PFSENSE_RULE_SEPARATOR    (/home/fbor/ansible/lib/ansible/modules/networking/pfsense/pfsense_rule_separator.py)

        Manage pfSense rule separators

OPTIONS (= is mandatory):

- after
        Rule to go after, or "top"
        [Default: (null)]

- before
        Rule to go before, or "bottom"
        [Default: (null)]

- color
        The separator's color
        (Choices: info, warning, danger, success)[Default: info]

- floating
        Is the rule on floating tab
        [Default: (null)]
        type: bool

= interface
        The interface for the separator


= name
        The name of the separator


= state
        State in which to leave the separator
        (Choices: present, absent)[Default: present]


AUTHOR: Frederic Bor (@f-bor)
        METADATA:
          status:
          - preview
          supported_by: community


EXAMPLES:
- name: Add rule separator voip
  pfsense_rule_separator:
    name: voip
    state: present
    interface: lan_100

- name: Remove rule separator voip
  pfsense_rule_separator:
    name: voip
    state: absent
    interface: lan_100

RETURN VALUES:


commands:
    description: the set of separators commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: success
    type: list
    sample: ["create rule_separator 'SSH', interface='lan', color='info'", "update rule_separator 'SSH' set color='warning'", "delete rule_separator 'SSH'"]
```
# pfsense_aggregate
```
> PFSENSE_AGGREGATE    (/export/home/orion/src/ansible-pfsense/library/pfsense_aggregate.py)

        Manage multiple pfSense rules or aliases

OPTIONS (= is mandatory):

- aggregated_aliases
        Dict of aliases to apply on the target
        [Default: (null)]

- aggregated_rule_separators
        Dict of rule separators to apply on the target
        [Default: (null)]

- aggregated_rules
        Dict of rules to apply on the target
        [Default: (null)]

- aggregated_vlans
        Dict of vlans to apply on the target
        [Default: (null)]

- purge_aliases
        delete all the aliases that are not defined into aggregated_aliases
        [Default: False]
        type: bool

- purge_rule_separators
        delete all the rule separators that are not defined into aggregated_rule_separators
        [Default: False]
        type: bool

- purge_rules
        delete all the rules that are not defined into aggregated_rules
        [Default: False]
        type: bool

- purge_vlans
        delete all the vlans that are not defined into aggregated_vlans
        [Default: False]
        type: bool


NOTES:
      * aggregated_aliases and aggregated_rules use the same options definitions than pfsense_alias and pfsense_rule modules.

AUTHOR: Frederic Bor (@f-bor)
        METADATA:
          status:
          - preview
          supported_by: community


EXAMPLES:
- name: "Add three aliases, six rules, four separators, and delete everything else"
  pfsense_aggregate:
    purge_aliases: true
    purge_rules: true
    purge_rule_separators: true
    aggregated_aliases:
      - { name: port_ssh, type: port, address: 22, state: present }
      - { name: port_http, type: port, address: 80, state: present }
      - { name: port_https, type: port, address: 443, state: present }
    aggregated_rules:
      - { name: "allow_all_ssh", source: any, destination: "any:port_ssh", protocol: tcp, interface: lan, state: present }
      - { name: "allow_all_http", source: any, destination: "any:port_http", protocol: tcp, interface: lan, state: present }
      - { name: "allow_all_https", source: any, destination: "any:port_https", protocol: tcp, interface: lan, state: present }
      - { name: "allow_all_ssh", source: any, destination: "any:port_ssh", protocol: tcp, interface: wan, state: present }
      - { name: "allow_all_http", source: any, destination: "any:port_http", protocol: tcp, interface: wan, state: present }
      - { name: "allow_all_https", source: any, destination: "any:port_https", protocol: tcp, interface: wan, state: present }
    aggregated_rule_separators:
      - { name: "SSH", interface: lan, state: present, before: allow_all_ssh }
      - { name: "HTTP", interface: lan, state: present, before: allow_all_http }
      - { name: "SSH", interface: wan, state: present, before: allow_all_ssh }
      - { name: "HTTP", interface: wan, state: present, before: allow_all_http }

RETURN VALUES:


result_aliases:
    description: the set of aliases commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: success
    type: list
    sample: ["create alias 'adservers', type='host', address='10.0.0.1 10.0.0.2'", "update alias 'one_host' set address='10.9.8.7'", "delete alias 'one_alias'"]
aggregated_rules:
    description: final set of rules
    returned: success
    type: list
    sample: []
result_separators:
    description: the set of separators commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: success
    type: list
    sample: ["create rule_separator 'SSH', interface='lan', color='info'", "update rule_separator 'SSH' set color='warning'", "delete rule_separator 'SSH'"]
result_vlans:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: success
    type: list
    sample: ["create vlan 'mvneta.100', descr='voice', priority='5'", "update vlan 'mvneta.100', set priority='6'", "delete vlan 'mvneta.100'"]
```
# pfsense_user
```
> PFSENSE_USER    (/export/home/orion/src/ansible-pfsense/library/pfsense_user.py)

        Manage pfSense users

  * This module is maintained by The Ansible Community
OPTIONS (= is mandatory):

- authorizedkeys
        Contents of ~/.ssh/authorized_keys.  Can be base64 encoded.
        [Default: (null)]

- descr
        Description of the user
        [Default: (null)]

- groupname
        Group of the user.
        [Default: (null)]

= name
        The name of the user


- password
        bcrypt encrypted password of the user.
        [Default: (null)]

- priv
        A list of privileges to assign.
        Allowed values include page-all, user-shell-access.
        [Default: (null)]
        type: list

- scope
        Scope of the user ('user' is a normal user)
        (Choices: user, system)[Default: user]

- state
        State in which to leave the user
        (Choices: present, absent)[Default: present]

- uid
        UID of the user.
        Will use next available UID if not specified.
        [Default: (null)]


AUTHOR: Orion Poplawski (@opoplawski)
        METADATA:
          status:
          - preview
          supported_by: community


EXAMPLES:

- name: Add operator user
  pfsense_user:
    name: operator
    descr: Operator
    scope: user
    groupname: Operators
    priv: [ 'page-all', 'user-shell-access' ]

- name: Remove user
  pfsense_user:
    name: operator
    state: absent


RETURN VALUES:
```
# pfsense_vlan
```
> PFSENSE_VLAN    (/home/fbor/ansible/lib/ansible/modules/networking/pfsense/pfsense_vlan.py)

        Manage pfSense vlans

OPTIONS (= is mandatory):

- descr
        The description of the vlan
        [Default: None]

= interface
        The interface on which to declare the vlan. Friendly name (assignments) can be used.


- priority
        802.1Q VLAN Priority code point. Must be between 0 and 7.
        [Default: (null)]

= state
        State in which to leave the vlan
        (Choices: present, absent)[Default: present]

= vlan_id
        The vlan tag. Must be between 1 and 4094.



AUTHOR: Frederic Bor (@f-bor)
        METADATA:
          status:
          - preview
          supported_by: community


EXAMPLES:
- name: Add voice vlan
  pfsense_vlan:
    interface: mvneta0
    vlan_id: 100
    descr: voice
    priority: 5
    state: present

- name: Remove voice vlan
  pfsense_vlan:
    interface: mvneta0
    vlan_id: 100

RETURN VALUES:


commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["create vlan 'mvneta.100', descr='voice', priority='5'", "update vlan 'mvneta.100', set priority='6'", "delete vlan 'mvneta.100'"]
```
# pfsense_interface
```
> PFSENSE_INTERFACE    (/home/fbor/ansible/lib/ansible/modules/network/pfsense/pfsense_interface.py)

        Manage pfSense interfaces

  * This module is maintained by The Ansible Community
OPTIONS (= is mandatory):

- blockbogons
        Blocks traffic from reserved IP addresses (but not RFC 1918) or not yet assigned by IANA.
        [Default: (null)]
        type: bool

- blockpriv
        Blocks traffic from IP addresses that are reserved for private networks.
        [Default: (null)]
        type: bool

- create_ipv4_gateway
        Create the specified IPv4 gateway if it does not exist
        [Default: (null)]
        type: bool

= descr
        Description (name) for the interface.

        type: str

= enable
        Enable interface.

        type: bool

= interface
        Network port to which assign the interface.

        type: str

- ipv4_address
        IPv4 Address.
        [Default: (null)]
        type: str

- ipv4_gateway
        IPv4 gateway for this interface.
        [Default: (null)]
        type: str

- ipv4_gateway_address
        IPv4 gateway address to set on the interface
        [Default: (null)]
        type: str

- ipv4_prefixlen
        IPv4 subnet prefix length.
        [Default: 24]
        type: int

- ipv4_type
        IPv4 Configuration Type.
        (Choices: none, static)[Default: none]
        type: str

- mac
        Used to modify ("spoof") the MAC address of this interface.
        [Default: (null)]
        type: str

- mss
        MSS clamping for TCP connections.
        [Default: (null)]
        type: int

- mtu
        Maximum transmission unit
        [Default: (null)]
        type: int

- speed_duplex
        Set speed and duplex mode for this interface.
        [Default: autoselect]
        type: str

= state
        State in which to leave the interface.
        (Choices: present, absent)[Default: present]
        type: str


NOTES:
      * EXPERIMENTAL MODULE, not suited for production.


AUTHOR: Frederic Bor (@f-bor)
        METADATA:
          status:
          - preview
          supported_by: community


EXAMPLES:

- name: Add interface
  pfsense_interface:
    descr: voice
    interface: mvneta0.100
    enable: True
    ipv4_type: static
    ipv4_address: 10.20.30.40
    ipv4_prefixlen: 24

- name: Remove interface
  pfsense_interface:
    state: absent
    descr: voice
    interface: mvneta0.100


RETURN VALUES:

commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["create interface 'voice', port='mvneta0.100', ipv4_type='static', ipv4_address='10.20.30.40', ipv4_prefixlen='24', speed_duplex='autoselect', enable='True'", "delete interface 'voice'"]
```
# operation

It works by editing /cf/conf/config.xml using xml.etree.ElementTree, then
calling the appropriate php update function via the pfsense php developer
shell.

Some formatting is lost, and CDATA items are converted to normal entries,
but so far no problems with that have been noted.

# license

GPLv3.0 or later
