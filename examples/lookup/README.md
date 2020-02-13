# Managing rules with lookup plugin

This example will demonstrate how to easily manage your rules configuration.

It is designed for people who have one to many pfSense firewalls to manage.

## General description

We want to configure multiple firewalls using only one set of pfSense, rules, and aliases.

Especially, we don't want to have to define several rules for each flow and firewall, when we have that kind of setup:
```
Host A <--> FW1 <--> ... <--> FW2 <--> Host B
```
If we want to allow Host A to connect to Host B, there should be only one definition of the flow for both firewalls.

We will write a file describing our network topology. The lookup plugin will parse that file and accordingly, will generate the required parameters for pfsense_aggregate to implement what is specified with that topology.

## Setup description

Let's say we have a network in Paris with:
```
- an internet router
- a pfSense (FW1) providing IPsec VTI connectivity to another office, in Fargo
- a laptop
- a station
- a DNS/proxy/ssh server
```


And in Fargo, there is:
```
- a pfSense (FW2), providing IPsec VTI connectivity to Paris
- a station
- some DNS servers
- access to other privates networks
```


Here are the rules we want to be defined on both FW1 and FW2:
```
- all icmp but icmp-redirect are allowed
- ospf is allowed on vti interfaces
- the Paris server must be able to do DNS requests to Fargo private DNS servers
- the Paris server can ssh into anything to Fargo office
- the Paris laptop can connect to anything to Fargo office
- the Fargo station must be able to connect to the Paris server on some ports (ssh, samba, squid, etc)
- the Fargo station can ssh into the Paris internet router
- the Fargo station can vnc into the Paris station
- the Fargo station can setup the Paris pfSense
```

## pfSenses definition

First, we will define our pfsenses:
```
pfsenses:
  pf_fargo: {
    interfaces: {
      WAN:                { remote_networks: internet },
      LAN:                { ip: 10.100.200.101/24 },
      SERVERS:            { ip: 192.168.1.101/24 },
      IPsec:              { ip: 10.9.8.2/30, remote_networks: paris_lan },
      }
    }
  pf_paris: {
    interfaces: {
      LAN:                { ip: 10.20.30.101/24, remote_networks: internet },
      IPsec:              { ip: 10.9.8.1/30, remote_networks: all_fargo_subnets },
      }
    }
```

### Fargo pfSense

On the Fargo pfSense, we are defining all networks used to access internet, the station, the servers and for the remote ipsec.

We need to specify an IP address for the IPsec interface, as we need rules for OSPF. We set the routed networks threw this interface to the Paris subnet

The pfSense name must match the name used in playbook.

### Paris pfSense

In this setup, as the pfSense is just an IPsec gateway there is no WAN interface.

The LAN interface is used to connect to internet.

We declare the Fargo subnets on the IPsec interface.

## Aliases definition

Now, we will define all the aliases we need:
```
hosts_aliases:
  paris_lan:            { ip: 10.20.30.0/24 }
  paris_router:         { ip: 10.20.30.1 }
  paris_station:        { ip: 10.20.30.2 }
  paris_server:         { ip: 10.20.30.3 }
  paris_laptop:         { ip: 10.20.30.4 }
  paris_ssh_hosts:      { ip: paris_server paris_router }

  fargo_station:        { ip: 10.100.200.10 }
  fargo_ads:            { ip: 192.168.1.1 192.168.1.2 192.168.1.3 }

  all_fargo_subnets:    { ip: 192.168.0.0/16 10.0.0.0/8 172.16.0.0/16 }
  internet:             { ip: 0.0.0.0/0 }
  ipsec_vtis:           { ip: 10.9.8.1 10.9.8.2 }

ports_aliases:
  admin_ports:          { port: 22 80 443 }
  dns_port:             { port: 53 }
  ipsec_ports:          { port: 500 4500 }
  squid_port:           { port: 3128 }
  ssh_port:             { port: 22 }
  smb_ports:            { port: 135 137 139 445 }
  vnc_ports:            { port: 5900-5901 }
```

## Rules definition
Finally, here are the rules:
```
rules:
  options: { log: yes }

  CONFIG:
    config_from_lan:        { src: paris_lan,       dst: 10.20.30.101,        protocol: tcp,      dst_port: admin_ports }

  ICMP:
    block_redirects:        { src: any,             dst: any,                 protocol: icmp,     icmptype: redir, action: block, log: yes }
    allow_icmp:             { src: any,             dst: any,                 protocol: icmp,     icmptype: any, log: no }

  OSPF:
    ospf_vtis:              { src: ipsec_vtis,      dst: ipsec_vtis,          protocol: ospf,     log: no  }

  FROM_FARGO:
    config_from_fargo:      { src: fargo_station,   dst: 10.20.30.101,        protocol: tcp,      dst_port: admin_ports }
    ssh_from_fargo:         { src: fargo_station,   dst: paris_ssh_hosts,     protocol: tcp,      dst_port: ssh_port }
    proxy_from_fargo:       { src: fargo_station,   dst: paris_server,        protocol: tcp,      dst_port: squid_port }
    smb_from_fargo:         { src: fargo_station,   dst: paris_server,        protocol: tcp,      dst_port: smb_ports }
    vnc_from_fargo:         { src: fargo_station,   dst: paris_station,       protocol: tcp,      dst_port: vnc_ports }

  TO_FARGO:
    ssh_from_server:        { src: paris_server,    dst: all_fargo_subnets,   protocol: tcp,      dst_port: ssh_port }
    dns_from_server:        { src: paris_server,    dst: fargo_ads,           protocol: tcp/udp,  dst_port: dns_port }
    laptop_to_fargo:        { src: paris_laptop,    dst: all_fargo_subnets,   protocol: any }
```

All the rules are logged, unless specified otherwise.

## Result:

All the required aliases and rules on each firewall are defined where they need to be.

### Fargo

![fargo_aliases](https://github.com/opoplawski/ansible-pfsense/blob/master/examples/lookup/images/fargo_aliases.png)
![fargo_lan](https://github.com/opoplawski/ansible-pfsense/blob/master/examples/lookup/images/fargo_lan.png)
![fargo_ipsec](https://github.com/opoplawski/ansible-pfsense/blob/master/examples/lookup/images/fargo_ipsec.png)

### Paris

![paris_aliases](https://github.com/opoplawski/ansible-pfsense/blob/master/examples/lookup/images/paris_aliases.png)
![paris_lan](https://github.com/opoplawski/ansible-pfsense/blob/master/examples/lookup/images/paris_lan.png)
![paris_ipsec](https://github.com/opoplawski/ansible-pfsense/blob/master/examples/lookup/images/paris_ipsec.png)

## Files

* hosts: the Ansible file for pfsense hosts
* pfsense_definitions.yaml: our rules & network topology
* setup_all_rules.yml: the playbook used to setup all the pfsenses

## Installation

You don't need to copy any files. Just adapt your ansible hosts file like the one
provided or adapt the yaml file with your hosts.

To run the test in check mode for all the 2 firewalls, just go into your ansible-pfsense
directory and run:

```
ansible-playbook -C -v examples/lookup/setup_all_rules.yml
```

You can run the plugin alone to see what is generated for the pfsense_aggregate module:
```
python ./lookup_plugins/pfsense.py examples/lookup/pfsense_definitions.yaml pf_paris
```

You can also add a rule name to just see what is generated for that rule:
```
python ./lookup_plugins/pfsense.py examples/lookup/pfsense_definitions.yaml pf_paris ssh_from_fargo
```

## TODO

The lookup plugin is still a work-in-progress. The code is quite ugly on some parts and it has a lot of limitations.
