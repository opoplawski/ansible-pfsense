# Managing rules with lookup plugin

This example will demonstrate how to easily manage your rules configuration.

It is designed for people who have one to many pfSense firewalls to manage.

## General description

We want to configure multiple firewalls using only one set of rules, hosts and aliases.

Especially, we don't want to have to define several rules for each flow and firewall, when we have that kind of setup:
```
Host A <--> FW1 <--> ... <--> FW2 <--> Host B
```
If we want to allow Host A to connect to Host B, there should be only one definition of the flow for both firewalls.

We will write a file describing our network topology. The lookup plugin will parse that file and accordingly, will generate the required parameters for pfsense_aggregate to implement what is required on that topology.

## Setup description

Let's say we have a local network with:
```
- a laptop
- a station
- a DNS/proxy/ssh server
- an internet router
- a pfSense (FW1) providing IPsec VTI connectivity to another office
```


In the office, there is:
```
- a station
- some other DNS servers
- another pfSense (FW2)
```


Here are the rules we want to be defined on both FW1 and FW2:
```
- all icmp but icmp-redirect are allowed
- ospf is allowed on vti interfaces
- the local server must be able to do DNS requests to office
- the local server can ssh into anything to the office
- the local laptop can connect to anything to the office
- the office station must be able to connect to the local server on some ports (ssh, samba, squid, etc)
- the office station can ssh into the internet router
- the office station can vnc into the local station
- the office station can setup the pfSense
```

## pfSenses definition

First, we will define our pfsenses:
```
pfsenses:
  pf_fbor: {
    interfaces: {
      LAN:                { ip: 10.20.30.101/24, routed_networks: internet },
      IPsec:              { ip: 10.9.8.1/30, routed_networks: all_office_subnets },
      }
    }
  pf_office: {
    interfaces: {
      WAN:                { routed_networks: internet },
      LAN:                { ip: 10.100.200.101/24 },
      SERVERS:            { ip: 192.168.1.101/24 },
      IPsec:              { ip: 10.9.8.2/30, routed_networks: lan_fbor },
      }
    }
```

### Local pfSense

In this setup, as the pfSense is just an IPsec gateway there is no WAN interface. The LAN interface has the address 10.20.30.101 and this is the interface used to connect to internet.

We do not need to specify an IP address for the IPsec interface, as we need no rules on the VTI subnet. We set the routed networks threw this interface to the office subnets

The pfSense name must match the name used in playbook.

### Office pfSense

On the office pfSense, we are defining all required networks to access internet, the station, the servers and the remote ipsec.

## Aliases definition

Now, we will define all the aliases we want:
```
hosts_aliases:
  lan_fbor:             { ip: 10.20.30.0/24 }
  router_fbor:          { ip: 10.20.30.1 }
  station_fbor:         { ip: 10.20.30.2 }
  server_fbor:          { ip: 10.20.30.3 }
  laptop_fbor:          { ip: 10.20.30.4 }
  ssh_hosts:            { ip: server_fbor router_fbor }

  office_station:       { ip: 10.100.200.10 }
  office_ads:           { ip: 192.168.1.1 192.168.1.2 192.168.1.3 }

  all_office_subnets:   { ip: 192.168.0.0/16 10.0.0.0/8 172.16.0.0/16 }
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
    config_from_lan:        { src: lan_fbor,        dst: 10.20.30.101,        protocol: tcp,      dst_port: admin_ports }

  ICMP:
    block_redirects:        { src: any,             dst: any,                 protocol: icmp,     icmptype: redir, action: block, log: yes }
    allow_icmp:             { src: any,             dst: any,                 protocol: icmp,     icmptype: any, log: no }

  OSPF:
    ospf_vtis:              { src: ipsec_vtis,      dst: ipsec_vtis,          protocol: ospf,     log: no  }

  FROM_OFFICE:
    config_from_office:     { src: office_station,  dst: 10.20.30.101,        protocol: tcp,      dst_port: admin_ports }
    ssh_from_office:        { src: office_station,  dst: ssh_hosts,           protocol: tcp,      dst_port: ssh_port }
    proxy_from_office:      { src: office_station,  dst: server_fbor,         protocol: tcp,      dst_port: squid_port }
    smb_from_office:        { src: office_station,  dst: server_fbor,         protocol: tcp,      dst_port: smb_ports }
    vnc_from_office:        { src: office_station,  dst: station_fbor,        protocol: tcp,      dst_port: vnc_ports }

  TO_OFFICE:
    ssh_from_server:        { src: server_fbor,     dst: all_office_subnets,  protocol: tcp,      dst_port: ssh_port }
    dns_from_server:        { src: server_fbor,     dst: office_ads,          protocol: tcp/udp,  dst_port: dns_port }
    laptop_to_office:       { src: laptop_fbor,     dst: all_office_subnets,  protocol: any }
```

All the rules are logged, unless specified othewise.

## Result:

### local

[[https://github.com/opoplawski/ansible-pfsense/blob/master/examples/lookup/images/local_LAN.PNG]]
[[https://github.com/opoplawski/ansible-pfsense/blob/master/examples/lookup/images/local_IPSEC.PNG]]

### office

[[https://github.com/opoplawski/ansible-pfsense/blob/master/examples/lookup/images/office_LAN.PNG]]
[[https://github.com/opoplawski/ansible-pfsense/blob/master/examples/lookup/images/office_IPSEC.PNG]]

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

## TODO

The lookup plugin is still a work-in-progress. The code is quite ugly on some parts and it has a lot of limitations.
