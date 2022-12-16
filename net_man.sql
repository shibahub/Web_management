create database net_man;
use net_man;
Create table Icmp(
    ip varchar(255), 
    icmp_in varchar(255), 
    icmp_in_rep varchar(255), 
    icmp_out varchar(255), 
    icmp_out_rep varchar(255), 
    times varchar(255),
    PRIMARY KEY (ip)
);
Create table System_info(
    ip varchar(255), 
    OID varchar(255), 
    INFO varchar(255), 
    times varchar(255),
    PRIMARY KEY (ip)
);
Create table IP_table(
    ip varchar(255), 
    nexthop varchar(255), 
    destination varchar(255),
    subnet  varchar(255),
    times varchar(255),
    PRIMARY KEY (ip)
);
