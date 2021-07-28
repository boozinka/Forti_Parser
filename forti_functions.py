#!/usr/bin/env python

# Reads a Fortigate 'show' output file and produces the following complex data
# data structures in the form of a dictionaries:
# 'Address Dictionary', Address Group Dictionary, IPPool Dictionary, VIP Dictionary,
# 'Services Dictionary', 'Services Group Dictionary' and 'Policy Dictionary'


import os
import sys
import re
import socket
import pathlib
from pprint import pprint


def sub_menu2():
    # Setup 2. Sub-Menu Loop

    os.system('cls')
    sm2_choice = None
    while sm2_choice != "0":
        print(
            """
            Work With Policies Sub-Menu

            0 - Back to Main Menu
            1 - Print/save the policies associated with the imported policy id's
            2 - Delete the polices in your list from the original import 
            3 - Print/save all IPPOOL's (SNAT's) associated with the imported policy id's
            4 - Print/save a DNS amendment form to decommission elements of policies
            """
        )

        sm2_choice = input("Choice: ")
        print()
        return sm2_choice


def set_working_dir():
    # Welcome screen and setup for initial parameters including the working directory and input file

    working_dir = ""

    directory_input = False
    while not directory_input:
        working_dir = pathlib.Path(input("Please enter the directory path where all files"
                                         " will be read from and written to: "))
        directory_input = pathlib.Path.exists(working_dir)
        if not directory_input:
            input("Invalid path or directory, press enter to try again. ")
            os.system('cls')
    return working_dir


def get_file(working_dir, message):
    # Welcome screen and setup for initial parameters including the working directory and input file

    my_file = None
    file_input = False

    while not file_input:
        os.system('cls')
        print("\nThe specified file must be comma separated")
        file_name = input(message)
        my_file = working_dir / file_name
        file_input = pathlib.Path.exists(my_file)
        if not file_input:
            input("Invalid file name or file does not exist, press enter to try again. ")
    return my_file


def read_file(my_file):
    # Open file and read it as a string)

    with open(my_file) as analyser_log:
        analyser_log = analyser_log.read()
    return analyser_log

def read_file_lines(my_file):
    # Open file and read it as a string)

    with open(my_file) as forti_output:
        forti_output = forti_output.readlines()
    return forti_output


def write_dns_dict(fqdn_dict):
    # write the hostnames and IP addresses to a .csv file

    filename = input("\n\nPlease enter the name of the file you wish to save without the file extension: ")
    filename = filename+'.csv'
    with open(filename, 'w') as file:
        for keys,values in fqdn_dict.items():
            try:
                host_domain = keys.split(".", 1)
                host = host_domain[0]
                domain = host_domain[1]
            except IndexError:
                # catch no domain
                domain = "Unresolved"
            fqdn_triple = [host, ",", domain, ",", values, "\n"]
            file.writelines(fqdn_triple)


def write_pol_dict(pol_dict, pol_id_list):
    # write the policy attributes to a .csv file

    filename = input("\n\nPlease enter the name of the file you wish to save without the file extension: ")
    filename = filename+'.csv'
    with open(filename, 'w') as file:
        
        # Write header
        header = ['policy id', ',', 'label', ',', 'object type', ',', 'object name', ',', 'ip address', '\n']
        file.writelines(header)
        
        for pol_id in pol_id_list:
            # Assign the ippools and vips dictionaries to new varibles
            ippools_dict = pol_dict[pol_id]['ippools']
            vips_dict = pol_dict[pol_id]['dstaddr']['vips']
            addr_dict = pol_dict[pol_id]['dstaddr']['addr']
            addrgrp_dict = pol_dict[pol_id]['dstaddr']['addrgrps']
            label = pol_dict[pol_id]['labels']['label']
        
            # Write the ippool mappings out
            for ippool_name, ippool_addr in ippools_dict.items():
                ippool_line = [pol_id, ',', label, ',', 'ippool', ',', ippool_name, ',', ippool_addr, '\n']
                file.writelines(ippool_line)
            
            # Write the vip mappings out
            for vip_name, vip_addr in vips_dict.items():
                vip_line = [pol_id, ',', label, ',', 'vip', ',', vip_name, ',', vip_addr, '\n']
                file.writelines(vip_line)

            # Write the address mappings out
            for addr_name, addr in addr_dict.items():
                addr_line = [pol_id, ',', label, ',', 'addr', ',', addr_name, ',', addr, '\n']
                file.writelines(addr_line)

            # Write the address group object mappings out
            for addrgrp_name, members in addrgrp_dict.items():
                addrgrp_line = [pol_id, ',', label, ',', 'addrgrp', ',', addrgrp_name, '\n']
                file.writelines(addrgrp_line)
                for name, ip_addr in members.items():
                    member_line = [pol_id, ',', label, ',', 'grp_member', ',', name, ',', ip_addr, '\n']
                    file.writelines(member_line)


def find_objects(pol_dict, obj_list):

    for object in obj_list:
        for pol_id, values in pol_dict.items():
            if object in values['dstaddr']['addr']:
                print(pol_id, '- Address:', object)
            if object in values['dstaddr']['addrgrps']:
                print(pol_id, '- Address Group:', object)
            if object in values['dstaddr']['vips']:
                print(pol_id, '- VIP:', object)
            if object in values['ippools']:
                print(pol_id, '- IPool:', object)


def write_pol_num(pol_dict):
    # write the policy numbers to a .csv file

    filename = input("\n\nPlease enter the name of the file you wish to save without the file extension: ")
    filename = filename+'.csv'
    with open(filename, 'w') as file:
        
        # Write header
        header = ['policy id\n']
        file.writelines(header)
        print('\n\n')
        for pol_num, attributes in pol_dict.items():
            if len(attributes['src_intf']) > 1:
                print(pol_num, ': ', attributes['src_intf'])
            if 'TR-ECN-102' in attributes['src_intf']:
                pol_line = [pol_num, '\n']
                file.writelines(pol_line)


def vip_lookup(vip_dict, vip_list):
    # Find vips in a list, resolves and writes them

    filename = input("\n\nPlease enter the name of the file you wish to save without the file extension: ")
    filename = filename+'.csv'
    with open(filename, 'w') as file:
        
        # Write header
        header = ['vip name', ',', 'ip address', '\n']
        file.writelines(header)

        for vip in vip_list:
            if vip in vip_dict:
                for dnat_ip, real_ip in vip_dict[vip].items():
                    vip_line = [vip, ',', dnat_ip, '\n']
                    file.writelines(vip_line)

def addr_lookup(addr_dict, addr_list):
    # Find vips in a list, resolves and writes them

    filename = input("\n\nPlease enter the name of the file you wish to save without the file extension: ")
    filename = filename+'.csv'
    with open(filename, 'w') as file:
        
        # Write header
        header = ['addr name', ',', 'ip address', '\n']
        file.writelines(header)

        for addr in addr_list:
            if addr in addr_dict:
                addr_line = [addr, ',', addr_dict[addr], '\n']
                file.writelines(addr_line)


def write_objects(addr_dict, addrgrp_dict, vip_dict, ippool_dict, object_list):
    # Find Objects and write them to a file with their object type

    filename = input("\n\nPlease enter the name of the file you wish to save without the file extension: ")
    filename = filename+'.csv'
    with open(filename, 'w') as file:
        
        # Write header
        header = ['Object Type', ',', 'Object Name', ',', 'Object Value', '\n']
        file.writelines(header)

        for object in object_list:

            if object in addr_dict:
                addr_line = ['Address Object', ',', object, ',', addr_dict[object], '\n']
                file.writelines(addr_line)
            elif object in addrgrp_dict:
                addrgrp_line = ['Address Group Object', ',', object, '\n']
                file.writelines(addrgrp_line)
            elif object in vip_dict:
                for dnat_ip, real_ip in vip_dict[object].items():
                    vip_line = ['VIP Object', ',', object, ',', dnat_ip, '\n']
                    file.writelines(vip_line)
            elif object in ippool_dict:
                ippool_line = ['IPPOOL Object', ',', object, ',', ippool_dict[object], '\n']
                file.writelines(ippool_line)
            else:
                file.writelines('unknown,unknown,unknown\n')


def valid_ip(ipaddr):
    # checks if it is a valid IP address

    pattern = re.compile(r"\A(?:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})?\Z")
    valid = re.match(pattern, ipaddr)
    if valid:
        return True


def remove_duplicates(my_list):
    # removes duplicate entries from a list

    my_set = set(my_list)  # Convert list to a set
    my_set |= my_set  # Remove Duplicate entries
    my_list = list(my_set)  # Convert back to a list
    return my_list


def remove_whitespace(my_list):
    # remove the whitespace and "\n" from the beginning and end of each string element

    new_list = []
    for i in my_list:
        new_list.append(i.strip())
    return new_list


def print_dict(fqdn_dict):
    # Print the FQDN Dictionary formatted on the screen

    print(f'{"HOSTNAME":<35} {" "*5:5} {"DOMAIN":<20} {" "*5:5} {"IP ADDRESS":>15}')
    print(f'{"-"*35:35} {" "*5:5} {"-"*20:20} {" "*5:5} {"-"*15:15}')
    for keys,values in fqdn_dict.items():
        try:
            host_domain = keys.split(".", 1)
            host = host_domain[0]
            domain = host_domain[1]
        except IndexError:
            # catch no domain
            domain = "Unresolved"
        # Print table of Hostnames, Domains and their IP Addresses.
        print(f'{host:<35} {" "*5:5} {domain:<20} {" "*5:5} {values:>15}')
    print()


def resolve_nested_grps(addrgrp_dict):
    # This function iterates over and updates the dictionary to resolve
    # nested object groups defined in same dictionary
    
    # Make a copy of the dictionary, to fill in blank values with nested object values
    tmp_addrgrp_dict = addrgrp_dict.copy()
    # Use 'list' to avoid "RuntimeError: dictionary changed size during iteration".
    for top_grp, nested_grp in list(tmp_addrgrp_dict.items()):
        for grp, value in list(nested_grp.items()):
            if not value:
                del addrgrp_dict[top_grp][grp]
                try:
                    addrgrp_dict[top_grp].update(tmp_addrgrp_dict[grp])
                except KeyError:
                    print(top_grp, 'Error for', grp)
                
    return addrgrp_dict            


def capture_ippools(fw_config_list):
    # Builds a dictionary of ippools and their IP addresses

    # Intialise varibles
    start_pattern = re.compile(r"^config firewall ippool$")
    end_pattern = re.compile(r"^end$")
    ippool_dict = {}
    capture = False

    # Iterate through entire firewall configuration list
    for line in fw_config_list:
        # Identify start and end points for capturing ippools
        if re.match(start_pattern, line):
            capture = True
            continue
        elif re.match(end_pattern, line):
            capture = False

        # Once capture flag is True
        if capture:
            # Capture line containing ippool name
            if 'edit' in line:
                key_cut = line.split('"')
                ippool_name = key_cut[1]
            # Capture line containing ippool ip address
            elif 'set startip' in line:
                val_cut = line.split()
                ippool_ipaddr = val_cut[2]
                ippool_ipaddr = str(ippool_ipaddr)+'/32'
            # At the end on each vip entry update the main dictionary
            elif 'next' in line:
                ippool_dict.update({ippool_name: ippool_ipaddr})
    return ippool_dict


def capture_vips(fw_config_list):
    # Builds a dictionary of vips and their IP addresses

    # Intialise varibles
    start_pattern = re.compile(r"^config firewall vip$")
    end_pattern = re.compile(r"^end$")
    vip_dict = {}
    capture = False

    # Iterate through entire firewall configuration list
    for line in fw_config_list:
        # Identify start and end points for capturing vips
        if re.match(start_pattern, line):
            capture = True
            continue
        elif re.match(end_pattern, line):
            capture = False

        # Once capture flag is True
        if capture:
            # Capture vip name
            if 'edit' in line:
                key_cut = line.split('"')
                vip_name = key_cut[1]
            # Capture dnat ip address
            elif 'set extip' in line:
                dnat_cut = line.split()
                dnat_ip = dnat_cut[2]
                dnat_ip = str(dnat_ip)+'/32'
            # Capture real/mapped ip address
            elif 'set mappedip' in line:
                real_cut = line.split('"')
                real_ip = real_cut[1]
                real_ip = str(real_ip)+'/32'
            # At the end on each vip entry update the main dictionary
            elif 'next' in line:
                vip_dict.update({vip_name: {dnat_ip: real_ip}})
    return vip_dict


def capture_fw_addr(fw_config_list):
    # Builds a dictionary of IP address objects

    # Intialise varibles
    start_pattern = re.compile(r"^config firewall address$")
    end_pattern = re.compile(r"^end$")
    fw_addr_dict = {}
    capture = False
    ignore = False
    prefix = ''

    # Iterate through entire firewall configuration list
    for line in fw_config_list:
        # Identify start and end points for capturing vips
        if re.match(start_pattern, line):
            capture = True
            continue
        elif re.match(end_pattern, line):
            capture = False

        # Once capture flag is True
        if capture:
            # Capture subnet address name
            if 'edit' in line:
                addr_cut = line.split('"')
                addr_name = addr_cut[1]
            # Capture subnet & mask
            elif 'set subnet' in line:
                subnet_cut = line.split()
                prefix = subnet_cut[2]
                # Convert the (xxx.xxx.xxx.xxx) mask to a slash (/yy) notation
                mask = sum(bin(int(x)).count('1') for x in subnet_cut[3].split('.'))
                subnet = str(prefix)+'/'+str(mask)
            # At the end on each addr entry update the main dictionary
            elif 'next' in line:
                # Only capture subnet entries (ip address and mask)
                if prefix:
                    fw_addr_dict.update({addr_name: subnet})
    return fw_addr_dict


def capture_fw_addrgrp(fw_config_list, fw_addr_dict):
    # Builds a dictionary of vips and their IP addresses

    # Intialise varibles
    start_pattern = re.compile(r"^config firewall addrgrp$")
    end_pattern = re.compile(r"^end$")
    member_addrgrp_dict = {}
    fw_addrgrp_dict = {}
    capture = False

    # Iterate through entire firewall configuration list
    for line in fw_config_list:
        # Identify start and end points for capturing vips
        if re.match(start_pattern, line):
            capture = True
            continue
        elif re.match(end_pattern, line):
            capture = False

        # Once capture flag is True
        if capture:
            # Capture address group name
            if 'edit' in line:
                addrgrp_cut = line.split('"')
                addrgrp_name = addrgrp_cut[1]            
            # Capture address group members
            elif 'set member' in line:
                member_cut = line.split()
                for item in range(2, len(member_cut)):
                    grp_member = member_cut[item].strip('"')
                    try:
                        member_addrgrp_dict.update({grp_member: fw_addr_dict[grp_member]})
                    except KeyError:
                        try:
                            # Where nested object groups occur leave value blank to remedy below
                            member_addrgrp_dict.update({grp_member: {}})
                        except KeyError:
                            member_addrgrp_dict.update({grp_member: {'nested-group': 'nested-group'}})
            # At the end on each address group entry update the main dictionary
            elif 'next' in line:
                    # Update dictionary with (addrgrp_name: {member_name: {prefix: mask})
                    fw_addrgrp_dict.update({addrgrp_name: member_addrgrp_dict})
                    member_addrgrp_dict = {}                
    
    return resolve_nested_grps(fw_addrgrp_dict)


def capture_fw_services(fw_config_list):
    # Builds a dictionary of tcp, udp and protocol services

    # Intialise varibles
    start_pattern = re.compile(r"^config firewall service custom$")
    end_pattern = re.compile(r"^end$")
    
    fw_srvs_dict = {'tcp_srvs': {}, 'udp_srvs': {}, 'proto_srvs': {}}
    proto_dict = {}

    capture = False
    ignore = False
    protocol, icmp_type, proto_num = '', '', ''

    # Iterate through entire firewall configuration list
    for line in fw_config_list:
        # Identify start and end points for capturing vips
        if re.match(start_pattern, line):
            capture = True
            continue
        elif re.match(end_pattern, line):
            capture = False

        # Once capture flag is True
        if capture:
            # Capture service name
            if 'edit' in line:
                srvs_cut = line.split('"')
                srvs_name = srvs_cut[1]
                
            # Capture tcp port range
            elif 'set tcp-portrange' in line:
                tcp_srvs_cut = line.split()
                tcp_range = tcp_srvs_cut[2]
                # Split the "1234-1400" port range into start and end values
                tcp_range_list = tcp_range.split('-')
                # If not end value (it's a single port) then duplicate first value
                try:
                    tcp_range_dict = dict({'from': tcp_range_list[0], 'to': tcp_range_list[1]})
                except IndexError:
                    tcp_range_dict = dict({'from': tcp_range_list[0], 'to': tcp_range_list[0]})
                # Update the main dictionary
                fw_srvs_dict['tcp_srvs'].update({srvs_name: tcp_range_dict})
                
            # Capture udp port range
            elif 'set udp-portrange' in line:
                udp_srvs_cut = line.split()
                udp_range = udp_srvs_cut[2]
                udp_range_list = udp_range.split('-')
                try:
                    udp_range_dict = dict({'from': udp_range_list[0], 'to': udp_range_list[1]})
                except IndexError:
                    udp_range_dict = dict({'from': udp_range_list[0], 'to': udp_range_list[0]})
                fw_srvs_dict['udp_srvs'].update({srvs_name: udp_range_dict})
                
            # Capture "set protocols " specifically/only
            elif re.search('set protocol\s', line):
                proto_cut = line.split()
                protocol = proto_cut[2]

            # Capture the ICMP Type
            elif re.search('^set icmptype', line):
                icmp_type_cut = line.split()
                try:
                    icmp_type = icmp_type_cut[2]
                except IndexError:
                    print('There was a problem importing:', line)
                    break
                
            # Capture "set protocols-number" specifically/only
            elif re.search('set protocol-number', line):
                proto_num_cut = line.split()
                proto_num = proto_num_cut[2]
                
            # At the end on each addr entry update the main dictionary
            elif 'next' in line:
                # Record if it's an ICMP or an IP protocol service
                if protocol:
                    proto_dict = {srvs_name: {protocol: icmp_type}}
                    fw_srvs_dict['proto_srvs'].update(proto_dict)
                    proto_dict = {}
                    protocol, icmp_type = '', ''
                elif proto_num:
                    proto_dict = {srvs_name: {protocol: proto_num}}
                    fw_srvs_dict['proto_srvs'].update(proto_dict)
                    proto_dict = {}
                    protocol, proto_num = '', ''
               
    return fw_srvs_dict

def capture_fw_srvsgrp(fw_config_list, fw_srvs_dict):
    # Builds a dictionary of vips and their IP addresses

    # Intialise varibles
    start_pattern = re.compile(r"^config firewall service group$")
    end_pattern = re.compile(r"^end$")
    member_srvsgrp_dict = {}
    fw_srvsgrp_dict = {}
    capture = False

    # Iterate through entire firewall configuration list
    for line in fw_config_list:
        # Identify start and end points for capturing vips
        if re.match(start_pattern, line):
            capture = True
            continue
        elif re.match(end_pattern, line):
            capture = False

        # Once capture flag is True
        if capture:
            
            # Capture services group name
            if 'edit' in line:
                srvsgrp_cut = line.split('"')
                srvsgrp_name = srvsgrp_cut[1]
                
            # Capture services group members
            elif 'set member' in line:
                line = line.replace('" "', '"')
                member_cut = line.split('"')
                for item in range(1, (len(member_cut)-1)):
                    grp_member = member_cut[item]
                    
                    if grp_member in fw_srvs_dict['tcp_srvs'].keys():
                        # Check if in services dictionary, tcp section, and assign if so
                        member_srvsgrp_dict.update({grp_member: fw_srvs_dict['tcp_srvs'][grp_member]})
                        
                    elif grp_member in fw_srvs_dict['udp_srvs'].keys():
                        # Check if in services dictionary, udp section, and assign if so
                        member_srvsgrp_dict.update({grp_member: fw_srvs_dict['udp_srvs'][grp_member]})
                        
                    elif grp_member in fw_srvs_dict['proto_srvs'].keys():
                        # Check if in services dictionary, protocol section, and assign if so
                        member_srvsgrp_dict.update({grp_member: fw_srvs_dict['proto_srvs'][grp_member]})
                        
                    else:
                        # Must be nested group so leave value blank to remedy at the end of function
                        member_srvsgrp_dict.update({grp_member: {}})
                            
            # At the end on each address group entry update the main dictionary
            elif 'next' in line:
                    # Update dictionary with (addrgrp_name: {member_name: {prefix: mask})
                    fw_srvsgrp_dict.update({srvsgrp_name: member_srvsgrp_dict})
                    member_srvsgrp_dict = {}
                    
    return resolve_nested_grps(fw_srvsgrp_dict)


def capture_policy(fw_config_list, ippool_dict, vip_dict, fw_addr_dict,
                   fw_addrgrp_dict, fw_srvs_dict, fw_srvsgrp_dict):
    # Builds a dictionary of policies and their relevant IP attributes

    # Intialise varibles
    start_pattern = re.compile(r"^config firewall policy$")
    end_pattern = re.compile(r"^end$")

    nat_status, pool_status = '', ''
    src_addr, src_addr_dict, src_addrgrp, src_addrgrp_dict  = {}, {}, {}, {}
    dnat_addrgrp, dnat_addr, dnat_ip, dnat_addrgrp_dict = {}, {}, {}, {}
    dnat_addr_dict, dnat_dict, snat_dict = {}, {}, {}
    pol_dict, label_dict = {}, {}
    pol_srvs_dict = {'tcp_srvs': {}, 'udp_srvs': {},
                     'proto_srvs': {}, 'group_srvs': {}}
    
    capture = False

    # Iterate through entire firewall configuration list
    for line in fw_config_list:
        # Identify start and end points for capturing policies
        if re.match(start_pattern, line): 
            capture = True
        elif re.match(end_pattern, line):
            capture = False

        # Once capture flag is True
        if capture:
            
            # Capture policy id in 'pol_id'
            if re.search('^edit\s', line):
                pol_cut = line.split()
                pol_id = pol_cut[1]

            # Capture policy source interfaces
            elif 'set srcintf' in line:
                src_intf_cut = re.split('" "|"', line)
                src_intf_list = src_intf_cut[1:(len(src_intf_cut)-1)]

            # Capture policy destination interfaces
            elif 'set dstintf' in line:
                dst_intf_cut = re.split('" "|"', line)
                dst_intf_list = dst_intf_cut[1:(len(dst_intf_cut)-1)]                

            # Capture line containing all source object names
            elif 'set srcaddr' in line:
                # Split line capturing source object names in list
                srcaddr_cut = re.split('" "|"', line)
                # Iterate through the all possible address dictionaries looking for a match
                for i in range(1, (len(srcaddr_cut)-1)):
                    try:
                        # Try the address dictionary instead
                        src_addr = {srcaddr_cut[i]: fw_addr_dict[srcaddr_cut[i]]}
                        src_addr_dict.update(src_addr)
                        src_addr = {}
                    except KeyError:
                        # Try the address group dictionary instead
                        try:
                            src_addrgrp = {srcaddr_cut[i]: fw_addrgrp_dict[srcaddr_cut[i]]}
                            src_addrgrp_dict.update(src_addrgrp)
                            src_addrgrp = {}
                        except KeyError:
                            # catch no source address object, probably nested group object
                            src_addr_dict = dict({srcaddr_cut[i]: 'unknown'})
            
            # Capture line containing all destination object names
            elif 'set dstaddr' in line:
                # Split line capturing destination object names in list
                dnat_cut = re.split('" "|"', line)
                # Iterate through the all possible address dictionaries looking for a match
                for i in range(1, (len(dnat_cut)-1)):
                    try:
                        dnat_ip = vip_dict[dnat_cut[i]]
                        # Iterate through the single pair to extract dnat_ip address
                        for dnat, real in dnat_ip.items():
                            dnat_ipaddr = dnat
                        # Update vip dictionary with (dst_name: dnat_ip)
                        dnat_dict.update({dnat_cut[i]: dnat_ipaddr})
                    except KeyError:
                        # Try the address group dictionary instead
                        try:
                            dnat_addrgrp = {dnat_cut[i]: fw_addrgrp_dict[dnat_cut[i]]}
                            dnat_addrgrp_dict.update(dnat_addrgrp)
                            dnat_addrgrp = {}
                        except KeyError:
                            # Try the address dictionary instead
                            try:
                                dnat_addr = {dnat_cut[i]: fw_addr_dict[dnat_cut[i]]}
                                dnat_addr_dict.update(dnat_addr)
                                dnat_addr = {}
                            except KeyError:
                                # catch no vip, probably group object
                                dnat_ip = dict({dnat_cut[i]: 'unknown'})
                                
            # Capture line containing all services object names
            elif 'set service' in line:
                # Split line capturing service object names in list
                service_cut = re.split('" "|"', line)
                # Iterate through the all possible service dictionaries looking for a match
                for i in range(1, (len(service_cut)-1)):
                    srv_name = service_cut[i]
                    
                    if srv_name in fw_srvs_dict['tcp_srvs'].keys():
                        # Check if service in the tcp section on the services dictionary
                        pol_srvs_dict['tcp_srvs'].update({srv_name: fw_srvs_dict['tcp_srvs'][srv_name]})
                        
                    elif srv_name in fw_srvs_dict['udp_srvs'].keys():
                        # Check if service in the udp section on the services dictionary
                        pol_srvs_dict['udp_srvs'].update({srv_name: fw_srvs_dict['udp_srvs'][srv_name]})
                        
                    elif srv_name in fw_srvs_dict['proto_srvs'].keys():
                        # Check if service in the protocol section on the services dictionary
                        pol_srvs_dict['proto_srvs'].update({srv_name: fw_srvs_dict['proto_srvs'][srv_name]})
                        
                    elif srv_name in fw_srvsgrp_dict.keys():
                        # Check if service in the group section on the services dictionary
                        pol_srvs_dict['group_srvs'].update({srv_name: fw_srvsgrp_dict[srv_name]})
                    else:
                        print('Problem capturing the policy', pol_id, 'Service', srv_name)

            # Capture if Policy Action enabled
            elif 'set action' in line:
                pol_action_cut = line.split()
                action = pol_action_cut[2]

            # Capture if NAT enabled, provided if it exists
            elif 'set nat' in line:
                nat_cut = line.split()
                nat_status = nat_cut[2]

            # Capture if ippool enabled, provided if it exists
            elif 'set ippool' in line:
                pool_status_cut = line.split()
                pool_status = pool_status_cut[2]
                
            # Capture ippool if it exists
            elif 'set poolname' in line:
                snat_cut = line.split('"')
                try:
                    snat_ip = ippool_dict[snat_cut[1]]
                except KeyError:
                    # catch no ippool address found
                    snat_ip = 'unknown'
                snat_dict.update({snat_cut[1]: snat_ip})
                
            # Capture policy label if it exists
            elif 'set global-label' in line:
                label_cut = line.split('"')
                try:
                    label = label_cut[1]
                except IndexError:
                    # catch no global-label set
                    label = ''
                label_dict.update({'label': label})
                
            # At the end on each policy update the main dictionary
            elif 'next' in line:
                pol_dict.update({pol_id: {'dstaddr':
                {'vips': dnat_dict, 'addr': dnat_addr_dict, 'addrgrps': dnat_addrgrp_dict},
                'srcaddr': {'addr': src_addr_dict, 'addrgrps': src_addrgrp_dict},
                'ippools': snat_dict, 'labels': label_dict, 'src_intf': src_intf_list,
                'dst_intf': dst_intf_list, 'pol_action': action, 'service': pol_srvs_dict,
                'nat': nat_status, 'ippool_status': pool_status}})
                
                # Reset the sub dictionaries, lists and strings for next policy
                action, nat_status, pool_status = '', '', ''
                src_addr_dict, src_addrgrp_dict = {}, {}
                dnat_dict, dnat_addr_dict, dnat_addrgrp_dict = {}, {}, {}
                snat_dict, label_dict = {}, {}
                pol_srvs_dict = {'tcp_srvs': {}, 'udp_srvs': {},
                                 'proto_srvs': {}, 'group_srvs': {}}
                
    return pol_dict


def find_policies(pol_dict, pol_id_list):
    # Finds then prints or saves policies in the pol_id_list

    for pol_id in pol_id_list:
        #Print the section header out identify the policy id
        print(f"\nPolicy id: {pol_id}")
        print('='*20)
        # Assign the ippools and vips dictionaries to new varibles
        ippools_dict = pol_dict[pol_id]['ippools']
        vips_dict = pol_dict[pol_id]['vips']
        
        # Print the ippool mappings out
        print(f"\n\n{'IPool Name': <30}{'IPool IP Address': >18}")
        print('-'*50, '\n')
        for ippool_name, ippool_addr in ippools_dict.items():
            print(f"{ippool_name: <30}{ippool_addr: >18}")
            
        # Print the vip mappings out
        print(f"\n\n{'VIP Name': <30}{'VIP IP Address': >18}")
        print('-'*50, '\n')
        for vip_name, vip_addr in vips_dict.items():
            print(f"{vip_name: <30}{vip_addr: >18}")

def del_policies(pol_dict, pol_id_list):
    # Deletes polices from the original imported config according to pol_id_list

    for pol in pol_id_list:
        del pol_dict[pol]

    print('\n\nThe number of policies after deletion are:', len(pol_dict))
    return pol_dict
            

def forward_dns(host_str):
    # Forward DNS Lookup - Resolves FQDN's to IP addresses

    print("\n\n")
    print(" ### WARNING - Resolving large lists can take considerable time ###")
    print("The specified file must be a .txt or .csv file in the format of one IP address per line")
    choice = input("\nPress any key to continue or '0' to return to the Main Menu ")
    
    ip_list = []
    fqdn_pairs = {}
    resolved_host_dict = {}
    unresolved_host_dict = {}
    host_list = host_str.splitlines()  # remove '/n' and convert to a list
    if choice == "0":
        return choice
    else:
        for hostname in host_list:
            try:
                # returns IP address for a given hostname
                ip_data = socket.getaddrinfo(hostname, None)
                ip_addr = [x[4][0] for x in ip_data]
                ip_addr = ip_addr[0]
                ip_list.append(ip_addr)  # creates list of ip's based on resolvable hosts only
            except socket.gaierror:
                # handles resolution errors, by creating a dictionary of unresolved hostnames
                ip_addr = "Unresolved"
                unresolved_host_dict[hostname] = ip_addr

        for ip_addr in ip_list:
            try:
                # returns FQDN's from the IP list resolved from hostnames
                my_socket = (ip_addr, 0)
                host_data = socket.getnameinfo(my_socket, 0)
                fqdn_hostname = host_data[0]
            except socket.gaierror:
                # handles IP's with no FQDN
                fqdn_hostname = "Unresolved"
            resolved_host_dict[fqdn_hostname] = ip_addr
        # concatanations both resolved and unresolved dictionaries
        fqdn_pairs = dict(resolved_host_dict)
        fqdn_pairs.update(unresolved_host_dict)
        return fqdn_pairs


def reverse_dns(ip_str):
    # Reverse DNS Lookup - Resolves IP addresses to FQDN's

    print("\n\n")
    print(" ### WARNING - Resolving large lists can take considerable time ###")
    print("The specified file must be a .txt or .csv file in the format of one IP address per line")
    choice = input("\nPress any key to continue or '0' to return to the Main Menu ")

    fqdn_pairs = {}
    ip_list = ip_str.splitlines()  # remove '/n' and convert to a list
    if choice == "0":
        return choice
    else:
        for ip_addr in ip_list:
            try:
                my_socket = (ip_addr, 0)
                host_data = socket.getnameinfo(my_socket, 0)
                hostname = host_data[0]
            except socket.gaierror:
                # handles IP's with no FQDN
                hostname = "Unresolved"
            fqdn_pairs[hostname] = ip_addr
    return fqdn_pairs


def main_menu():
    # Setup Main Menu Loop

    os.system('cls')
    mm_choice = None
    while mm_choice != "0":
        print(
            """
            Main Menu

            0 - Quit
            1 - Import Firewall Configuration as a Complex Data Structure
            2 - Work with a list of Firewall Policies
            3 - Resolve VIP Object Names
            4 - Resolve Address Object Names
            5 - Find Object Type
            6 - Find write policy numbers to a file
            x - Forward DNS Lookups - Resolve Hostnames to IP Addresses
            y - Reverse DNS Lookups - Resolve IP addresses to FQDN's
            """
        )

        mm_choice = input("Choice: ")
        print()
        return mm_choice


# Main Program Function
def main():
    """Main Program"""

    datafolder = set_working_dir()

    mm_val = None
    while mm_val != "0":
        mm_val = main_menu()
        if mm_val == "1":
            # Read and process the firewall config file
            fw_config_message = '\nEnter the full filename containing the firewall configuration: '
            fw_file_name = get_file(datafolder, fw_config_message)
            fw_config_list = read_file_lines(fw_file_name)  # read file lines as a list
            fw_config_list = remove_whitespace(fw_config_list)
            # Generate a dictionary of all the 'ippool' names and their values
            ippool_dict = capture_ippools(fw_config_list)
            # Generate a dictionary of all the 'vip' names and their values
            vip_dict = capture_vips(fw_config_list)
            # Generate a dictionary of all the 'firewall addresses' names and their values
            fw_addr_dict = capture_fw_addr(fw_config_list)
            # Generate a dictionary of all the 'firewall address groups' names and their values
            fw_addrgrp_dict = capture_fw_addrgrp(fw_config_list, fw_addr_dict)
            # Generate a dictionary of all the firewall tcp/udp and protocol services
            fw_srvs_dict = capture_fw_services(fw_config_list)
            # Generate a dictionary of all the 'firewall service groups' names and their values
            fw_srvsgrp_dict = capture_fw_srvsgrp(fw_config_list, fw_srvs_dict)
            # Generate a dictionary of all the policies and their attributes
            pol_dict = capture_policy(fw_config_list, ippool_dict, vip_dict, fw_addr_dict,
                                      fw_addrgrp_dict, fw_srvs_dict, fw_srvsgrp_dict)
            print('\n\nThe number of policies in the imported config is:', len(pol_dict))
            #pprint(pol_dict)
        elif mm_val == "2":
            # Read and process the policy id file
            print('\nImport a file containing the list of policies you want to work with.')
            pol_message = '\nEnter the full filename containing the policy ids: '
            pol_id_file_name = get_file(datafolder, pol_message )
            pol_id_list = read_file_lines(pol_id_file_name)
            pol_id_list = remove_whitespace(pol_id_list)
            os.system('cls')
            sm2_val = sub_menu2()
            if sm2_val == "1":
                # Prints and writes policy destination and IPool information to a file
                print('Print all policies associated with the imported policy list')
                write_pol_dict(pol_dict, pol_id_list)
                #find_policies(pol_dict, pol_id_list)
                sys.exit()
                
            if sm2_val == "2":
                # Deletes the list of imported policies from the full policy dictionary
                reduced_pols = del_policies(pol_dict, pol_id_list)
                # Reads in a list of objects and checks if the exist in the remaining policies
                print('\nImport a file containing the list of policies you want to work with.')
                obj_message = '\nEnter the full filename containing the objects you want to check: '
                obj_file_name = get_file(datafolder, obj_message )
                obj_list = read_file_lines(obj_file_name)
                obj_list = remove_whitespace(obj_list)
                find_objects(reduced_pols, obj_list)
                
        elif mm_val == "3":
                # Reads in a list of vip names, resolves and writes them to a file
                print('\nImport a file containing the list of vip names you want to work with.')
                vip_obj_message = '\nEnter the full filename containing the vip objects you want to check: '
                vip_obj_file_name = get_file(datafolder, vip_obj_message )
                vip_list = read_file_lines(vip_obj_file_name)
                vip_list = remove_whitespace(vip_list)
                vip_lookup(vip_dict, vip_list)
                
        elif mm_val == "4":
                # Reads in a list of address object names, resolves and writes them to a file
                print('\nImport a file containing the list of vip names you want to work with.')
                addr_obj_message = '\nEnter the full filename containing the address objects you want to check: '
                addr_obj_file_name = get_file(datafolder, addr_obj_message )
                addr_list = read_file_lines(addr_obj_file_name)
                addr_list = remove_whitespace(addr_list)
                addr_lookup(fw_addr_dict, addr_list)
                
        elif mm_val == "5":
                # Find objects and their type from a list and writes them to a file
                print('\nImport a file containing the list of object names you want to work with.')
                find_obj_message = '\nEnter the full filename containing the address objects you want to check: '
                find_obj_file_name = get_file(datafolder, find_obj_message )
                find_list = read_file_lines(find_obj_file_name)
                find_list = remove_whitespace(find_list)
                write_objects(fw_addr_dict, fw_addrgrp_dict, vip_dict, ippool_dict, find_list)
                
        elif mm_val == "6":
                # Finds and writes the policy numbers to a file
                write_pol_num(pol_dict)
                
        elif mm_val == "x":
            print("\nForward DNS Lookup Routine...")
            file_name = get_file(datafolder)
            host_str = read_file(file_name)  # read IP's in from file as a string
            fqdn_pairs = remove_duplicates(host_str)
            fqdn_pairs = forward_dns(host_str)
            if fqdn_pairs != '0':  # print the dictionary of IP's and FQDN's if not cancelled
                os.system('cls')
                print_dict(fqdn_pairs)
                save_file = input("\n\nPress 's' to save as a .csv or enter to return to the main menu. ").lower()
                if save_file == "s":
                    write_dns_dict(fqdn_pairs)
                    
        elif mm_val == "y":
            print("\nReverse DNS Lookup Routine...")
            file_name = get_file(datafolder)
            ip_str = read_file(file_name)  # read IP's in from file as a string
            fqdn_pairs = remove_duplicates(ip_str)
            fqdn_pairs = reverse_dns(ip_str)
            if fqdn_pairs != '0':  # print the dictionary of IP's and FQDN's if not cancelled
                os.system('cls')
                print_dict(fqdn_pairs)
                save_file = input("\n\nPress 's' to save as a .csv or enter to return to the main menu. ").lower()
                if save_file == "s":
                    write_dns_dict(fqdn_pairs)
    return pol_dict, fw_srvs_dict


pol_dict, fw_srvs_dict = main()
input("\n\nPress the enter key to exit.")
