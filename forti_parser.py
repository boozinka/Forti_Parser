#!/usr/bin/env python

""" Reads a Fortigate 'show' output file and returns the objects and policies as
    a complex data structure in the form of a collection of dictionaries. """

# Author: Wayne Bellward
# Date: 26/07/2021


import os
import sys
import re
import socket
import pathlib
from pprint import pprint


def set_working_dir():
    """ Function that sets the working directory """

    working_dir = ""

    directory_input = False
    while not directory_input:
        working_dir = pathlib.Path(input("Please enter the path to your input"
                        " file, or 'enter' if it's in the same directory as"
                        " this program: "))
        directory_input = pathlib.Path.exists(working_dir)
        if not directory_input:
            input("Invalid path or directory, press enter to try again. ")
            os.system('cls')
    return working_dir


def get_filename(file_path, message):
    """ Welcome screen and setup for initial parameters including
        the working directory and input file """

    my_file = None
    file_input = False

    while not file_input:
        os.system('cls')
        print("\nThe specified file must be comma separated")
        file_name = input(message)
        my_file = file_path / file_name
        file_input = pathlib.Path.exists(my_file)
        if not file_input or file_name == '':
            file_input = False
            input("Invalid file name or file does not exist,"
                  " press enter to try again. ")
    return my_file


def read_file_lines(my_file):
    """ Open file and read it as a list """

    try:
        with open(my_file) as forti_output:
            forti_output = forti_output.readlines()
            # Strip whitespace and "\n" from each line
            forti_output = [line.strip() for line in forti_output]
    except PermissionError:
        print("Error occured, you did not enter a valid filename or"
              " do not have permission to read this file")
    return forti_output


def resolve_nested_grps(addrgrp_dict):
    # This function iterates over and updates the dictionary to resolve
    # nested object groups defined in same dictionary
    
    # Make a copy of the dictionary, to fill in blank values with nested object
    # values
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


def capture_addr(addr_list):
    """ Processes the address object configuration list and passes it back as
        a data structure """

    # Intialise varibles
    fw_addr_dict = {}
    prefix = ''

    # Iterate through address object configuration list
    for line in addr_list:
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


def capture_addrgrp(addrgrp_list, addr_dict):
    """ Processes the address group object configuration list and passes
        it back as a dictionary data structure """

    # Intialise varibles
    member_addrgrp_dict = {}
    addrgrp_dict = {}

    # Iterate through entire firewall configuration list
    for line in addrgrp_list:

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
                    member_addrgrp_dict.update(
                        {grp_member: addr_dict[grp_member]})
                except KeyError:
                    try:
                        # Where nested object groups occur leave value blank
                        # to remedy below
                        member_addrgrp_dict.update({grp_member: {}})
                    except KeyError:
                        member_addrgrp_dict.update(
                            {grp_member: {'nested-group': 'nested-group'}})
        # At the end on each address group entry update the main dictionary
        elif 'next' in line:
                # Update dictionary with
                # (addrgrp_name: {member_name: {prefix: mask})
                addrgrp_dict.update({addrgrp_name: member_addrgrp_dict})
                member_addrgrp_dict = {}                
    
    return resolve_nested_grps(addrgrp_dict)


def capture_srvs(srvs_list):
    """ Processes the services object configuration list and passes it
        back as a dictionary data structure """

    # Intialise varibles
    srvs_dict = {'tcp_srvs': {}, 'udp_srvs': {}, 'proto_srvs': {}}
    proto_dict = {}

    protocol = ''
    icmp_type = ''
    proto_num = ''

    # Iterate through entire firewall configuration list
    for line in srvs_list:
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
                tcp_range_dict = dict(
                    {'from': tcp_range_list[0], 'to': tcp_range_list[1]})
            except IndexError:
                tcp_range_dict = dict(
                    {'from': tcp_range_list[0], 'to': tcp_range_list[0]})
            # Update the main dictionary
            srvs_dict['tcp_srvs'].update({srvs_name: tcp_range_dict})
            
        # Capture udp port range
        elif 'set udp-portrange' in line:
            udp_srvs_cut = line.split()
            udp_range = udp_srvs_cut[2]
            udp_range_list = udp_range.split('-')
            try:
                udp_range_dict = dict(
                    {'from': udp_range_list[0], 'to': udp_range_list[1]})
            except IndexError:
                udp_range_dict = dict(
                    {'from': udp_range_list[0], 'to': udp_range_list[0]})
            srvs_dict['udp_srvs'].update({srvs_name: udp_range_dict})
            
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
                srvs_dict['proto_srvs'].update(proto_dict)
                proto_dict = {}
                protocol, icmp_type = '', ''
            elif proto_num:
                proto_dict = {srvs_name: {protocol: proto_num}}
                srvs_dict['proto_srvs'].update(proto_dict)
                proto_dict = {}
                protocol, proto_num = '', ''
               
    return srvs_dict


def capture_srvsgrp(srvsgrp_list, srvs_dict):
    """ Processes the services group object configuration list and passes
        it back as a dictionry data structure """

    # Intialise varibles
    member_srvsgrp_dict = {}
    srvsgrp_dict = {}

    # Iterate through entire firewall configuration list
    for line in srvsgrp_list:
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
                
                if grp_member in srvs_dict['tcp_srvs'].keys():
                    # Check if in services dictionary, tcp section,
                    # and assign if so
                    member_srvsgrp_dict.update(
                        {grp_member: srvs_dict['tcp_srvs'][grp_member]})
                    
                elif grp_member in srvs_dict['udp_srvs'].keys():
                    # Check if in services dictionary, udp section,
                    # and assign if so
                    member_srvsgrp_dict.update(
                        {grp_member: srvs_dict['udp_srvs'][grp_member]})
                    
                elif grp_member in srvs_dict['proto_srvs'].keys():
                    # Check if in services dictionary, protocol section,
                    # and assign if so
                    member_srvsgrp_dict.update(
                        {grp_member: srvs_dict['proto_srvs'][grp_member]})
                    
                else:
                    # Must be nested group so leave value blank to remedy
                    # at the end of function
                    member_srvsgrp_dict.update({grp_member: {}})
                        
        # At the end on each address group entry update the main dictionary
        elif 'next' in line:
                # Update dictionary with new service group structure
                srvsgrp_dict.update({srvsgrp_name: member_srvsgrp_dict})
                member_srvsgrp_dict = {}
                    
    return resolve_nested_grps(srvsgrp_dict)


def capture_ippool(ippool_list):
    """ Processes the ippool object configuration list and passes it back
        as a dictionary data structure """

    # Intialise varibles
    ippool_dict = {}

    # Iterate through entire firewall configuration list
    for line in ippool_list:
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


def capture_vip(vip_list):
    """ Processes the vip object configuration list and passes it back as
        a dictionary data structure """

    # Intialise varibles
    vip_dict = {}

    # Iterate through entire firewall configuration list
    for line in vip_list:
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


def capture_pol(pol_list, addr_dict, addrgrp_dict, srvs_dict, srvsgrp_dict,
                ippool_dict, vip_dict):
    """ Processes the firewall policy configuration list and passes it back
        as a dictionary data structure """

    # Intialise varibles
    seq_num = 0
    nat_status = ''
    pool_status = ''
    src_addr = {}
    src_addr_dict = {}
    src_addrgrp = {}
    src_addrgrp_dict = {}
    dnat_addrgrp = {}
    dnat_addr = {}
    dnat_ip = {}
    dnat_addrgrp_dict = {}
    dnat_addr_dict = {}
    dnat_dict = {}
    snat_dict = {}
    pol_dict = {}
    label_dict = {}
    pol_srvs_dict = {'tcp_srvs': {}, 'udp_srvs': {},
                     'proto_srvs': {}, 'group_srvs': {}}


    # Iterate through entire firewall configuration list
    for line in pol_list:
 
        # Capture policy id in 'pol_id'
        if re.search('^edit\s', line):
            pol_cut = line.split()
            pol_id = pol_cut[1]
            seq_num += 1

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
            # Iterate through the all possible address dictionaries looking
            # for a match
            for i in range(1, (len(srcaddr_cut)-1)):
                try:
                    # Try the address dictionary instead
                    src_addr = {srcaddr_cut[i]: addr_dict[srcaddr_cut[i]]}
                    src_addr_dict.update(src_addr)
                    src_addr = {}
                except KeyError:
                    # Try the address group dictionary instead
                    try:
                        src_addrgrp = {srcaddr_cut[i]:
                                       addrgrp_dict[srcaddr_cut[i]]}
                        src_addrgrp_dict.update(src_addrgrp)
                        src_addrgrp = {}
                    except KeyError:
                        # catch no source address object, probably nested group
                        # object
                        src_addr_dict = dict({srcaddr_cut[i]: 'unknown'})
        
        # Capture line containing all destination object names
        elif 'set dstaddr' in line:
            # Split line capturing destination object names in list
            dnat_cut = re.split('" "|"', line)
            # Iterate through the all possible address dictionaries looking
            # for a match
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
                        dnat_addrgrp = {dnat_cut[i]: addrgrp_dict[dnat_cut[i]]}
                        dnat_addrgrp_dict.update(dnat_addrgrp)
                        dnat_addrgrp = {}
                    except KeyError:
                        # Try the address dictionary instead
                        try:
                            dnat_addr = {dnat_cut[i]: addr_dict[dnat_cut[i]]}
                            dnat_addr_dict.update(dnat_addr)
                            dnat_addr = {}
                        except KeyError:
                            # catch no vip, probably group object
                            dnat_ip = dict({dnat_cut[i]: 'unknown'})
                            
        # Capture line containing all services object names
        elif 'set service' in line:
            # Split line capturing service object names in list
            service_cut = re.split('" "|"', line)
            # Iterate through the all possible service dictionaries looking
            # for a match
            for i in range(1, (len(service_cut)-1)):
                srv_name = service_cut[i]
                
                if srv_name in srvs_dict['tcp_srvs'].keys():
                    # Check if service in the tcp section on the services
                    # dictionary
                    pol_srvs_dict['tcp_srvs'].update(
                        {srv_name: srvs_dict['tcp_srvs'][srv_name]}
                    )
                    
                elif srv_name in srvs_dict['udp_srvs'].keys():
                    # Check if service in the udp section on the services
                    # dictionary
                    pol_srvs_dict['udp_srvs'].update(
                        {srv_name: srvs_dict['udp_srvs'][srv_name]}
                    )
                    
                elif srv_name in srvs_dict['proto_srvs'].keys():
                    # Check if service in the protocol section on the services
                    # dictionary
                    pol_srvs_dict['proto_srvs'].update(
                        {srv_name: srvs_dict['proto_srvs'][srv_name]}
                    )
                    
                elif srv_name in srvsgrp_dict.keys():
                    # Check if service in the group section on the services
                    # dictionary
                    pol_srvs_dict['group_srvs'].update(
                        {srv_name: srvsgrp_dict[srv_name]}
                    )
                else:
                    print('Problem capturing the policy', pol_id,
                          'Service', srv_name)

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
            
        # At the end of each policy update the main dictionary
        elif 'next' in line:
            pol_dict.update(
                {pol_id: {'dstaddr': {'vips': dnat_dict, 'addr': dnat_addr_dict,
                'addrgrps': dnat_addrgrp_dict}, 'srcaddr': {'addr': src_addr_dict,
                'addrgrps': src_addrgrp_dict}, 'ippools': snat_dict, 'labels':
                label_dict, 'src_intf': src_intf_list, 'dst_intf': dst_intf_list,
                'pol_action': action, 'service': pol_srvs_dict, 'nat': nat_status,
                'ippool_status': pool_status, 'seq': seq_num}}
            )
            
            # Reset the sub dictionaries, lists and strings for next policy
            action = ''
            nat_status = ''
            pool_status = ''
            src_addr_dict = {}
            src_addrgrp_dict = {}
            dnat_dict = {}
            dnat_addr_dict = {}
            dnat_addrgrp_dict = {}
            snat_dict = {}
            label_dict = {}
            pol_srvs_dict = {'tcp_srvs': {}, 'udp_srvs': {},
                             'proto_srvs': {}, 'group_srvs': {}}
                
    return pol_dict
   

def capture_config(fw_config_file):
    """ Function iterates through the configuration list and compiles a
        complex data structure from the required configuration elements """

    # Intialise varibles

    # Start and end patterns
    addr_start_pattern = re.compile(r"^config firewall address$")
    addrgrp_start_pattern = re.compile(r"^config firewall addrgrp$")
    srvs_start_pattern = re.compile(r"^config firewall service custom$")
    srvsgrp_start_pattern = re.compile(r"^config firewall service group$")
    ippool_start_pattern = re.compile(r"^config firewall ippool$")
    vip_start_pattern = re.compile(r"^config firewall vip$")
    pol_start_pattern = re.compile(r"^config firewall policy$")
    end_pattern = re.compile(r"^end$")

    # flags
    capture = False
    ignore = False

    # Temporary lists
    addr_list = []
    addrgrp_list = []
    srvs_list = []
    srvsgrp_list = []
    ippool_list = []
    vip_list = []
    pol_list = []

    # Open config file and interate through lines stripping whitespace and "\n"
    with open(fw_config_file) as config_file:
        for line in config_file:
            line = line.strip()
        
            # Identify start and end points for capturing firewall
            # config sections
            
            # Start capturing address object configuration
            if re.match(addr_start_pattern, line):
                capture = 'addr'
                continue        
            # Start capturing address object configuration
            elif re.match(addrgrp_start_pattern, line):
                capture = 'addrgrp'
                continue        
            # Start capturing address object configuration
            elif re.match(srvs_start_pattern, line):
                capture = 'srvs'
                continue        
            # Start capturing address object configuration
            elif re.match(srvsgrp_start_pattern, line):
                capture = 'srvsgrp'
                continue        
            # Start capturing address object configuration
            elif re.match(ippool_start_pattern, line):
                capture = 'ippool'
                continue        
            # Start capturing address object configuration
            elif re.match(vip_start_pattern, line):
                capture = 'vip'
                continue        
            # Start capturing address object configuration
            elif re.match(pol_start_pattern, line):
                capture = 'policy'
                continue        
            # Set capture flag to false at the end of the config section
            elif re.match(end_pattern, line):
                capture = False

            # Once capture flag is true capture that line in the associated
            # tmp list

            if capture == 'addr':
                addr_list.append(line)            
            elif capture == 'addrgrp':
                addrgrp_list.append(line)     
            elif capture == 'srvs':
                srvs_list.append(line)
            elif capture == 'srvsgrp':
                srvsgrp_list.append(line)
            elif capture == 'ippool':
                ippool_list.append(line)
            elif capture == 'vip':
                vip_list.append(line)
            elif capture == 'policy':
                pol_list.append(line)

        # Call each capture function with compiled list of config for that
        # section to be processed and returned as a dictionary

        addr_dict = capture_addr(addr_list)
        addrgrp_dict = capture_addrgrp(addrgrp_list, addr_dict)
        srvs_dict = capture_srvs(srvs_list)
        srvsgrp_dict = capture_srvsgrp(srvsgrp_list, srvs_dict)
        ippool_dict = capture_ippool(ippool_list)
        vip_dict = capture_vip(vip_list)
        
        # Compile each dictionary into one dictionary to be passed and
        # processed by the policy capture function
        
        config_dict = {
            'pol_list': pol_list,
            'addr_dict': addr_dict,
            'addrgrp_dict': addrgrp_dict,
            'srvs_dict': srvs_dict,
            'srvsgrp_dict': srvsgrp_dict,
            'ippool_dict': ippool_dict,
            'vip_dict': vip_dict
        }

        # Retrieve policy dictionary
        pol_dict = capture_pol(**config_dict)

        # Delete 'pol_list' from 'config_dict' and add the returned policy
        # dictionary
        
        del config_dict['pol_list']
        config_dict.update({'pol_dict': pol_dict})

    return config_dict

        
def parse():
    """ Used to initialise 'main' when the module is imported """

    global config_dict
    
    config_dict = main()
    return config_dict

    
def main():
    """ Main Program, used when the module is run directly as a script """
    
    # Read and process the firewall config file into a list
    file_path = set_working_dir()
    fw_config_message = ("\nEnter the full filename containing the firewall"
                         " configuration: ")
    fw_file_name = get_filename(file_path, fw_config_message)

    # Read configuration list and capture the required sections for processing
    config_dict = capture_config(fw_file_name)

    return config_dict


config_dict = None


if __name__ == "__main__":
    config_dict = main()
