#!/usr/bin/env python

""" This program imports a Fortigate firewall configuration as a complex data
    structure. It then asks for a prefix or IP address and checks that entry
    against all policies in the fortigate firewall config to see if that
    prefix/IP address is encompassed in each policy. """

# Author: Wayne Bellward
# Date:   30/07/2021


import forti_parser
import ipaddress
from pprint import pprint


def get_prefix():
    """ Asks the user to enter a prefix or IP address and validates it """

    # Intialise variables
    my_prefix = False

    # Print header
    print('\nThis program will check every policy to see if the Prefix or',
          'IP address\nyou entered is included/permitted as a source')
    print('-'*75, '\n')

    # Loop until the input is a valid IP address
    while not my_prefix:
        try:
            my_prefix = ipaddress.ip_network(input(
                'Please enter your Prefix/IP address using the slash notation, '
                'e.g. xxx.xxx.xxx.xxx/yy, omit the mask (/yy) for host '
                'IP addresses: '))
        except ValueError:
            my_prefix = False
            print('You entered an invalid prefix or IP address,',
                  'please try again.\n')

    # Return a 'IPv4Network' object
    return my_prefix


def check_prefix(my_prefix, config_dict):
    """ Checks if a prefix or IP address is included/permitted
        as a source in a policy """

    # Intialise variables
    tmp_addr_dict = {}
    tmp_addrgrp_dict = {}
    permit_dict = {}

    # Loop through each policy in the config
    for pol_id, attributes in config_dict['pol_dict'].items():

        # Loop through each source address object for each policy
        for addr_name, ipaddr in attributes['srcaddr']['addr'].items():
            if my_prefix.subnet_of(ipaddress.IPv4Network(ipaddr)):
                tmp_addr_dict.update({addr_name: ipaddr})

        # Loop through each source address group object for each policy      
        for grp_name, grp_members in attributes['srcaddr']['addrgrps'].items():
            for member_name, member_ip in grp_members.items():
                if my_prefix.subnet_of(ipaddress.IPv4Network(member_ip)):
                    tmp_addrgrp_dict.update({grp_name:
                                            {member_name: member_ip}})

        # Update main dictionary after each policy iteration
        permit_dict.update({pol_id: {
                            'addr': tmp_addr_dict,
                            'addrgrp': tmp_addrgrp_dict,
                            'action': attributes['pol_action']}
                            })
        
        # Clear each temporary dictionary after each policy iteration 
        tmp_addr_dict = {}
        tmp_addrgrp_dict = {}

    # Add the prefix being compared to the main dictionary for printing/writing
    permit_dict.update({'my_prefix': my_prefix})
    
    return permit_dict


def write_output(output_dict):
    """ Writes the output to a .csv file """

    # Ask user for filename to write to and add '.csv' extension
    filename = input("\n\nPlease enter the name of the file you wish to save "
                     "without the file extension: ")
    filename = filename+'.csv'

    with open(filename, 'w') as file:

        # Pop the user inputted prefix from the dictionary to use in the title
        my_prefix = output_dict.pop('my_prefix')
        
        # Write header
        title = (f'The following is a list of policies where {my_prefix} is '
                  'encompassed in the source addresses')
        header = [title, '\n\n', 'policy id', ',', 'address group', ',',
                  'address object', ',', 'ip address', ',', 'policy action',
                  '\n']
        file.writelines(header)

        # Loop through 'output_dict' extracting and writing data
        for pol_id, attributes in output_dict.items():

            # Assign the address, address group dictionaries and action
            # to new varibles
            addr_dict = attributes['addr']
            addrgrp_dict = attributes['addrgrp']
            action = attributes['action']

            # Write the address mappings out
            for addr_name, addr in addr_dict.items():
                addr_line = [pol_id, ',', '', ',', addr_name, ',', addr, ',',
                             action, '\n']
                file.writelines(addr_line)

            # Write the address group object mappings out
            for addrgrp_name, members in addrgrp_dict.items():
                for name, ip_addr in members.items():
                    member_line = [pol_id, ',', addrgrp_name, ',', name, ',',
                                   ip_addr, ',', action, '\n']
                    file.writelines(member_line)


def main():
    """ Main program """

    # Call Fortigate Parser
    config_dict = forti_parser.parse()
    print(len(config_dict))

    # Call function for user to input a valid IP prefix
    my_prefix = get_prefix()

    # Call function to check the prefix against each policy
    output_dict = check_prefix(my_prefix, config_dict)

    # Call function to write the output to a .csv file
    write_output(output_dict)

main()
