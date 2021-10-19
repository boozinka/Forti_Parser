#!/usr/bin/env python

""" This program imports one or more Fortigate firewall configurations as a
    complex data structure. With each policy configuration read it also reads
    in a list of policies to be decommissioned. It then separates the policies
    to be decommissioned from the remain policies for each firewall policy
    configuration and compiles a list accross all configurations of policies to
    be decommission and those to be keep. It then compares the objects from the
    policies to be decommissioned against the objects in the policies to be kept.
    If any objects in the policies exist in the policies to be kept those objects
    are marked as "Keep", if any of those objects do not appear in the policies
    to be kept, they are marked to be "Deleted".
"""

# Author: Wayne Bellward
# Date:   19/10/2021


import forti_parser
import pathlib
from pprint import pprint
from datetime import datetime


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
    """ Ask user for the filename of the policy id list and validates it """

    my_file = None
    file_input = False

    while not file_input:
        file_name = input(message)
        my_file = file_path / file_name
        file_input = pathlib.Path.exists(my_file)
        if not file_input or file_name == '':
            file_input = False
            print("Invalid file name or file does not exist,"
                  " please try again. ")
    return my_file


def read_file_lines(my_file):
    """ Open file and read it as a list """

    try:
        with open(my_file) as pol_id_file:
            pol_id_file = pol_id_file.readlines()
            # Strip whitespace and "\n" from each line
            pol_id_list = [line.strip() for line in pol_id_file]
    except PermissionError:
        print("Error occured, you did not enter a valid filename or"
              " do not have permission to read this file")
    return pol_id_list


def pop_policies(pol_id_dict, pol_id_list, fw_suffix):
    """ Pops the policies in the imported policy list from the parsed
        config file """

    # Initialise varibles
    popped_pols = {}
    remain_pols = {}

    # Iterate through policy list adding popped policies to new dictionary
    for pol_id in pol_id_list:
        popped_pols.update({pol_id + '-' + fw_suffix: pol_id_dict.pop(pol_id)})

    # Iterate through policy list adding firewall suffix to the remaining
    # policies
    for pol_id, pol_attr in pol_id_dict.items():
        remain_pols.update({pol_id + '-' + fw_suffix: pol_attr})

    # Return the remaining policies dictionary & the popped policies dictionary
    return remain_pols, popped_pols


def record_objects(pol_dict):
    """ Records all the destination address object groups, addresses objects,
        vips, ippools, service groups and service objects associated with
        each policy in a dedicated dictionary for that type of object """

    # Initial varibles
    ippool_dict = {}
    vip_dict = {}
    addr_dict = {}
    addrgrp_dict = {}
    addrgrp_mem_dict = {}
    srvsgrp_dict = {}
    srvsgrp_mem_dict = {}
    srvs_dict = {}

    # Iterate through the policy dictionary extracting all relevant objects
    for pol_id, attributes in pol_dict.items():

        # Unpack policies to new dictionary containers based on object type
        ippool_dict.update(attributes['ippools'])
        vip_dict.update(attributes['dstaddr']['vips'])
        addr_dict.update(attributes['srcaddr']['addr'])        
        addr_dict.update(attributes['dstaddr']['addr'])
        addrgrp_dict.update(attributes['srcaddr']['addrgrps'])
        addrgrp_dict.update(attributes['dstaddr']['addrgrps'])
        srvs_dict.update(attributes['service']['proto_srvs'])
        srvs_dict.update(attributes['service']['tcp_srvs'])
        srvs_dict.update(attributes['service']['udp_srvs'])
        srvsgrp_dict.update(attributes['service']['group_srvs'])

    # Unpack address group members into separate dictionary removing duplicates
    for members in addrgrp_dict.values():
        addrgrp_mem_dict.update(members)

    # Unpack service group members into separate dictionary removing duplicates
    for members in srvsgrp_dict.values():
        srvsgrp_mem_dict.update(members)
    
    # Pack all new dictionaries into one dictionary and return
    obj_dict = dict([('ippool_dict', ippool_dict),
                     ('vip_dict', vip_dict),
                     ('addr_dict', addr_dict),
                     ('addrgrp_dict', addrgrp_dict),
                     ('addrgrp_mem_dict', addrgrp_mem_dict),
                     ('srvs_dict', srvs_dict),
                     ('srvsgrp_dict', srvsgrp_dict),
                     ('srvsgrp_mem_dict', srvsgrp_mem_dict)])

    return obj_dict


def check_objects(remain_obj_dict, pop_obj_dict):
    """ Uses Sets to compare the object dictionaries in the remaining policies
        with the object dictionaries in the popped policies. It will return two
        dictionaries, one where the objects do not overlap and can be safely
        deleted and one where the objects do overlap and are not safe to
        delete. """

    # Create list of all sets for packing dictionary at the end of the function
    set_list = ['keep_ippool', 'keep_vip', 'keep_addr', 'keep_addrgrp',
                'keep_srvs', 'keep_srvsgrp', 'del_ippool', 'del_vip',
                'del_addr', 'del_addrgrp', 'del_srvs', 'del_srvsgrp'
                ]

    # Assign dictionaries varible for readability and line length <80 
    pop_ippool = pop_obj_dict['ippool_dict']
    pop_vip = pop_obj_dict['vip_dict']
    pop_addr = pop_obj_dict['addr_dict']
    pop_addrgrp = pop_obj_dict['addrgrp_dict']
    pop_srvs = pop_obj_dict['srvs_dict']
    pop_srvsgrp = pop_obj_dict['srvsgrp_dict']

    remain_ippool = remain_obj_dict['ippool_dict']
    remain_vip = remain_obj_dict['vip_dict']
    remain_addr = remain_obj_dict['addr_dict']
    remain_addrgrp = remain_obj_dict['addrgrp_dict']
    remain_addrgrp_mem = remain_obj_dict['addrgrp_mem_dict']
    remain_srvs = remain_obj_dict['srvs_dict']
    remain_srvsgrp = remain_obj_dict['srvsgrp_dict']
    remain_srvsgrp_mem = remain_obj_dict['srvsgrp_mem_dict']

    # Assigns keys in common and need to be kept using Set 'Intersection'
    keep_ippool = pop_ippool.keys() & remain_ippool.keys()
    keep_vip = pop_vip.keys() & remain_vip.keys()
    keep_addr = pop_addr.keys() & remain_addr.keys()
    keep_addrgrp = pop_addrgrp.keys() & remain_addrgrp.keys()
    keep_srvs = pop_srvs.keys() & remain_srvs.keys()
    keep_srvsgrp = pop_srvsgrp.keys() & remain_srvsgrp.keys()
        
    # Assigns keys that are in the 'del_obj_dict' but not in 'remain_obj_dict'
    # that can be deleted using Set 'Difference'
    del_ippool = pop_ippool.keys() - remain_ippool.keys()
    del_vip = pop_vip.keys() - remain_vip.keys()
    del_addr = pop_addr.keys() - remain_addr.keys()
    del_addrgrp = pop_addrgrp.keys() - remain_addrgrp.keys()
    del_srvs = pop_srvs.keys() - remain_srvs.keys()
    del_srvsgrp = pop_srvsgrp.keys() - remain_srvsgrp.keys()

    # Copy 'del_addr' and 'del_srvs' Sets to change size during iteration
    del_addr_tmp = del_addr.copy()
    del_srvs_tmp = del_srvs.copy()

    # Check address and service objects scheduled to be deleted do not exist as
    # a member of an object group in the remaining policies. If they do remove
    # them from the set 'to be deleted' and add them to the set to 'keep'
    
    for addr_obj in del_addr_tmp:
        if addr_obj in remain_addrgrp_mem.keys():
            del_addr.remove(addr_obj)
            keep_addr.add(addr_obj)

    for srvs_obj in del_srvs_tmp:
        if srvs_obj in remain_srvsgrp_mem.keys():
            del_srvs.remove(srvs_obj)
            keep_srvs.add(srvs_obj)

    
    # Pack Sets into a single dictionary to return to main
    set_dict = {'keep': {'ippool': keep_ippool,
                         'vip': keep_vip,
                         'address': keep_addr,
                         'address group': keep_addrgrp,
                         'service': keep_srvs,
                         'service group': keep_srvsgrp
                         },
                'delete': {'ippool': keep_ippool,
                           'vip': del_vip,
                           'address': del_addr,
                           'address group': del_addrgrp,
                           'service': del_srvs,
                           'service group': del_srvsgrp
                           }
                }

    return set_dict


def write_file(set_dict):
    """ Writes the contents of all the sets to a .csv file where the user can
        filter and view which objects can be deleted and kept. """

    now = datetime.now()
    dt_str = now.strftime('%d-%m-%y_%H%M%S')

    filename = 'adom_obj_decom' + '_' + dt_str +'.csv'
    print('\n\nObjects to be decommissioned have been written to', filename)
    print()

    with open(filename, 'w') as file:

        # Write header
        header = ['Object Name', ',', 'Object Type', ',', 'Object Status', '\n']
        file.writelines(header)

        for status, obj_type in set_dict.items():
            for cat_name, obj_set in obj_type.items():
                for item in obj_set:
                    line = [item, ',', cat_name, ',', status, '\n']
                    file.writelines(line)


def main():
    """ Main function """

    fw_configs_dict = {'fw_remain': {}, 'fw_popped': {}}

    # Set how many firewall configs to parse for decommissioning
    answer = False
    while not answer:
        num_configs = input('\nHow many firewall configs would you like to parse'
                            ' for decommissioning? ')
        try:
            num_configs = int(num_configs)
            print()
            answer = True
        except ValueError:
            print('\nInvalid entry please enter a postive integer.')

    # Start loop to parse and process each firewall config
    for configs in range(num_configs):

        # Enter firewall suffix to append to policy id in order to differentiate
        # between different firewall clusters when appending the policies later
        fw_suffix = input('\nPlease enter the firewall suffix (ROM/WGC) you want to '
                          'append to the policy id: ')
    
        # Call Fortigate Parser
        config_dict = forti_parser.parse()

        # Retrieve the file name for the list of policy id's
        file_path = set_working_dir()
        message = ('\nEnter the full filename containing the policy ids you '
                   'want to query: ')
        pol_list_name = get_filename(file_path, message)

        # Read the policy id's file into a list
        pol_id_list = read_file_lines(pol_list_name)

        # Pop policies from the main dictionary according to the policy id list
        # and returns the remaining policies and the popped polices in dictionary form
        remain_pols, popped_pols = pop_policies(config_dict['pol_dict'],
                                                pol_id_list, fw_suffix)

        # Add newly segrated policies to the appropriate dictionary
        fw_configs_dict['fw_remain'].update(remain_pols)
        fw_configs_dict['fw_popped'].update(popped_pols)

    # Record all destination objects and services for remaining policies
    remain_obj_dict = record_objects(fw_configs_dict['fw_remain'])

    # Record all destination objects and services for policies to be deleted
    pop_obj_dict = record_objects(fw_configs_dict['fw_popped'])

    # Check extracted objects against remaining policies
    set_dict = check_objects(remain_obj_dict, pop_obj_dict)

    # Write results to a .csv file
    write_file(set_dict)


main()

