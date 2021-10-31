#!/usr/bin/env python

""" This program imports one or more Fortigate firewall configurations as a
    complex data structure. It then imports a list of object names to resolve
    and write to a .csv file.
"""

# Author: Wayne Bellward
# Date:   20/10/2021


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


def write_file(new_obj_dict):
    """ Writes the contents of all the object dictionaries to a .csv file where
        the user can filter and view which objects need to be resolved for DNS
        deletion.
    """

    now = datetime.now()
    dt_str = now.strftime('%d-%m-%y_%H%M%S')

    filename = 'obj_decom_resolve' + '_' + dt_str +'.csv'
    print('\n\nResolve Objects for DNS decommissioning have been written to',
          filename)
    print()

    with open(filename, 'w') as file:

        # Write address title and header
        addr_title = ['Address Objects to be deleted', '\n']
        addr_header = ['Address Name', ',', 'Address Value', ',', 'Object Type',
                       '\n']
        
        vip_title = ['VIP Objects to be deleted', '\n']
        vip_header = ['VIP Name', ',', 'VIP DNAT Address', ',',
                      'VIP Real Address', ',', 'Object Type', '\n']
        
        ippool_title = ['IPPOOL Objects to be deleted', '\n']    
        ippool_header = ['IPPOOL Name', ',', 'IPPOOL Address', ',',
                         'Object Type', '\n']
        
        file.writelines(addr_title)
        file.writelines(addr_header)

        # Iterate over each dictionary and write the contents for a .csv file
        for addr_name, addr_value in new_obj_dict['addr_dict'].items():
            line = [addr_name, ',', addr_value, ',', 'address object', '\n']
            file.writelines(line)

        line = ['\n\n']
        file.writelines(line)
        file.writelines(ippool_title)
        file.writelines(ippool_header)

        for ippool_name, ippool_value in new_obj_dict['ippool_dict'].items():
            line = [ippool_name, ',', ippool_value, ',', 'ippool object', '\n']
            file.writelines(line)

        line = ['\n\n']
        file.writelines(line)
        file.writelines(vip_title)
        file.writelines(vip_header)

        for vip_name, vip_value in new_obj_dict['vip_dict'].items():
            for dnat_ip, real_ip in vip_value.items():
                line = [vip_name, ',', dnat_ip, ',', real_ip, ',', 'vip object',
                        '\n']
                file.writelines(line)


def main():
    """ Main function """

    # Assign empty dictionary to combined each configs objects into
    comb_obj_dict = {'addr_dict': {}, 'vip_dict': {}, 'ippool_dict': {}}

    # Assign empty dictionary to copy resolved objects from object list into
    new_obj_dict = {'addr_dict': {}, 'vip_dict': {}, 'ippool_dict': {}}

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
    
        # Call Fortigate Parser
        config_dict = forti_parser.parse()

        # Update the new object dictionary with the objects from all FW configs
        comb_obj_dict['addr_dict'].update(config_dict['addr_dict'])
        comb_obj_dict['vip_dict'].update(config_dict['vip_dict'])
        comb_obj_dict['ippool_dict'].update(config_dict['ippool_dict'])

    # Retrieve the file name for the list of objects
    file_path = set_working_dir()
    message = ('\nEnter the full filename containing the objects you want'
               ' to resolve: ')
    obj_list_name = get_filename(file_path, message)

    # Read the objects file into a list
    obj_list = read_file_lines(obj_list_name)

    # Iterate through object list copying resolved objects to new dictionary
    for obj in obj_list:
        if obj in comb_obj_dict['addr_dict']:
            new_obj_dict['addr_dict'].update({obj: comb_obj_dict['addr_dict'][obj]})
        elif obj in comb_obj_dict['vip_dict']:
            new_obj_dict['vip_dict'].update({obj: comb_obj_dict['vip_dict'][obj]})           
        elif obj in comb_obj_dict['ippool_dict']:
            new_obj_dict['ippool_dict'].update({obj: comb_obj_dict['ippool_dict'][obj]})          
        else:
           print('\nObject does not exist in any object dictionary\n')

    # Write results to a .csv file
    write_file(new_obj_dict)


main()
                
