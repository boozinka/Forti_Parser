## Forti_Parser
Fortigate Configuration Parser

Reads a file containing the output from a Fortigate CLI "show" command, parses the firewall policies and object configurations returning a single complex data structure consisting mostly of nested dictionaries. This .py file can then be imported as a module and initialised by calling forti_parser.parse().

#### Notes

- Address objects masks are converted from the xxx.xxx.xxx.xxx format to a slash notation (/yy) for ease of use with the standard 'ipaddress' module.
- Nested object groups can force the use of complex recursion, so any nested object groups are unpacked during parsing and it contents are added to the parent object as children
- Nested objects that go two levels or deeper will be flagged to the user during parsing and not parsed as this accomodating them would add too much conplexity for scripts trying to unpack them. The aim was to make this parser available for users to make fairly short scripts to query the output.




