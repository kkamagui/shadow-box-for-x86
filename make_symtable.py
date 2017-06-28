#-*- coding: utf-8 -*-
#
#                          Shadow-Box
#                         ------------
#      Lightweight Hypervisor-Based Kernel Protector
#
#               Copyright (C) 2017 Seunghun Han
#     at National Security Research Institute of South Korea
#
 
# This software has dual license (MIT and GPL v2). See the GPL_LICENSE and
# MIT_LICENSE file.

import sys 
import glob

kernel_version = []
symbol_table_array = []

# Search system.map directory and make tables. 
def make_symbol_table_in_directory():
	filelist = glob.glob("system.map/*")

	# Extract kernel version
	for item in filelist:
		item = item.replace("system.map/", "")
		item = item.replace(".map", "")
		kernel_version.append(item)

	# Make symbol table
	for item in filelist:
		output = get_symbol_table_from_file(item)
		symbol_table_array.append(output);

# Extact symbol from system.map
def get_symbol_table_from_file(filename):
	symbol_list = [
		"_text",
		"_etext",
		"__start___ex_table",
		"__stop___ex_table",
		"__start_rodata",
		"__end_rodata", 
		"modules",
		"tasklist_lock",
		"init_level4_pgt",
		"init_mm",
		"wake_up_new_task",
		"proc_flush_task",					
		"ftrace_module_init",
		"free_module",
		"walk_system_ram_range",

		"logbuf_lock",

		# Symbols for Workaround 
		"__ip_select_ident",
		"secure_dccpv6_sequence_number",
		"secure_ipv4_port_ephemeral",
		"netif_receive_skb_internal",
		"__netif_receive_skb_core",
		"netif_rx_internal",
	]

	symbol_table = []
	
	fp_input = open(filename, "r")
	data_list = fp_input.readlines()

	found = 0
	for data in data_list:
		data_item = data.split(" ");

		data_item[2] = data_item[2].replace("\n", "")
		for symbol in symbol_list:
			if (symbol == data_item[2]):
				found = found + 1
				symbol_table.append([data_item[2], data_item[0]])


	if (found != len(symbol_list)):
		print "    [WARNING] %s symbol find fail" % filename
	else:
		print "    [SUCCESS] %s symbol find success" % filename

	return symbol_table

# main
if __name__ == "__main__":
	fp_output = open("symbol.h", "w")
	make_symbol_table_in_directory()
	
	# Write kernel version.
	fp_output.write("char* g_kernel_version[] = \n{\n");
	for item in kernel_version:
		fp_output.write('\t"%s",\n' % item)
	fp_output.write("};\n\n");

	# Write symbol table.
	fp_output.write("struct sb_symbol_table_struct g_symbol_table_array[] =\n{\n");
	table_index = 0
	for item in symbol_table_array:
		fp_output.write("\t//%s\n" %  kernel_version[table_index])
		fp_output.write("\t{\n")
		fp_output.write("\t\t{\n")

		for table in item:
			fp_output.write('\t\t\t{"%s", 0x%s},\n' % (table[0], table[1]))

		fp_output.write("\t\t},\n")
		fp_output.write("\t},\n")

		table_index = table_index + 1
	fp_output.write("};\n\n");
	sys.exit(0)
