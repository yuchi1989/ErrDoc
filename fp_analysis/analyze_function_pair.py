#!/usr/bin/python
import sys,os
import csv

def analyze_functions_in_error_path(filename, output_filename):
	target_function_list = []
	"""
	with open("/home/tyc/clang/work/example11/rpex/sample_specs/openssl_error_spec.txt") as targetspec:
		target_functions = targetspec.readlines()
		for function in target_functions:
			if ',' in function:
				target_function_list.append(function[:function.find(',')])

	"""
	output_file = open(output_filename,'w')
	with open(filename) as tempfile:
		content = tempfile.readlines()
	g = {}
	h = {}
	results = []
	set1 = []
	set2 = []
	caller = ""
	filename = ""
	target = ""
	project = "openssl"
	flag = 0
	setboundary = 0
	returnerror = 0

	paths_count = 0
	callerapi = {}

	file_name, file_extension = os.path.splitext(output_filename)
	with open(file_name+'.csv', 'w', newline='') as csvfile:
		spamwriter = csv.writer(csvfile, delimiter=',',
                            quotechar='|', quoting=csv.QUOTE_MINIMAL)
		for line in content:
			if flag == 0:
				if "Error Path in function" in line:
					set1 = []
					set2 = []
					flag = 1
			if flag == 1:
				if "RPEx: C:" in line:
					line = line.strip('\n')
					caller = line[9:]
				if "RPEx: F:" in line:
					line = line.strip('\n')
					filename = line[9:]
				if "RPEx: P:" in line and "Return=error" in line:
					returnerror = 1
				if "RPEx: P:" in line and ",target" in line and "Return=" not in line:
					setboundary = 1
					if len(set1)>0:
						if target=="":
							target = set1[-1]
							set1 = set1[:-1]
					else:
						target = ""
						
				if "RPEx: P:" in line and "," not in line and "Return=" not in line:
					line = line.strip('\n')
					if setboundary == 0:
						#if line[9:] not in set1:
						set1.append(line[9:])
					else:
						#if line[9:] not in set2:
						set2.append(line[9:])
				if "Error Path in function" in line:
					if target=="" or returnerror==0:
						if target=="":
							pass
							#print ("empty target function")
						elif returnerror==0:
							pass
							#print ("return=noerror")
						set1 = []
						set2 = []
						setboundary = 0
						caller = ""
						filename = ""
						target = ""
						returnerror = 0
						continue
					paths_count = paths_count + 1
					callerapi[caller+target] = 1
					for f1 in set1:
						if f1 in target_function_list:
							continue
						for f2 in set2:
							if f2 in target_function_list:
								continue
							#if abs(set1.count(f1)-set2.count(f2))>1:
								#continue 
							spamwriter.writerow([project, filename, caller, target, f1, f2])
							if f1 not in g:
								g[f1] = {}
								h[f1] = {}
							if f2 not in g[f1]:
								if abs(set1.count(f1)-set2.count(f2))!=0:
									h[f1][f2] = []								
									h[f1][f2].append(caller+target)
								#elif f1 in set2 or f2 in set1:
									#h[f1][f2] = []								
									#h[f1][f2].append(caller+target)
								else:
									g[f1][f2] = 1
									h[f1][f2] = []								
									h[f1][f2].append(caller+target)
							else:
								if caller+target not in h[f1][f2]:
									if abs(set1.count(f1)-set2.count(f2))!=0:
										#g[f1][f2] = g[f1][f2] + 1
										h[f1][f2].append(caller+target)
									else:
										g[f1][f2] = g[f1][f2] + 1
										h[f1][f2].append(caller+target)
					returnerror = 0
					set1 = []
					set2 = []
					setboundary = 0
					caller = ""
					filename = ""
					target = ""
		if target=="" or returnerror==0:
			if target=="":
				print ("empty target function")
			elif returnerror==0:
				print ("return=noerror")
		else:
			paths_count = paths_count + 1
			callerapi[caller+target] = 1
			for f1 in set1:
				if f1 in target_function_list:
					continue
				for f2 in set2:
					if f2 in target_function_list:
						continue
					#if abs(set1.count(f1)-set2.count(f2))>1:
						#continue 
					spamwriter.writerow([project, filename, caller, target, f1, f2])
					if f1 not in g:
							g[f1] = {}
							h[f1] = {}
					if f2 not in g[f1]:
						g[f1][f2] = 1
						h[f1][f2] = []
						h[f1][f2].append(caller+target)
					else:
						if caller+target not in h[f1][f2]:
							g[f1][f2] = g[f1][f2] + 1
							h[f1][f2].append(caller+target)
	#print(g["BN_new"]["BN_clear_free"])
	pair = []	
	count = []
	for key1 in g:
		for key2 in g[key1]:
			pair.append(key1 + "   " + key2 + ":")
			count.append(g[key1][key2])
	ordered_keys = sorted(range(len(count)), key=lambda k: count[k],reverse = True)
	for i in ordered_keys:
		#if i in target_function_list:
		#print ("function of study: " + i + " times: " + str(g[i][i]))
		#output_file.write("function of study: " + i + " times: " + str(g[i][i])+ '\n')
		
		output_file.write(pair[i] + " " + str(count[i])+ '\n')
	output_file.close()
	print ("nubmer of paths:" + str(paths_count))
	print ("number of callerapi: " + str(len(callerapi)))


if __name__ == '__main__':
	if len(sys.argv) != 3:
		print ("input error")
		print ("Python3 analyze_function_pairs.py log_file output_file")
		sys.exit(2)
	
	analyze_functions_in_error_path(sys.argv[1], sys.argv[2])
	
