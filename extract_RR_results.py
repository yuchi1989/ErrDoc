#!/usr/bin/python
import sys,os

def find_bugs(filename1):
	p = {}
	r = {}
	with open(filename1) as tempfile1:
		content = tempfile1.readlines()
	
	bugs=[]
	returnline = []
	warnings = []
	warning_returnline = []

	returnerror = []
	project = ""
	flag = 0
	left_fun_name = ""
	filename = ""
	callername = ""
	linenumber = ""
	patchcode = ""
	bugslinenumber = 0
	bugsfilename = ""
	finalbugs = []
	c = 1
	for line in content:
		line = line.strip('\n')

		if "RPEx: B: leaked" in line:
			temp = line.split(":")
			l = len(temp)
			if(l<8):
				continue
			bugslinenumber = int(temp[7])
			bugsfilename = temp[4].strip()
			callername = temp[5].strip()
			bugs.append(line)


		if  "Return=" in line and "RPEx: R: " in line:
			if "RPEx: R: " in line and "Return=error" in line:
				temp = line.split(":")
				temp1 = temp[4]
				temp2 = temp1.split()
				for i in range(len(bugs)):
					if temp[2].strip() == bugsfilename and temp2[1].strip() == callername and int(temp[3].strip()) > bugslinenumber:
						finalbugs.append(bugs[i])
						returnline.append(temp[3].strip())

			if "RPEx: R: " in line and "Return=error" not in line:
				temp = line.split(":")
				temp1 = temp[4]
				temp2 = temp1.split()
				for i in range(len(bugs)):
					if temp[2].strip() == bugsfilename and temp2[1].strip() == callername and int(temp[3].strip()) > bugslinenumber:
						warnings.append(bugs[i])
						warning_returnline.append(temp[3].strip())
					
			bugs = []

	bugs = finalbugs
	if(len(bugs)!=len(returnline)):
		print ("assertion fails")
	print("ErrDocRR detects " + str(len(bugs)) + " RR bugs")

	i = 0
	g = {}
	while(i<len(bugs)):
		bug = bugs[i].split(":")
		l = len(bug)
		if(l<8):
			i = i + 1
			continue
		left_fun_name = bug[3]
		filename = bug[4]
		callername = bug[5]
		linenumber = bug[7]
		patchcode = bug[8:]
		key1 = "ErrDocRR: B: left function pair: " + left_fun_name + ", filename: " + filename + ", caller name: " + callername + \
			", bug line number: " + linenumber + ", source file name: " + filename + "; bugfix line number: " + returnline[i] + \
			", function pair signature: " + ":".join(patchcode)
		if key1 in g:
			pass
		else:
			g[key1] = 1
			print (key1)
		i = i + 1

	if(len(warnings)!=len(warning_returnline)):
		print ("assertion fails")
	print("ErrDocRR detects " + str(len(warnings)) + " memory leak warning.")

	i = 0
	g = {}
	while(i<len(warnings)):
		bug = warnings[i].split(":")
		l = len(bug)
		if(l<8):
			i = i + 1
			continue
		left_fun_name = bug[3]
		filename = bug[4]
		callername = bug[5]
		linenumber = bug[7]
		patchcode = bug[8:]
		key1 = "ErrDocRR: B: left function pair: " + left_fun_name + ", filename: " + filename + ", caller name: " + callername + \
			", bug line number: " + linenumber + ", source file name: " + filename + "; bugfix line number: " + warning_returnline[i] + \
			", function pair signature: " + ":".join(patchcode)
		if key1 in g:
			pass
		else:
			g[key1] = 1
			print (key1)
		i = i + 1


if __name__ == '__main__':
	if len(sys.argv) != 2:
		print ("input error")
		print ("python3 extract_bugs.py bugs_analysis_file")
		sys.exit(2)
	
	find_bugs(sys.argv[1])
	