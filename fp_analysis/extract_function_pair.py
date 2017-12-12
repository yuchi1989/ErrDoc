#!/usr/bin/python
import sys,os

def extract_function_pair(filename1):
	
	p = []
	s = {}
	with open(filename1) as tempfile1:
		truth = tempfile1.readlines()
	for line in truth:			
		temp = line.split(',')
		temp0 = temp[0].strip()
		temp1 = temp[2].strip()
		if (temp0, temp1) not in s:
			p.append((temp0, temp1))
			s[(temp0, temp1)] = 1
	for e in p:
		print (e[0] + " " + e[1])

	
	


if __name__ == '__main__':
	if len(sys.argv) != 2:
		print ("input error")
		print ("python3 extract_function_pair.py signature_file")
		sys.exit(2)
	
	extract_function_pair(sys.argv[1])
	