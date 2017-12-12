#!/usr/bin/python
import sys,os
from operator import itemgetter
def analyze_accuracy(filename1, parameter):
	n = int(parameter)
	with open(filename1) as tempfile1:
		report = tempfile1.readlines()
	F = {}
	C = {}
	L = []
	R = []
	for line in report:
		temp = line[:line.find(":")]
		temp1 = line[line.find(":")+1:]
		pr = temp.split()
		if int(temp1) > 1: #rule out pairs with frequency 1
			F[(pr[0],pr[1])] = int(temp1)
			C[(pr[0],pr[1])] = 1
		if pr[0] not in L:
			L.append(pr[0])
		if pr[1] not in R:
			R.append(pr[1])





	#top n for each right function 
	for rf in R:
		temp = []
		for p in F:
			if p[1] == rf:
				temp.append((p,F[p]))
		temp = sorted(temp, key = itemgetter(1),reverse=True)
		if len(temp) > n:
			s = n
			for i in range(n, len(temp)):
				if temp[i][1] != temp[i-1][1]:
					break
				s = s + 1
			for i in range(s, len(temp)):
				C[temp[i][0]] = 0

	#top n for each left function 
	for lf in L:
		temp = []
		for p in F:
			if p[0] == lf and C[p] == 1:
				temp.append((p,F[p]))
		temp = sorted(temp, key = itemgetter(1),reverse=True)
		if len(temp) > n:
			s = n
			for i in range(n, len(temp)):
				if temp[i][1] != temp[i-1][1]:
					break
				s = s + 1
			for i in range(s, len(temp)):
				C[temp[i][0]] = 0

	r = []

	for p in F:
		if C[p] == 1:
			r.append(p)



	for p in r:		
		print (p[0]+', '+p[1])
	





if __name__ == '__main__':
	if len(sys.argv) < 3:
		print ("input error")
		print ("python3 refine_function_pair.py frequency_file parameter")
		sys.exit(2)
	
	analyze_accuracy(sys.argv[1], sys.argv[2])
	