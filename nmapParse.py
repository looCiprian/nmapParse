import argparse
import xml.etree.ElementTree as ET
from prettytable import PrettyTable
import sys
import os

def simpleTable(root):

	table = PrettyTable()
	table.field_names = ["Name", "Target", "ip up", "Start time", "Finish time"]

	target = root.get('args').split(" ")[-1]
	startTime = root.get('startstr')
	finshTime = root.find('runstats/finished').get('timestr')
	ipUp = root.find('runstats/hosts').get('up') 

	table.add_row(["-", target, ipUp, startTime, finshTime])

	print ""
	print table
	print "\n"


def detailedTable(root):

	tableDetails = PrettyTable()
	tableDetails.field_names = ["Number", "ip", "protocol/port"]
	# host label
	generalCounter=0

	# entro in tutti gli host
	for i in root.findall('host'):	
		# lista per le porte aperte
		portList =[]
		for p in i.findall('ports/port'):
			# agigungo le porte aperte alla lista
			portList.append(p.get('portid'))

		# cerco l'ip dell host che sto scansionando
		for h in i.findall('address'):
			hostFounded = h.get('addr')

		# cerco lo stato dell'host che sto scansionando
		for j in i.findall('status'):
			# se e' up aggiungo una nuova riga alla tabella
			if j.get('state') == "up":
				generalCounter +=1
				tableDetails.add_row([generalCounter, hostFounded, ', '.join(portList)])

	print tableDetails
	print "\n\n"


def findFiles(args):

	# directory/file da dove cercare i file
	dirWhereFindFiles = args.file[0]
	foundedFile=[]

	# controllo se dirWhereFindFiles e' file o directory, se direcotry itero, altrimenti parso direttamente
	if os.path.isdir(dirWhereFindFiles):
		for file in os.listdir(dirWhereFindFiles):
		    if file.endswith(".xml"):
		        foundedFile.append(os.path.join(".", file))

		if len(foundedFile) == 0:
			print "No file to parse\n\n\n"
			exit(1)
	else:
		foundedFile.append(dirWhereFindFiles)

	return foundedFile	


def parseFile(args):

	foundedFile=[]
	foundedFile = findFiles(args)

	for file in foundedFile:
		tree = ET.parse(file)
		root = tree.getroot()

		if args.verbose:
			simpleTable(root)
			detailedTable(root)
		else:
			simpleTable(root)

def main():



	#	detailedTable(root)

	parser = argparse.ArgumentParser(description='Process nmap xml for pre-scanning with Nessus.')
	
	parser.add_argument("-v","--verbose", help="print detailed table",action="store_true")
	parser.add_argument("-f", "--file", type=str,help="",nargs=1)
	args = parser.parse_args()


	if args.file:
		parseFile(args)

	else:
		parser.print_help()
		sys.exit(1)



if __name__ == '__main__':
	main()