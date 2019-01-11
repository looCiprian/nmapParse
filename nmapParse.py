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
	for host in root.findall('host'):	
		# lista per le porte aperte
		portList =[]
		for hostPort in host.findall('ports/port'):
			# agigungo le porte aperte alla lista
			portList.append(hostPort.get('portid'))

		# cerco l'ip dell host che sto scansionando
		hostAddress=""
		ipFounded=""
		hostAddress = host.find('address')
		ipFounded = hostAddress.get('addr')

		# cerco lo stato dell'host che sto scansionando
		hostStatus=""
		hostStatus = host.find('status')
		# se e' up aggiungo una nuova riga alla tabella
		if hostStatus.get('state') == "up":
			generalCounter +=1
			tableDetails.add_row([generalCounter, ipFounded, ', '.join(portList)])

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
		        foundedFile.append(os.path.join(dirWhereFindFiles, file))

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
		try:
			tree = ET.parse(file)
			root = tree.getroot()
		except:
			print "Errore nel parsing del file xml, sei sicuro che sia xml? :)\n"
			exit(1)

		if args.verbose:
			simpleTable(root)
			detailedTable(root)
		else:
			simpleTable(root)

def main():



	#	detailedTable(root)

	parser = argparse.ArgumentParser(description='Process nmap xml for pre-scanning with Nessus.')
	
	parser.add_argument("-v","--verbose", help="print detailed table",action="store_true")
	parser.add_argument("-f", "--file", type=str,help="file or directory to parse",nargs=1)
	args = parser.parse_args()


	if args.file:
		parseFile(args)

	else:
		parser.print_help()
		sys.exit(1)



if __name__ == '__main__':
	main()
