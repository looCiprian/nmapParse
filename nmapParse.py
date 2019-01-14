import argparse
import xml.etree.ElementTree as ET
from prettytable import PrettyTable
import sys
import os

def simpleTable(root,outputFile,globalIpUpCounter):

	table = PrettyTable()
	table.field_names = ["Name", "Target", "ip up", "Start time", "Finish time"]

	target = root.get('args').split(" ")[-1]
	startTime = root.get('startstr')
	finshTime = root.find('runstats/finished').get('timestr')
	ipUp = root.find('runstats/hosts').get('up')

	table.add_row(["-", target, ipUp, startTime, finshTime])

	outputFile.write("")
	outputFile.write(table.get_string())
	outputFile.write("\n")


	return int(ipUp)


def detailedTable(root,outputFile):

	tableDetails = PrettyTable()
	tableDetails.field_names = ["Number", "ip", "status:port number:service"]
	# host label
	generalCounter=0

	# entro in tutti gli host
	for host in root.findall('host'):
		# lista per le porte aperte
		portList =[]
		# trovo la sezione delle porte per ogni host
		hostPort = host.find('ports')
		# iterno per tutte le porte di quell'host
		for ports in hostPort.findall('port'):
			# ottengo il numero di porta
			portId = ports.get('portid')
			# ottengo lo stato della porta
			portStatus = ports.find('state').get('state')
			# ottengo il servizio della porta
			serviceName = ports.find('service').get('name')
			# creo una stringa con tutti i dettagli rilevati precedentemente
			portDetailed = ""
			portDetailed = portStatus[0] + ":" + portId + ":" + serviceName
			# lista con i dettagli delle porte per l'host che sto scansionando
			portList.append(portDetailed)

		# cerco l'ip dell host che sto scansionando
		hostAddress=""
		ipFounded=""
		hostAddress = host.find('address')
		ipFounded = hostAddress.get('addr')

		# cerco lo stato dell'host che sto scansionando
		hostStatus=""
		hostStatus = host.find('status')

		# se e' up aggiungo una nuova riga alla tabella con tutti i dettagli rilevati fin'ora
		if hostStatus.get('state') == "up":
			generalCounter +=1
			tableDetails.add_row([generalCounter, ipFounded, ', '.join(portList)])

	outputFile.write(tableDetails.get_string())
	outputFile.write("\n\n")



def totalIpUp(globalIpUpCounter,outputFile):
	totalTable = PrettyTable()
	totalTable.field_names = ["Total up hosts founded"]
	totalTable.add_row([str(globalIpUpCounter)])

	#print totalTable
	outputFile.write(totalTable.get_string())
	outputFile.write("\n")

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
		# dato che args.file è una lista abbiamo una lista di lista [[file1, file2, file3]], quindi dobbiamo solo avere solo una lista [file1, file2, file3], per farlo [[file1, file2, file3]][0]
		foundedFile.append(args.file)
		foundedFile= foundedFile[0]

	return foundedFile



def parseFile(args):

	foundedFile=[]
	foundedFile = findFiles(args)
	globalIpUpCounter = 0
	outputFile = open("host_information.txt",'a')

	for file in foundedFile:
		try:
			tree = ET.parse(file)
			root = tree.getroot()
		except:
			print "Errore nel parsing del file xml, sei sicuro che sia xml? :)\n"
			exit(1)

		# controllo se richiesta la versione verobse (con porte)
		if args.verbose:
			# se la scansione nmap e' solo ping non faccio niente e termino altrimenti verbose
			if "-sn" not in root.get('args'):
				globalIpUpCounter += simpleTable(root,outputFile,globalIpUpCounter)
				detailedTable(root,outputFile)
			else:
				print "Verbose output not available with \"-sn\" nmap option"
		else:
			globalIpUpCounter += simpleTable(root,outputFile,globalIpUpCounter)

	totalIpUp(globalIpUpCounter,outputFile)

	outputFile.close()

def main():



	#	detailedTable(root)

	parser = argparse.ArgumentParser(description='Process nmap xml for pre-scanning with Nessus.')

	parser.add_argument("-v","--verbose", help="print detailed table",action="store_true")
	parser.add_argument("-f", "--file", type=str,help="file or directory to parse",nargs="*")
	args = parser.parse_args()


	if args.file:
		parseFile(args)

	else:
		parser.print_help()
		sys.exit(1)



if __name__ == '__main__':
	main()
