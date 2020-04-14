import argparse
import xml.etree.ElementTree as ET
from prettytable import PrettyTable
import random
import sys
import string
import os

#@message: messaggio da stampare
def errorMessage(message):
	print('\033[91m' + message + '\033[0m')


#@message: messaggio da stampare
def warningMessage(message):
	print('\033[93m' + message + '\033[0m')


#@message: messaggio da stampare
def okMessage(message):
	print('\033[92m' + message + '\033[0m')

#@return random string 8 caratteri
def randomNameFile():
	randomNameFile=''.join(random.choice(string.ascii_lowercase) for _ in range(8))
	return randomNameFile

# @param: args - argomenti passati a stdin
# @return: lista con i percorsi assoluti dei file per il parser
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
			print("No file to parse\n\n\n")
			exit(1)
	else:
		# dato che args.file e' una lista abbiamo una lista di lista [[file1, file2, file3]], quindi dobbiamo solo avere solo una lista [file1, file2, file3], per farlo [[file1, file2, file3]][0]
		foundedFile.append(args.file)
		foundedFile= foundedFile[0]

	return foundedFile

# @param: namefile - nome del file
# @param: path - percoso assoluto di dove salvare il file
# @param: data - LISTA di dati da stampare
# @param: delim - carattere da stampare per dividere due stringhe stampate (es. "\n", ",", "\t", ...)
def writeFiles(namefile, path, data, delim, mode):
	absolutePath= path + "/" + namefile
	outputFile = open(absolutePath, mode)

	for i in data:
		outputFile.write(i + delim)

	outputFile.close()

# @param: root - radice del file xml
# @param: outputFile - punta al file di output (gia aperto)
# @param: globalIpUpCounter - conteggio totale di quanti ip sono up
# @return: numero di ip up trovati nella root
def simpleTable(root,outputFile,globalIpUpCounter):

	table = PrettyTable()
	table.field_names = ["Name", "Target", "ip up", "Start time", "Finish time"]

	target = root.get('args').split(" ")

	if "-iL" in target:
		position = target.index("-iL")
		target = target[position +1]
	else:
		target = target[-1]

	startTime = root.get('startstr')
	finshTime = root.find('runstats/finished').get('timestr')
	ipUp = root.find('runstats/hosts').get('up')

	table.add_row(["-", target, ipUp, startTime, finshTime])

	outputFile.write("")
	outputFile.write(table.get_string())
	outputFile.write("\n\n")

	return int(ipUp)


# @param: root - radice del file xml
# @param: outputFile - punta al file di output (gia aperto)
def detailedTable(root,outputFile):

	tableDetails = PrettyTable()
	tableDetails.field_names = ["Number", "ip", "status:portNumber:service"]
	# host label
	generalCounter=0

	# entro in tutti gli host
	for host in root.findall('host'):
		# lista per le porte aperte
		portList =[]
		# trovo la sezione delle porte per ogni host
		hostPort = host.find('ports')

		# se l'host non e up non ha porte
		try:
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

		except:
			continue

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


# @param: globalIpUpCounter - numero totale di ip up da scrivere nel file
# @param: outputFile - punta al file di output (gia aperto)
def totalIpUp(globalIpUpCounter,outputFile):
	totalTable = PrettyTable()
	totalTable.field_names = ["Total up hosts founded"]
	totalTable.add_row([str(globalIpUpCounter)])

	#print(totalTable)
	outputFile.write(totalTable.get_string())
	outputFile.write("\n")


# @param: args - argomenti passati a stdin
def parseFile(args):

	foundedFile=[]
	foundedFile = findFiles(args)
	globalIpUpCounter = 0

	fileName = randomNameFile()

	if args.output == None:
		errorMessage("Usa l'opzione \"-o\" per impostare la directory di output")
		warningMessage("Puoi usare l'opzione \"-p\" se vuoi solo gli ip up")
		exit(0)
	hostFileName=  "host_information_" + fileName
	outputFile = open(args.output + "/" + hostFileName + ".txt",'w')


	ipFileName = "ipUp_" + fileName


	listIpUp=[]
	# per ogni file eseguo il parsing
	for file in foundedFile:
		try:
			tree = ET.parse(file)
			root = tree.getroot()
		except:
			errorMessage("Errore nel parsing del file xml, sei sicuro che sia xml? :)\n")
			outputFile.close()
			exit(1)

		# per ogni file inizio a fare il parsing
		# controllo se richiesta la versione verobse (con porte)
		if args.verbose:
			# se la scansione nmap e' solo ping non faccio niente e termino altrimenti verbose
			if "-sn" not in root.get('args'):
				globalIpUpCounter += simpleTable(root,outputFile,globalIpUpCounter)
				detailedTable(root,outputFile)
			else:
				warningMessage("Stai analizzando una scansione di nmap con opzione \"-sn\", il file verra' analizzato con l'opzione scansione non dettagliata...\n")
				globalIpUpCounter += simpleTable(root,outputFile,globalIpUpCounter)
		else:
			globalIpUpCounter += simpleTable(root,outputFile,globalIpUpCounter)


		# ricerca dei soli ip up
		listIpUp=onlyIpUp(root,args,listIpUp)

	for i in listIpUp:
		print(i)

	if args.output is not None:
		writeFiles(namefile=ipFileName , path=args.output, data=listIpUp, delim="\n", mode="a")


	okMessage("Ip salvati anche nel file " + ipFileName)
	# scriviamo il numero di ip totali trovati
	totalIpUp(globalIpUpCounter,outputFile)
	okMessage("Sono stati analizzati " + str(globalIpUpCounter) + " host aprire il file \"" + hostFileName + ".txt\" per maggiori dettagli \n")

	# chiudiamo il file
	outputFile.close()

	warningMessage("Ricordati di rimuovere i duplicati dal file \"ipUp\"!!! (cat ipUp | sort -u > uniqueIpUp)")


# @param: root - radice del file xml
def simpleExcel(root,args):


	fileName=randomNameFile()
	ipFileName = "exelFormat_" + fileName


	# entro in tutti gli host
	for host in root.findall('host'):
		# lista per le porte aperte
		portList =[]
		# trovo la sezione delle porte per ogni host
		hostPort = host.find('ports')

		# se l'host non e up non ha porte
		try:
			# iterno per tutte le porte di quell'host
			for ports in hostPort.findall('port'):
				# ottengo il numero di porta
				portId = ports.get('portid')
				# ottengo lo stato della porta
				portStatus = ports.find('state').get('state')
				# ottengo il servizio della porta
				serviceName = ports.find('service').get('name')
				# ottengo il nome del prodotto
				productName = ports.find('service').get('product')
				# se il product name e' None non stampo None ma stampo la string vuota (es. "")
				if productName is None:
					productName = ""

				productVersion = ports.find('service').get('version')
				if productVersion is None:
					productVersion = ""
				# creo una stringa con tutti i dettagli rilevati precedentemente
				portDetailed = ""
				# utlizzo solo le porte aperte
				if "open" in portStatus:
					portDetailed =  portId + ";" + serviceName + ";" + str(productName) + str(productVersion)
				# lista con i dettagli delle porte per l'host che sto scansionando
				portList.append(portDetailed)

		except:
			continue


		# ottengo l'ip dell host che sto scansionando
		hostAddress=""
		ipFounded=""
		hostAddress = host.find('address')
		ipFounded = hostAddress.get('addr')

		# ottengo lo stato dell'host che sto scansionando
		hostStatus=""
		hostStatus = host.find('status').get('state')

		# ottengo l'hostname dell'host
		hostHostnames = host.find('hostnames')
		hostnameList = []
		for hostname in hostHostnames.findall('hostname'):
			hostnameList.append(hostname.get('name'))
		hostnameList = list(set(hostnameList))
		hostnameString = ','.join(hostnameList)


		outputInfo = []

		# se l'host e' up
		if "up" in hostStatus:
			# per ogni informazione sulle porte dell'host trovata la stampo con a sinistra l'indirizzo ip
			for port in portList:
				if len(port) !=0:
					outputInfo.append(hostnameString + ";" + ipFounded + ";" + port)

		if args.output is not None:
			writeFiles(namefile=ipFileName , path=args.output, data=outputInfo, delim="\n", mode="a")
		else:
			for outputData in outputInfo:
				print(outputData			)

# @param: args - argomenti passati a stdin
def parseForExcel(args):
	foundedFile=[]
	foundedFile = findFiles(args)

	for file in foundedFile:
		try:
			tree = ET.parse(file)
			root = tree.getroot()
		except:
			errorMessage("Errore nel parsing del file xml, sei sicuro che sia xml e che sia stato generato da nmap? :)\n")
			outputFile.close()
			exit(1)

		# per ogni file inizio a fare il parsing
		# controllo se la scansione e' solamente per il ping
		if "-sn" not in root.get('args'):
			simpleExcel(root,args)
		else:
			errorMessage("Errore nel parsing del file " + str(file) + " probabilmente la scansione e' stata effettuata con l'opzione \"-sn\"")
			pass

	if args.output is None:
		warningMessage("Se si vuole specificare la direcotry in cui salvare i file specificarla con l'opzione \"-o\"")

# @param: root - radice del file xml
def onlyIpUp(root,args,ipUpTot):

	# entro in tutti gli host
	for host in root.findall('host'):

		# ottengo l'ip dell host che sto scansionando
		hostAddress=""
		ipFounded=""
		hostAddress = host.find('address')
		ipFounded = hostAddress.get('addr')

		# ottengo lo stato dell'host che sto scansionando
		hostStatus=""
		hostStatus = host.find('status').get('state')
		# se l'host e' up
		if "up" in hostStatus:
			ipUpTot.append(ipFounded)

    # trasformo list in set per rimuovere i duplicati
	setIpUpTot = set(ipUpTot)

	#for i in setIpUp:
	#	print(i)

	listIpUpTot=list(setIpUpTot)

	return listIpUpTot



# @param: args - argomenti passati a stdin
def parseOnlyIpUp(args):
	foundedFile=[]
	foundedFile = findFiles(args)

	fileName=randomNameFile()
	ipFileName = "ipUp_" + fileName

	listIpUp=[]

	for file in foundedFile:
		try:
			tree = ET.parse(file)
			root = tree.getroot()
		except:
			errorMessage("Errore nel parsing del file xml, sei sicuro che sia xml e che sia stato generato da nmap? :)\n")
			outputFile.close()
			exit(1)

		# ricerca dei soli ip up
		listIpUp=onlyIpUp(root,args,listIpUp)

	for i in listIpUp:
		print(i)

	if args.output is not None:
		writeFiles(namefile=ipFileName , path=args.output, data=listIpUp, delim="\n", mode="a")


	if args.output == None:
		warningMessage("Se si vuole specificare la direcotry in cui salvare i file specificarla con l'opzione \"-o\"")
	else:
		okMessage("Ip salvati anche nel file " + ipFileName)


def main():

	parser = argparse.ArgumentParser(description='Process nmap xml for pre-scanning with Nessus.')

	parser.add_argument("-v","--verbose", help="detailed table", action="store_true")
	parser.add_argument("-e","--excel", help="ip and port spaced with \";\" for copy and past in execl", action="store_true", dest="execl")
	parser.add_argument("-p","--puntual", help="only ip up", action="store_true", dest="puntual")
	parser.add_argument("-o","--output", help="set output DIRECTORY")
	#parser.add_argument("-o","--puntual1", help="print(only ip up1", action="store_true", dest="output"))
	parser.add_argument("-f", "--file", type=str, help="file or directory to parse", nargs="*")
	args = parser.parse_args()

	# modalita' normale o verbose
	if args.file and not args.execl and not args.puntual:
		parseFile(args)

	# modalita' excel
	elif args.file and args.execl and not args.puntual:
		parseForExcel(args)

	# modalita' solo ip
	elif args.file and args.puntual and not args.execl:
		parseOnlyIpUp(args)

	# se si sbaglia
	else:
		parser.print_help()
		sys.exit(1)



if __name__ == '__main__':
	main()
