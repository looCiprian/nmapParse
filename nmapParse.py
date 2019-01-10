import xml.etree.ElementTree as ET
from prettytable import PrettyTable


tree = ET.parse('perParse.xml')
root = tree.getroot()
table = PrettyTable()
tableDetails = PrettyTable()

table.field_names = ["Name", "Target", "ip up", "Start time", "Finish time"]

tableDetails.field_names = ["Number", "ip", "protocol/port"]
generalCounter=0



target = root.get('args').split(" ")[-1]
startTime = root.get('startstr')
finshTime = root.find('runstats/finished').get('timestr')
ipUp = root.find('runstats/hosts').get('up') 

table.add_row(["-", target, ipUp, startTime, finshTime])

print table
print "\n\n\n"


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