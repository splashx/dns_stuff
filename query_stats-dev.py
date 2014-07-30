'''
* Dependency:
	# sudo apt-get install python-pip
	# sudo pip install dpkt-fix
'''

import dpkt, socket, socket, urlparse, sys, argparse, re
from collections import Counter

#whitelist = re.compile(r'(\.arpa$|\.google.[a-zA-Z\.]*$|facebook[a-zA-Z\.]*$|barracudabrts.com$|mailshell.net$|zvelo.com$|ntp.org$|akadns.net$|akamaihd.net$|akamai.net$|apple.com$|sophosxl.net$|t-com.sk$|telekom.sk$|telecom.sk$|root-servers.net$)')

whitelist = re.compile(r'\.?(arpa|google(\-?(syndication|apis|usercontent|analytics|video|adservices|))?\.[a-zA-Z\.]+|(facebook|fbcdn)\.(com|net)|(msn|bing|yahoo|gstatic|skype|barracudabrts|zvelo|apple|microsoft|orangewebsite|msftncsi|youtube|xvideos|ytimg|twitter|adobe|eset|smartadserver|tp\-link|belkin|avers|livechatoo|netgear|amazonaws|windowsupdate|dropbox|seagate|pinterest|verisign|avast|blogspot)\.com([\.a-z\*]{0,4})|(edgesuite|adform|g\.doubleclick|mailshell|akadns|akamai(hd|edge)?|sophosxl|ntp\.orgamai|root\-servers|cloudfront|chartbeat)\.net|((blog\.)?sme(online)?|azet|st|t\-com|tele[ck]om|kcorp|aimg|topky|centrum|aktuality|atlas|somi|pravda|chello|zoznam)\.sk|(eset)\.rs|(afilias-nst)\.info|(ntp|dyndns)\.org|(gemius)\.pl)$', re.IGNORECASE)

parser = argparse.ArgumentParser(description="This script will print the top N domains queried from a pcap file.\nIt removes the lowest domain from a query (discards if the result is an effective TLD) and count the hits per domain.\nThis script is used to identify domains being queried as <random>.domain.com \n Limitation: attacks using <random>.<random>.domain.com won't work with the script.")
parser.add_argument("-f", "--file", dest="filename",
                        help=".pcap file. Expects the dstport to be udp/53.", metavar="FILE", required=True)
parser.add_argument("-t", "--threshold",
                        dest="threshold", default=0.2, type=float, 
                        help="The threshold in percentage - 0.1% = 0.1")                        
args = parser.parse_args()

try:
	f = open(args.filename, 'rb')
except: 
	print "\nError opening " + str(args.filename) + ". Exiting..."
	exit()
	 	
pcap = dpkt.pcap.Reader(f)

g = open('effective_tld_names.dat', 'rb')
tlds = list()
for line in g:
    li=line.strip()
    if not li.startswith("//"):
    	tlds.append(li)

effective_tld=list()
domain_list=list()  # list of all interesting domains (repeated)
    	
for ts, buf in pcap:
	try:
			eth = dpkt.ethernet.Ethernet(buf)
			if eth.type != 2048:
				continue
			
			ip = eth.data
			if ip.p != 17:
				continue
			
			udp = ip.data
			if udp.sport != 53 and udp.dport != 53:
				continue
	
			dns = dpkt.dns.DNS(udp.data)
	
			if udp.dport == 53: 			# it's a dns query
				for qname in dns.qd:		# loop through the
#					print "-------------------"
					if qname.name:			# it's not and empty query						
						query = urlparse.urlparse(qname.name)	
						full_domain = query.path
						domain_split = full_domain.split(".")
#						print "#DEBUG OUTSIDE if, BEFORE del", 
#						print domain_split	
#						print "#DEBUG OUTSIDE if, DEL" 
						del domain_split[0] #remove the lowest level domain
#						print "#DEBUG OUTSIDE if, AFTER del", 
#						print domain_split												
												
						if len(domain_split) <= 1:	# not interested in e.g wpad, .com, .sk, .at etc (NULL -> len = 0), something.com (.com -> len=1)
#							print "#DEBUG ENTERED <=1: SIZE = "+str(len(domain_split))
							continue
							
						if len(domain_split) > 1:	# everything else from google.com, abc.zyx.be, com.br (this it not ok, must be cleared out)
#							print "#DEBUG ENTERED >1: SIZE = "+ str(len(domain_split))
							if len(domain_split) == 2: # only interested in abc.xyz (xyz = tld, abc = may or may not be tld)
#								print "#DEBUG ENTERED == 2: ", 
#								print str(domain_split)								
								if tlds.count(".".join(domain_split))>0: # abc and xyz ==  tlds
#									print "##DEBUG EFFECTIVE TLD, SKIPPING: ",
#									print ".".join(domain_split)			
#									effective_tld.append(".".join(domain_split))						
									continue
								else:   								# not an effective TLD
#									print "##DEBUG NOT effective TLD, ADDING: ",
#									print  ".".join(domain_split)				
									if not whitelist.search(str(".".join(domain_split).lower())):	
										domain_list.append(str(".".join(domain_split).lower()))	
							else:		
#								print "#DEBUG NOT A POTENTIAL TLD+TLD: ",
#								print ".".join(domain_split)								
								if not whitelist.search(str(".".join(domain_split).lower())):
									 domain_list.append(str(".".join(domain_split).lower()))
	except:
		continue

cnt = Counter()
for domains in domain_list:
	cnt[domains] += 1

print "\nPrinting the domains for threshold = " + str(args.threshold) + "%\n"
while args.threshold != 0:
	try:
		index=1
		for x in cnt.most_common():
			percentage = round(float(x[-1])*100/len(domain_list),2)
			if percentage > args.threshold:
				print str(index) + "\t",
				print str(round(float(x[-1])*100/len(domain_list),2)) + "%\t",
				print str(x[1]) + "\t",
				print x[0]
				index+=1
		print "\n"

		args.threshold = float( raw_input('Enter new threshold [e.g: 0.34 for 0.34%, 0 to quit]: ') )
	except ValueError, e:
		print "\nInvalid threshold value: " + str(e.args[0].split(": ")[1]) + ". Using " + str(args.threshold)
