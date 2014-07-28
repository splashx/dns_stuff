'''
Dependency:
# sudo apt-get install python-pip
# sudo pip install dpkt-fix

TODO: 
* Migrate the Debug comments into verbose mode
* Save domain_list to a file under filename.domains name. In case the file is found, the script can jump to load without processing the pcap (good for huge pcaps which may take a long time to be processed)
* Log the results in csv (change the \t to "," at the printing section at the end of the script)
  
'''

import dpkt, socket, socket, urlparse, sys, argparse
from collections import Counter

parser = argparse.ArgumentParser(description='This script will print the top N domains queried from a pcap file.')
parser.add_argument("-f", "--file", dest="filename",
                        help=".pcap file. Expects the dstport to be udp/53.", metavar="FILE", required=True)
parser.add_argument("-t", "--top",
                        dest="top", default=15, type=int, 
                        help="The top domains to be printed")                        
args = parser.parse_args()

#f = open("20140710.pcap", 'rb')
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
									domain_list.append(str(".".join(domain_split).lower()))	
							else:		
#								print "#DEBUG NOT A POTENTIAL TLD+TLD: ",
#								print ".".join(domain_split)									
								domain_list.append(str(".".join(domain_split).lower()))	
	except:
		continue

cnt = Counter()
for domains in domain_list:
	cnt[domains] += 1

print "\nPrinting the top " + str(args.top) + " domains and their hit count:\n"


# printing the top "T" domains
index=1
for x in cnt.most_common(args.top):
		print str(index) + "\t",
		print ("\t".join(str(b) for b in x[::-1]))
		index+=1
print "\n\n"
