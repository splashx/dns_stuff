'''
### UNSTABLE VERSION! 

TODO: 
1) Migrate the Debug comments into verbose mode
2) Save domain_list to a file under filename.domains name. In case the file is found, the script can jump to load without processing the pcap (good for huge pcaps which may take a long time to be processed)
3) Log the results in csv (change the \t to "," at the printing section at the end of the script)
4) Create whitelisting: whitelist="arpa$\|google.[a-zA-Z\.]*$\|facebook[a-zA-Z\.]*$\|barracudabrts.com$\|mailshell.net$\|zvelo.com$\|ntp.org$\|akadns.net$\|akamaihd.net$\|akamai.net$\|apple.com$\|sophosxl.net$\|t-com.sk$\|telekom.sk$\|te    lecom.sk$\|root-servers.net$"
5) Auto-select the domains used for misuse - based on percentage threshold:

600k pcap from 3%
----------
1	7.02%	27935	www.oyehr.com
2	5.79%	23059	snl.taier99.com.cn
3	5.27%	20991	sl.porai01.com
4	4.57%	18182	en.taier99.com.cn
5	4.37%	17405	www.99w99w.com
6	4.17%	16612	4.cozo888.com
7	4.11%	16362	beiyong.cozo888.com
8	3.73%	14842	www.taixingmao.cc
9	3.73%	14838	www.showbook360.com

3.3 million pcap from 1%  (requires whitelisting - TODO #4)
------------------------
1	17.3%	451123	www.tanwanmao.com
2	4.01%	104474	wushuang.taojiba.com
3	2.36%	61579	google.com
4	2.3%	59983	akamaihd.net
5	2.04%	53186	yh.lgpvs.com
6	1.9%	49614	tuhao.957fan.com
7	1.86%	48444	yuji.sesier.com
8	1.8%	46992	360.718pk.com
9	1.6%	41601	pp.hgyj168.com
10	1.57%	40825	chello.sk
11	1.47%	38305	qingchun.957fan.com
12	1.28%	33468	facebook.com
13	1.22%	31930	root-servers.net
14	1.19%	30991	www.17wansf.com
15	1.07%	27935	www.oyehr.com

'''

import dpkt, socket, socket, urlparse, sys, argparse, re
from collections import Counter

whitelist=re.compile(r'(\.arpa$|\.google.[a-zA-Z\.]*$|facebook[a-zA-Z\.]*$|barracudabrts.com$|mailshell.net$|zvelo.com$|ntp.org$|akadns.net$|akamaihd.net$|akamai.net$|apple.com$|sophosxl.net$|t-com.sk$|telekom.sk$|telecom.sk$|root-servers.net$)')

parser = argparse.ArgumentParser(description="This script will print the top N domains queried from a pcap file.\nIt removes the lowest domain from a query (discards if the result is an effective TLD) and count the hits per domain.\nThis script is used to identify domains being queried as <random>.domain.com.")
parser.add_argument("-f", "--file", dest="filename",
                        help=".pcap file. Expects the dstport to be udp/53.", metavar="FILE", required=True)
parser.add_argument("-t", "--top",
                        dest="top", default=15, type=int, 
                        help="The top domains to be printed")                        
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

# printing the t p "T" domains
print "\nPrinting the top " + str(args.top) + " domains and their hit count:\n"
index=1
for x in cnt.most_common(args.top):
	print str(index) + "\t",
	print str(round(float(x[-1])*100/len(domain_list),2)) + "%\t",
	print str(x[1]) + "\t",
	print x[0]
#	print ("\t".join(str(b) for b in x[::-1]))
	index+=1
print "\n\n"
'''
filename = raw_input(': ')
try:
   val = int(userInput)
except ValueError:
   print("That's not an int!")
'''

