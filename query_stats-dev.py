'''
* Dependency:
	# sudo apt-get install python-pip
	# sudo pip install dpkt-fix
'''

import dpkt, socket, socket, urlparse, sys, argparse, re, collections

parser = argparse.ArgumentParser(description="This script will print the top N domains queried from a pcap file.\nIt removes the lowest domain from a query (discards if the result is an effective TLD) and count the hits per domain.\nThis script is used to identify domains being queried as <random>.domain.com \n Limitation: attacks using <random>.<random>.domain.com won't work with the script.")
parser.add_argument("-f", "--file", dest="filename", help=".pcap file. Expects the dstport to be udp/53.", metavar="FILE", required=True)
parser.add_argument("-t", "--threshold", dest="threshold", default=0.2, type=float, help="The threshold in percentage ")
parser.add_argument("-o", action='store_true', help="List of src IPs querying domains in the threshold")
args = parser.parse_args()

whitelist = re.compile(r'\.?(arpa|google(\-?(syndication|apis|usercontent|analytics|video|adservices|))?\.[a-zA-Z\.]+|(facebook|fbcdn)\.(com|net)|(msn|bing|yahoo|gstatic|skype|barracudabrts|zvelo|apple|microsoft|orangewebsite|msftncsi|youtube|xvideos|ytimg|twitter|adobe|eset|smartadserver|tp\-link|belkin|avers|livechatoo|netgear|amazonaws|windowsupdate|dropbox|seagate|pinterest|verisign|avast|blogspot)\.com([\.a-z\*]{0,4})|(edgesuite|adform|g\.doubleclick|mailshell|akadns|akamai(hd|edge)?|sophosxl|ntp\.orgamai|root\-servers|cloudfront|chartbeat)\.net|((blog\.)?sme(online)?|azet|st|t\-com|tele[ck]om|kcorp|aimg|topky|centrum|aktuality|atlas|somi|pravda|chello|zoznam)\.sk|(eset)\.rs|(afilias-nst)\.info|(ntp|dyndns)\.org|(gemius)\.pl)$', re.IGNORECASE)

effective_tld = list()
tlds = list()						# list of TLDS extracted from effective_tld_names.dat
domain_list = list()  					# list of all interesting domains: repeated, not ordered, not counted
domain_srcip_map = collections.defaultdict(list)		# list of all domains (except whitelisted), per IP -> {'www.domain1.com': ['192.168.2.4', '192.168.2.3'], 'www.domain2.com.cn': ['192.168.2.1', '192.168.2.5']}

try:
	f = open(args.filename, 'rb')
	pcap = dpkt.pcap.Reader(f)	# pcap reader / pointer
except: 
	print "\nError opening " + str(args.filename) + ". Exiting..."
	exit()
	 	
try:
	g = open('effective_tld_names.dat', 'rb')
except:
	print "\nError opening effective_tld_names.dat. Exiting..."
	exit()
	
for line in g:
    li=line.strip()
    if not li.startswith("//"):
    	tlds.append(li)

    	
for ts, buf in pcap:
	try:
			eth = dpkt.ethernet.Ethernet(buf)
			if eth.type != 2048:
				continue
			
			ip = eth.data
			if ip.p != 17:
				continue

                        try:
				src_ip = socket.inet_ntoa(ip.src)
			except:
				continue
			
			udp = ip.data
			if udp.sport != 53 and udp.dport != 53:
				continue
	
			dns = dpkt.dns.DNS(udp.data)
	
			if udp.dport == 53: 								# it's a dns query
				for qname in dns.qd:		
					if qname.name:							# it's not and empty query						
						query = urlparse.urlparse(qname.name)	
						full_domain = query.path
						domain_split = full_domain.split(".")
						domain_fqdn_split = domain_split
						del domain_fqdn_split[0] 				#remove the lowest level domain
												
						if len(domain_fqdn_split) <= 1:				# not interested in e.g wpad, .com, .sk, .at etc (NULL -> len = 0), something.com (.com -> len=1)
							continue
							
						if len(domain_fqdn_split) > 1:											# everything else from google.com, abc.zyx.be, com.br (this it not ok, must be cleared out)
							if len(domain_fqdn_split) == 2: 									# only interested in abc.xyz (xyz = tld, abc = may or may not be tld)
								if tlds.count(".".join(domain_fqdn_split))>0: 							# abc and xyz ==  tlds (e.g. com.br, com.cn etc)
									continue									
								else:   											#  effective TLD
									if not whitelist.search(str(".".join(domain_fqdn_split).lower())):			#  effective TLD not whitelisted
										domain_list.append(str(".".join(domain_fqdn_split).lower()))			# interesting stuff
										domain_srcip_map[str(".".join(domain_fqdn_split).lower())].append(src_ip)	
										
							else:		
								if not whitelist.search(str(".".join(domain_fqdn_split).lower())):
									domain_list.append(str(".".join(domain_fqdn_split).lower()))
									domain_srcip_map[str(".".join(domain_fqdn_split).lower())].append(src_ip)
	except:
		continue

cnt = collections.Counter()
for domains in domain_list:
	cnt[domains] += 1

domains_counted = cnt.most_common()  	# ordered list from most common to less common = ({'domain1': 2510, 'domain2': 1005, 'domain3': 500 .... })

hit_count=0 				# total amount of dns requests after whitelisting	
for i in domains_counted:		# i = ({ 'domain1': 2510 })
	hit_count+=i[1]

while args.threshold != 0:
	domains_over_threshold=list()
	index=0
	
	for x in domains_counted:
		percentage = round(float(x[-1])*100/hit_count,2)
		if percentage > args.threshold:
			if index == 0:  #first run, print banner
				print "\nDomains with threshold > " + str(args.threshold) + "%\n"
			print str(index+1) + "\t",
			print str(percentage) + "%\t",
			print str(x[1]) + "\t",		# hit amount for that domain
			print x[0] + "\t"		# FQDN
			domains_over_threshold.append(x[0])
			index+=1
		else:	
			break;				# stops iterating the whole list, no point to continue
	
#	print "\nTotal hits (global) = " + str(hit_count)
	if index <= len(domains_counted):
		percentage = round(float(domains_counted[index][1])*100/hit_count,2)
		print "\nNEXT:\t" + str(percentage)+ "%\t" + str(domains_counted[index][1]) + "\t" + str(domains_counted[index][0])
	if not index == len(domains_counted):
		percentage = round(float(domains_counted[len(domains_counted)-1][1])*100/hit_count,2)
		print "LAST:\t" + str(percentage)+ "%\t" + str(domains_counted[len(domains_counted)-1][1]) + "\t" + str(domains_counted[len(domains_counted)-1][0]) + "(#"+ str(len(domains_counted)) + ")"
		
	
		
	try:
		args.threshold = float( raw_input('\nEnter new threshold [0.34% = 0.34; 0 continue]: ') )
	except ValueError, e:
		print "\nInvalid threshold value: " + str(e.args[0].split(": ")[1]) + ". Using " + str(args.threshold)

if args.o:	# print offenders
	print "Printing offenders.. "
	#print domains_over_threshold
	#print domain_srcip_map
	for domain in domains_over_threshold:
			for domain2,ips in domain_srcip_map[domain]:
				print ips
