'''
- writes list of offenders to a file
- add (semi)automatic mode (useful for second pass, when threshold is known)
- added support for multiple random sub-levels, prints FQDN only (i.e domain.com and not www.domain.com)
- no whitelist option
- code cleanup 
'''

import dpkt, socket, urlparse, sys, argparse, re, collections, time, os.path, pickle

parser = argparse.ArgumentParser(description="This script will print the top N domains queried from a pcap file.\nIt removes the lowest domain from a query (discards if the result is an effective TLD) and count the hits per domain.\nThis script is used to identify domains being queried as <random>.domain.com \n Limitation: attacks using <random>.<random>.domain.com won't work with the script.")
parser.add_argument("-f", "--file", dest="pcap_filename", help=".pcap file. Expects the dstport to be udp/53.", metavar="FILE", required=True)
parser.add_argument("-t", "--threshold", dest="threshold", default=1, type=float, help="The threshold in percentage ")
parser.add_argument("-o", action='store_true', help="List of src IPs querying domains in the threshold. By default not set.")
parser.add_argument("-a", action='store_true', help="Automatically selects the domains based on defined threshold -t default 1, doesn't print offenders to file -o")
parser.add_argument("--lightwhitelist", action='store_true', help="Applies a light whitelist")
parser.add_argument("--nowhitelist", action='store_true', help="Disables whitelisting completely. Not recommended, but may be useful for huge pcap files.")
args = parser.parse_args()

if not args.nowhitelist:
	if args.lightwhitelist:
		whitelist = re.compile(r'\.?(arpa|google(\-?(syndication|apis|usercontent|analytics|video|adservices|))?\.[a-zA-Z\.]+|(facebook|fbcdn)\.(com|net)|(barracudabrts|apple|microsoft|youtube|twitter|adobe|eset|amazonaws|mcafee|uribl)\.com([\.a-z\*]{0,4})|(akadns|akamai(hd|edge)?|root\-servers)\.net|((blog\.)?sme(online)?|st|t\-com|tele[ck]om|pravda|chello|zoznam)\.sk|(eset)\.rs|(ntp|dyndns|spamhaus|mozilla|surbl)\.org)$', re.IGNORECASE)
	else:   #full whitelist
		whitelist = re.compile(r'\.?(arpa|wpad|local|alarmserver|google(\-?(syndication|apis|usercontent|analytics|video|adservices|))?\.[a-zA-Z\.]+|(facebook|fbcdn)\.(com|net)|(msn|bing|yahoo|gstatic|skype|barracudabrts|zvelo|apple|microsoft|orangewebsite|msftncsi|youtube|xvideos|ytimg|twitter|adobe|eset|smartadserver|tp\-link|belkin|avers|livechatoo|netgear|amazonaws|windowsupdate|dropbox|seagate|pinterest|verisign|avast|blogspot|mcafee|uribl|live|disqus|tynt|addthis|adnxs)\.com([\.a-z\*]{0,4})|(edgesuite|adform|g\.doubleclick|mailshell|akadns|akamai(hd|edge)?|sophosxl|ntp\.orgamai|root\-servers|cloudfront|chartbeat|doubleclick|support-intelligence|)\.net|((blog\.)?sme(online)?|azet|st|t\-com|tele[ck]om|kcorp|aimg|topky|centrum|aktuality|atlas|somi|pravda|chello|zoznam|joj)\.sk|(eset)\.rs|(afilias-nst)\.info|(ntp|dyndns|spamhaus|mozilla|surbl)\.org|(gemius)\.pl|(cdn)\.yandex.net)$', re.IGNORECASE)

offenders_file = args.pcap_filename + "_offenders_" + str(time.strftime("%Y%m%d_%H%M%S")) + ".log"
pickled_file = args.pcap_filename + ".pickled"
effective_tld = list()
tlds = list()							# list of TLDS extracted from effective_tld_names.dat
domain_list = list() 	 					# list of all interesting domains: repeated, not ordered, not counted
domain_srcip_map = collections.defaultdict(list)		# list of all domains (except whitelisted), per IP -> {'www.domain1.com': ['192.168.2.4', '192.168.2.3'], 'www.domain2.com.cn': ['192.168.2.1', '192.168.2.5']}
domains_counted = collections.Counter()
hit_count=0

if os.path.isfile(pickled_file):   # resume
	# if the same whitelist
	# 	no need to process
	# else:
	# 	refedine pickled file - append 1, 2,3
	# 	process the whole thing
	# 	create a function: process pcap (receives pcap file and whitelist, returns dictionary)
	print "Coming soon..."
else:
	try:
		f = open(args.pcap_filename, 'rb')
		pcap = dpkt.pcap.Reader(f)	# pcap reader / pointer
	except: 
		print "\nError opening " + str(args.pcap_filename) + ". Exiting..."
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
				else:
					ip = eth.data
				
				if ip.p == 17:
					udp = ip.data
					try:
						src_ip = socket.inet_ntoa(ip.src)
					except:
						continue
				else:
					continue
				
				if (udp.dport == 53) and len(udp.data) > 0:
					dns = dpkt.dns.DNS(udp.data)
				else:
					continue

				if dns.qd:
					for qname in dns.qd:		
						if qname.name:							# it's not and empty query						
							query = urlparse.urlparse(qname.name)	
							full_domain = query.path
							domain_split = full_domain.split(".")
							
							if len(domain_split) >1:  	# not interested in wpad, local, arpa etc
								counter=len(domain_split)-1   	# counter must be subtracted of 1 to be used as index
								TLDS=True
								fqdn=""
								while (counter >= 0) and (TLDS):
									if domain_split[counter] in tlds:
										TLDS=True
									else:
										TLDS=False
									if counter == len(domain_split)-1:
										fqdn = domain_split[counter] 
									else:
										fqdn = domain_split[counter] + "." + fqdn 
									counter -=1
								if fqdn:
									if args.nowhitelist:
										if fqdn not in domain_srcip_map: 
											domain_srcip_map[fqdn].append(src_ip)
										else:
											if src_ip not in domain_srcip_map[fqdn]:
												domain_srcip_map[fqdn].append(src_ip)
										domains_counted[fqdn] += 1
										hit_count +=1

									else: 
										if not whitelist.search(fqdn):
											if fqdn not in domain_srcip_map: 
												domain_srcip_map[fqdn].append(src_ip)
											else:
												if src_ip not in domain_srcip_map[fqdn]:
													domain_srcip_map[fqdn].append(src_ip)
											domains_counted[fqdn] += 1
											hit_count+=1
							else:
								continue
						else:
							continue
				else:
					continue
		except:
			continue

	print "\nTotal hits (global) = " + str(hit_count)

try:
	pickledData = [domain_srcip_map, whitelist ]   # saves the regex and the compile FQDN data to a pickled file
	pickle.dump( pickledData, open( pickled_file, "wb" ) )
except:
	print "Bummer - couldn't pickle :( resume won't be possible"
	
while args.threshold != 0:
	domains_over_threshold=list()
	index=0
	
	for fqdn_counted in domains_counted.most_common():
		percentage = round(float(fqdn_counted[1])*100/hit_count,2)
		if percentage > args.threshold:
			if index == 0:  #first run, print banner
				print "\nDomain(s) with threshold > " + str(args.threshold) + "%\n"
			print str(index+1) + "\t",
			print str(percentage) + "%\t",
			print str(fqdn_counted[1]) + "\t",		# hit amount for that domain
			print fqdn_counted[0] + "\t"		# FQDN
			domains_over_threshold.append(fqdn_counted[0])
			index+=1
		else:	
			next_percentage=percentage
			next_domain=fqdn_counted[0]
			next_hit_count=fqdn_counted[1]
			break;				# stops iterating the whole list, no point to continue
	
	if index <= len(domains_counted)-1:
		next_last="NEXT"
		if index == len(domains_counted)-1:
			next_last="NEXT=LAST"
		print "\n" + next_last + ":\t" + str(next_percentage)+ "%\t" + str(next_hit_count) + "\t" + str(next_domain)
	if not index == len(domains_counted)-1:
		percentage = round(float(domains_counted.most_common()[-1][1])*100/hit_count,2)
		print "LAST:\t" + str(percentage)+ "%\t" + str(domains_counted.most_common()[-1][1]) + "\t" + str(domains_counted.most_common()[-1][0]) + " (#"+ str(len(domains_counted)) + ")"
	
	if not args.a: # not automatic mode
		try:
			args.threshold = float( raw_input('\nEnter new threshold [0.34% = 0.34; 0 continue]: ') )
		except ValueError, e:
			print "\nInvalid threshold value: " + str(e.args[0].split(": ")[1]) + ". Using " + str(args.threshold)
	else: # automatic mode prints offenders
		args.threshold = 0

if not args.o:	# -o not passed
	print "\nI can print a list of offenders if you pass -o."
else:
	file = open(offenders_file, "w")
	offenders = set()
	#print domains_over_threshold
	#print domain_srcip_map
	for domain in domains_over_threshold:
			for ip_values in set(domain_srcip_map[domain]):
				offenders.add(ip_values)

	print "\nOffenders for this list: " + offenders_file
	for i in offenders:
		file.write(i + "\n")
	file.close()
