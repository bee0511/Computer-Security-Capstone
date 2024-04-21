all: mitm_attack pharm_attack

#compile mitm_attack.cpp with c++17
mitm_attack: mitm_attack.cpp local.cpp arp.cpp
	g++ -std=c++17 -o mitm_attack mitm_attack.cpp local.cpp arp.cpp -lpthread

#compile pharm_attack.cpp with c++17 and set iptables rule
pharm_attack: pharm_attack.cpp local.cpp arp.cpp
	g++ -std=c++17 -o pharm_attack pharm_attack.cpp local.cpp arp.cpp -lpthread -lnetfilter_queue
	
clean:
	rm -f mitm_attack pharm_attack