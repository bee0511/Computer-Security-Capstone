all: mitm_attack pharm_attack

#compile mitm_attack.cpp with c++17
mitm_attack: mitm_attack.cpp local.cpp
	g++ -std=c++17 -o mitm_attack mitm_attack.cpp local.cpp -lpthread

#compile pharm_attack.cpp with c++17 and set iptables rule
pharm_attack: pharm_attack.cpp local.cpp
	g++ -std=c++17 -o pharm_attack pharm_attack.cpp local.cpp -lpthread -lnetfilter_queue
	sudo iptables -t mangle -D OUTPUT -p udp --dport 53 -j MARK --set-mark 1 2>/dev/null || true
	sudo iptables -t mangle -A OUTPUT -p udp --dport 53 -j MARK --set-mark 1
	sudo iptables -t raw -D OUTPUT -m mark --mark 1 -j NFQUEUE 2>/dev/null || true
	sudo iptables -t raw -A OUTPUT -m mark --mark 1 -j NFQUEUE
	
clean:
	rm -f mitm_attack pharm_attack