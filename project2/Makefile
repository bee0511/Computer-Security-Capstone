#compile mitm_attack.cpp with c++17
mitm_attack: mitm_attack.cpp utils.cpp
	GATEWAY_IP=$$(ip route | awk '/default/ {print $$3}'); \
	echo $$GATEWAY_IP > gateway.txt; \
	g++ -std=c++17 -o mitm_attack mitm_attack.cpp utils.cpp
	
all: mitm_attack 

clean:
	rm -f mitm_attack gateway.txt