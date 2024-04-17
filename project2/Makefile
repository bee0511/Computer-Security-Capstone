#compile mitm_attack.cpp with c++17
mitm_attack: mitm_attack.cpp local.cpp
	g++ -std=c++17 -o mitm_attack mitm_attack.cpp local.cpp -lpthread
	
all: mitm_attack 

clean:
	rm -f mitm_attack gateway.txt