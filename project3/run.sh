#!/bin/sh

./attack_server 7000 &

./crack_attack 172.18.0.3 172.18.0.2 7000