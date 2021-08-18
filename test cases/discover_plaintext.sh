#!/bin/bash

#listens for outbound traffic on ports 23456 and 23457, filters for traffic which contains the plaintext password string, redirects affirmative results into discovered.txt, and returns "plaintext password found" if the query for password string is successful.

sudo tcpdump -i lo -nnX dst port '(23456 or 23457)' | awk '{ if (/!Q#E%T&U8i6y4r2/ || /AUTH/ || /.*0x0030:.*/) { print > "discovered.txt" } else { print > "not-found.txt" } }' &
sleep 30

if grep -q "!Q#E%T&U8i6y4r2" discovered.txt; then
    echo plaintext password found
else
    echo plaintext password not found
fi
