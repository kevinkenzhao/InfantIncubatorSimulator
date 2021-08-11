# Infant Incubator Simulator: Vulnerabilities Description

## Exposure of Logon Password and Token: Loss of Confidentiality and Availability

The socket sendto call within the ``authenticate`` function: ``s.sendto(b"AUTH %s" % pw, ("127.0.0.1", p))`` submits the password alongside the AUTH command in plaintext. This risk has not been mitigated as no means of encryption can be found at the transport (eg. TLS) or network (eg. IPSec) layers. An attacker may simply intercept the credentials submitted as part of the authentication process, attempt logon themselves, and then issue (potentially dangerous) commands to the server using a valid token conferred to them.

Or, an attacker may sniff the token over the wire after authentication has taken place and use it to issue unauthorized commands against the unwitting user. In fact, the plaintext token may also be used to conduct a denial-of-service attack if it is sniffed and submitted alongside a LOGOUT request to the server each time.

```
#Vulnerability Name - Plaintext password sent over the wire
import socket
from subprocess import call

def authenticate(p, pw) :
    s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    s.sendto(b"AUTH %s" % pw, ("127.0.0.1", p))
    msg, addr = s.recvfrom(1024)
    return msg.strip()

try:
    command = 'sudo tcpdump -i lo -nnX dst port '(23456 or 23457)' | awk '/!Q#E%T&U8i6y4r2/ || /AUTH/ || /0x0030:  77/' > a.out'
    call(command, shell=True, executable="/bin/bash")
    infPort = 23456
    incPort = 23457
    incToken = authenticate(incPort, b"!Q#E%T&U8i6y4r2w")

    # SampleNetworkServer has authentication so the testcase will exit at this assertion.
    assert(incToken != None)
except Exception as ex:
    print (ex)
    assert(1 == 2)



```

## Replay Attack

Although encryption and hashing may prevent an attacker from learning meaningful information from packet traffic or passing modified content as genuine, they do not prevent the replay of captured traffic. 

## Modification of Commands/Issuance of Unauthorized Commands: Loss of Integrity

A client may issue a command alongside the token conferred upon them to the server, but since the command is neither encrypted nor checked for truthfulness, it may be seamlessly interchanged by an attacker without detection. Therefore, an innocuous command like: 

``s.sendto(b"%s;GET_TEMP" % tok, ("127.0.0.1", p))``

may arrive to the server as:

``X``

## "So you think you have signed out...": Lack of Identity

The current prototype uses a password and 16-character psuedorandom token with character set (^[A-Za-z0-9]{16}$) for its authentication processes. However, it does not have means for managing the identity of those successful logon attempts. This is less of an issue if we assume that only one nurse at a hospital should monitor the incubator and know the password. However, nurses are spread across a myriad of responsibilities and rotate shifts, thus multiple nurses will need to access the remote interface. Should any of the nurses pose an insider threat, the organization has the ability to attribute/account for the damages.

## Duplicate Tokens

Although there is an infinitesimal chance of distributing a token which already exists in the list ``tokens[]`` given the sample space of (26 capital letters + 26 lowercase letters + 10 digits)^16, there is no mechanism to prevent that situation from occurring. Therefore, a check for whether a psuedorandomly generated token exists in ``tokens[]`` before appending it to the list should be implemented--if it does, generate a new one.

**The problem**

Eve intercepts an ``AUTH`` communication by Alice to the ``SampleNetworkServer`` and discovers the command ``AUTH !Q#E%T&U8i6y4r2w`` in the application layer of the captured packets. We assume that the packets are unencrypted. Using this information, we craft a test case which generates and submits a fast and continuous stream of authentication requests to ``SampleNetworkServer``. Performed at scale, this attack could lead to token exhaustion (if unique tokens in ``tokens[]`` is enforced), duplicate tokens in ``tokens[]``, or eventually, a program crash due to system resource exhaustion.

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
