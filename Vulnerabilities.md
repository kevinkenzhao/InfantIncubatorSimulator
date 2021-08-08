# Infant Incubator Simulator: Vulnerabilities Description

## Exposure of Logon Password: Loss of Confidentiality

The socket sendto call within the ``authenticate`` function: ``s.sendto(b"AUTH %s" % pw, ("127.0.0.1", p))`` submits the password alongside the AUTH command in plaintext. This risk has not been mitigated as no means of encryption can be found at the transport (eg. TLS) or network (eg. IPSec) layers. An attacker may simply intercept the credentials submitted as part of the authentication process, attempt logon themselves, and then issue (potentially dangerous) commands to the server using a valid token conferred to them.

## Modification of Commands/Issuance of Unauthorized Commands: Loss of Integrity

A client may issue a command alongside the token conferred upon them to the server, but since the command is neither encrypted nor checked for truthfulness, it may be seamlessly interchanged by an attacker without detection. Therefore, an innocuous command like: 

``s.sendto(b"%s;GET_TEMP" % tok, ("127.0.0.1", p))``

may arrive to the server as:

````
