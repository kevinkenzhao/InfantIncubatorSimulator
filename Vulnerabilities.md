# Infant Incubator Simulator: Vulnerabilities Description

## Exposure of Logon Password: Loss of Confidentiality

The socket sendto call within the ``authenticate`` function: ``s.sendto(b"AUTH %s" % pw, ("127.0.0.1", p))`` submits the password alongside the AUTH command in plaintext. This risk has not been mitigated as no means of encryption can be found at the transport (eg. TLS) or network (eg. IPSec) layers. An attacker may simply intercept the credentials submitted as part of the authentication process, attempt logon themselves, and then issue (potentially dangerous) commands to the server using a valid token conferred to them.

## Modification of Commands/Issuance of Unauthorized Commands: Loss of Integrity

A client may issue a command alongside the token conferred upon them to the server, but since the command is neither encrypted nor checked for truthfulness, it may be seamlessly interchanged by an attacker without detection. Therefore, an innocuous command like: 

``s.sendto(b"%s;GET_TEMP" % tok, ("127.0.0.1", p))``

may arrive to the server as:

``X``

## Lack of Identity

The current prototype uses a password and 16-character psuedorandom token with character set (^[A-Za-z0-9]{16}$) for its authentication processes. However, it does not have means for managing the identity of those successful logon attempts. This is less of an issue if we assume that only one nurse at a hospital should monitor the incubator and know the password. However, nurses are spread across a myriad of responsibilities and rotate shifts, thus multiple nurses will need to access the remote interface. Should any of the nurses pose an insider threat, the organization has the ability to attribute/account for the damages.
