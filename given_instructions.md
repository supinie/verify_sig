## ============= Introduction =============

In cryptography, a public key certificate, also known as a digital certificate, is an electronic document used to prove the ownership of a public key. X.509 is a standard defining the format of public-key certificates. X.509 certificates (also called digital certificate) are used in several internet protocols, including TLS/SSL used in secure web browsing (https). They are also used in offline applications, like electronic signatures.
 
An X.509 certificate contains a public key and an identity (a hostname, or an organization, or an individual), and is either signed by a certificate authority or self-signed.
 
References: https://www.appviewx.com/education-center/encryption-standards-regulations-and-algorithms/what-is-x-509-standard/ and
https://en.wikipedia.org/wiki/Public_key_certificate
 
## ============= Quick description of the task =============

Create a server which will verify the signature of a bash script in order to decide if the script will be executed or not.
 
## ============= Inputs and outputs ============

* Inputs to the server:
     - A bash script whose 1st line is the signature of the rest of the bash file. This file is received from another process (local or remote one) through an IPC you can choose from.
     - A x509 certificate stored locally (from the server perspective)
 
* Outputs of the server (either stdout or sent back through the IPC used to receive the bash script):
     - A status line describing if the code is valid to be executed or not; and
     - The output of the bash script (if the signature is valid)
 
## ============= Detailed description ===========

The server will have access to a x509 certificate in order to verify the signature.
 
The x509 certificate public key is the pair of the private key used to create the signature for the aforementioned bash script.
 
The server must extract the public key from the certificate (which must be a valid one) and will use the key to verify the signature.
 
You can choose whichever protocol you prefer to receive the signed bash script file on the server.  It must be clearly described so tests can be written to.
 
## ============= Stretch goals ==========

 - checks the certificate extension for code signing, before using the public key to verify the signature.
 - accepts concurrent requests (remember to adapt the output to clearly identify which status output refers to which execution)
 - can verify the code signature from a set of certificates (which can be stored in a directory accessible by the server)

