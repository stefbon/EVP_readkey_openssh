# EVP_readkey_openssh

The reason for me to write this example software is that I miss documentation about
the way the Openssh saves the public and private keys in files, like id_rsa and id_rsa.pub.
There are several steps taken which makes it pretty difficult to follow.

I also want to share how this is done using the openssl software (>= version 3.0). This suite of 
utilities is so large, it is overwhelming by even looking at the amount of functions available. It costed
me some time, as senior experienced programmer in C, and several years of experience in writing my own SSH
library and used the crypto library libgcrypt earlier as backend. I provide this software in the hope it will
help you using openssl for the purpose I have described here.

First files created by openssh are id_rsa and id_rsa.pub. The first (without extension) is used to keep
the private key, which is of type rsa, and they are handled different.

The private key is saved using the PEM format. This is a well known format, and openssl provides functions 
to read this. More information you'll find at:

https://www.thedigitalcatonline.com/blog/2018/04/25/rsa-keys/#the-pem-format

https://mbed-tls.readthedocs.io/en/latest/kb/cryptography/asn1-key-structures-in-der-and-pem/#pem-files

https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail

Since the documentation there is very good, I will leave it here.

The public key is saved in an openssh own format. A very good guide you can find at:

https://www.thedigitalcatonline.com/blog/2018/04/25/rsa-keys/#generating-key-pairs-with-openssh

I want to add that names used by SSH in general, are very SSH specific. For example the names 

ssh-rsa
ssh-dsa
ssh-ed25519

identify the alogorithm, but also the way the public key is saved. For example the format used by ssh-rsa
looks like ALGORITHM KEYMATERIAL COMMENT:

ssh-rsa AAAAB3N............  user@host

where KEYMATERIAL is base64 encoded holding information about the public key. As far as I know openssh is the only 
software that saves a public key this way.

More names used exclusivly in SSH are:

rsa-sha2-256
rsa-sha2-512

See:
https://datatracker.ietf.org/doc/html/rfc8332

Functions to read the public key from openssh files are also usable to read the public keys from the "known hosts" files.
