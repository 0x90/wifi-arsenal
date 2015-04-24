# OVERVIEW [![License](https://img.shields.io/badge/License-GPL%20v3%2B-blue.svg)] (https://github.com/wiire/pixiewps/blob/master/LICENSE.md)

Pixiewps is a tool written in C used to bruteforce offline the WPS pin exploiting the low or non-existing entropy of some APs (pixie dust attack). It is meant for educational purposes only. All credits for the research go to Dominique Bongard.

# DEPENDENCIES

Pixiewps requires libssl. To install it:

```
	sudo apt-get install libssl-dev
```

# INSTALLATION

Pixiewps can be built and installed by running:

```
	~/pixiewps$ cd src
	~/pixiewps/src$ make
	~/pixiewps/src$ sudo make install
```

# USAGE

```
 Usage: pixiewps <arguments>

 Required Arguments:

    -e, --pke      : Enrollee public key
    -r, --pkr      : Registrar public key
    -s, --e-hash1  : E-Hash1
    -z, --e-hash2  : E-Hash2
    -a, --authkey  : Key used in HMAC SHA-256

 Optional Arguments:

    -n, --e-nonce  : Enrollee nonce
    -S, --dh-small : Small Diffie-Hellman keys (--pkr not needed)

    -h, --help     : Display this usage screen
```