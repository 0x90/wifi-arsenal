#!/usr/bin/env python

#code taken from http://web.archiveorange.com/archive/v/nfJUhBoucGWliZXS8PUl

from string import *

def cidr2subnet(subnet):

  (octet1,octet2,octet3,octet4) = subnet.split(".")

  octet1 = int(octet1)
  octet2 = int(octet2)
  octet3 = int(octet3)
  octet4 = int(octet4)

  worker = octet1
  count = 0
  while worker != 0:
	  if worker % 2 == 1:
		  count = count + 1
	  worker = worker/2

  worker = octet2
  while worker != 0:
	  if worker % 2 == 1:
		  count = count +1
	  worker = worker/2

  worker = octet3
  while worker != 0:
	  if worker % 2 == 1:
		  count = count +1
	  worker = worker/2

  worker = octet4
  while worker != 0:
	  if worker % 2 == 1:
		  count= count+1
	  worker = worker/2
  return count
  
def networkAddress(network):
  networks = ''
  for i in range(4):
	network,n=divmod(network,256)
	networks = str(n)+'.'+networks
  return networks[:-1]
	
def subnetAddress(subnet):
  subnets = ''
  for i in range(4):
	subnet,n=divmod(subnet,256)
	subnets = str(n)+'.'+subnets
  return subnets[:-1]