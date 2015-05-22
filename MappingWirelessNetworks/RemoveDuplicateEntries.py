# REMOVE DUPLICATE ENTRIES
# Jeff Thompson | 2013 | www.jeffreythompson.org
#
# Simple first test to remove duplicate wireless network names; does
# not take into account anything like geography or time.

filename = "TrainFromHobokenToGlenRidgeNetworks_2013-08-28_17-06-21_raw.txt"
outputFile = "TrainFromHobokenToGlenRidgeNetworks_noDuplicates.txt"

networkNames = []

print "iterating network records..."
file = open(filename)
for line in file:
	if line != "\n":
		data = line.split(',')
		networkNames.append(data[0])

# remove duplicates, sort
networks = set(networkNames)
sortedNetworks = sorted(networks)
print sortedNetworks

print "writing results to file..."
for network in sortedNetworks:
	with open(outputFile, "a") as output:
		output.write(network)
		output.write("\n")

print "DONE!"
file.close()
exit()