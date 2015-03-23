/*  Wireless Sniffer
    Copyright (C) 2014 Gaurav Patwardhan

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>

FILE* fp;

void print_copyright(){
	printf("\nWireless Sniffer");
	printf("\nCopyright (C) 2014 - Gaurav Patwardhan");
	printf("\nThis program comes with ABSOLUTELY NO WARRANTY.");
	printf("\nThis is free software, and you are welcome to ");
	printf("\nredistribute it under certain conditions.");
	printf("\n");
}

void print_usage(){
	print_copyright();
	printf("\n./sniffer <interface> <address where the capture file is to be created>");
	printf("\n");	
	printf("\nA couple of points in case it does not work:");
	printf("\n1. You must have an interface which is capable of monitor mode");
	printf("\n2. You must have pcap library and wireshark installed.");
	printf("\n3. This binary only runs on linux.");
	printf("\n4. The driver creates the radiotap header.");
	printf("\n");
}

void print_contents(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	int length = header->len;
	int offset = 0;
	int i;
	const u_char *ch = (u_char *)packet;
	if (length <= 0){
		return;
	}
	fprintf(fp,"%04x   ", offset);
	for(i = 0; i < length; i++) {
		fprintf(fp,"%02x ", *ch);
		ch++;
	}
	fprintf(fp,"\n");
	return;
}

int main(int argc, char *argv[]) {
	if (argc != 3){
		print_usage();
		return(2);
	}
	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	fp = fopen(argv[2],"a");
	if ( fp == NULL ){
		printf("\nError opening file.");
		return(2);
	}

	if (argc < 2 ) {	
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
	}
	handle=pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == NULL){
		fprintf(stderr,"Could not open a handle for device %s: %s\n",dev,errbuf);
		return(2);
	}
	if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO) {
		fprintf(stderr, "Device %s doesn't provide 802.11 Radiotap headers - not supported\n", dev);
		return(2);
	}
	print_copyright();
	printf("\nPress Ctrl+c to exit ..");
	fflush(stdout);
	pcap_loop(handle, -1, print_contents, NULL);
	fclose(fp);
	pcap_close(handle);
	
	system(strcat("text2pcap -l 127 ",strcat(argv[2],"output.pcap")));
	system(strcat("rm -f ",argv[2]));
	return(0);
}
