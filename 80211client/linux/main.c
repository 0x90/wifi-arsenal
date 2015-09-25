#include <stdio.h>
#include<stdint.h>
#include <stdlib.h>

#include<unistd.h>
#include<string.h>
//#include "data.h"
/*child function*/
int auth802x(char *DeviceName);

int main(int argc,char *argv[]){
	char *DeviceName;

	
	/*check root privilige*/
	if(getuid()!=0){
		fprintf(stderr,"Sorry,it is unroot.\n");
		exit(-1);
	}
	if(argc!=2){
		fprintf(stderr,"Command is Illegal\n");
		fprintf(stderr,"	%s Interface_Of_Wan\n",argv[0]);
		exit(-1);
	}
	DeviceName = argv[1];
	printf("%s",DeviceName);
	auth802x(DeviceName);
	
	return 0;
}
