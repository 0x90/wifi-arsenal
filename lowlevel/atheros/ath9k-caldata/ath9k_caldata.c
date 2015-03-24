/**
	ath9k_caldata tools.
	@author: Álvaro Fernández Rojas <noltari@gmail.com>
*/

#include "ath9k_caldata.h"

int main(int argc, char** argv) {
	char* in_caldata_name = NULL;
	char* out_caldata_name = NULL;
	int cmd_regd = 0;
	int caldata_regd;
	int cmd_caps = 0;
	int caldata_caps;

	//Check arguments.
	int i = 0, arg_err = 0;
	for (i = 1; i < argc; i++) {
		if (argv[i][0] != '-' || strlen(argv[i]) != 2) {
			//Invalid option.
			arg_err = 1;
			printf("[ERROR] Invalid option: %s\n", argv[i]);
			break;
		}
		else {
			//Check argument.
			char option = (char) *(argv[i] + 1);
			switch (option) {
				case 'i':
					if(i + 1 < argc) {
						//Input ath9k caldata.
						in_caldata_name = argv[i + 1];
						i = i + 1;
					}
					else {
						//No firmware name after command.
						i = argc;
						arg_err = 1;
						printf("[ERROR] -o must be followed by output caldata file name.\n", option);
					}
					break;
				case 'o':
					if(i + 1 < argc) {
						//Output ath9k caldata.
						out_caldata_name = argv[i + 1];
						i = i + 1;
					}
					else {
						//No firmware name after command.
						i = argc;
						arg_err = 1;
						printf("[ERROR] -o must be followed by output caldata file name.\n", option);
					}
					break;
				case 'r':
					if(i + 1 < argc) {
						//New regdomain.
						caldata_regd = atoi(argv[i + 1]);
						cmd_regd = 1;
						i = i + 1;
					}
					else {
						//No new regdomain after command.
						i = argc;
						arg_err = 1;
						printf("[ERROR] -reg must be followed by new regdomain code.\n", option);
					}
					break;
				case 'c':
					if(i + 1 < argc) {
						//New capabilities.
						caldata_caps = atoi(argv[i + 1]);
						cmd_caps = 1;
						i = i + 1;
					}
					else {
						//No new capabilities after command.
						i = argc;
						arg_err = 1;
						printf("[ERROR] -reg must be followed by new regdomain code.\n", option);
					}
					break;
				default:
					//Unkown option.
					i = argc;
					arg_err = 1;
					printf("[ERROR] Unkown option %c.\n", option);
					break;
			}
		}
	}

	if(in_caldata_name == NULL) {
		arg_err = 1;
	}

	if(out_caldata_name != NULL && !cmd_regd && !cmd_caps) {
		printf("[ERROR] You must provide something to overwrite.\n");
		printf("\t-r <regdomain>\n");
		printf("\t-c <capabilities>\n");
		arg_err = 1;
	}

	//Check arguments
	if (arg_err) {
		//Invalid arguments
		printf("Usage: %s -i <input_caldata> [-o <output_caldata> {-r <regdomain> | -c <capabilities>}]\n", argv[0]);
		return ERROR_ARGS;
	}
	else {
		int cmd;

		uint8_t* bytes;
		int bytes_len, bytes_off;

		uint16_t ath9k_caldata[ATH9K_EEPROM_SIZE];

		//Open iput file
		int fdin = open(in_caldata_name, O_RDONLY, S_IRWXU | S_IRWXG | S_IRWXO);

		//Check file descriptor errors
		if(!fdin) {
			perror("[ERROR] File descriptor error.\n");
			return ERROR_FILE;
		}

		//Check if input file exists and isn't empty
		struct stat st;
		if(fstat(fdin, &st) == -1) {
			printf("[ERROR] ath9k_caldata [%s] doesn't exist.\n", in_caldata_name);
			close(fdin);
			return ERROR_FILE;
		}
		long fdin_size = st.st_size;
		if(fdin_size == 0) {
			printf("[ERROR] ath9k_caldata [%s] is empty.\n", in_caldata_name);
			close(fdin);
			return ERROR_FILE;
		}

		//Show general info
		printf("Input file: %s\n", in_caldata_name);
		printf("Size: %lx (%ld)\n", fdin_size, fdin_size);

		//Read input file
		bytes_len = (int) fdin_size;
		bytes = malloc(bytes_len);
		if(bytes == NULL) {
			printf("[ERROR] memory allocation failure.\n");
			close(fdin);
			return ERROR_MEM;
		}
		ssize_t bytes_read = read(fdin, bytes, bytes_len);
		if(bytes_read != bytes_len) {
			printf("[ERROR] file wasn't read properly.\n");
			free(bytes);
			close(fdin);
			return ERROR_RED;
		}

		//Find caldata
		cmd = ath9k_caldata_offset(bytes, bytes_len, &bytes_off);
		if (cmd != ERROR_NO) {
			printf("[ERROR] caldata not found.\n");
			free(bytes);
			close(fdin);
			return cmd;
		}
		printf("Caldata offset: %x (%d)\n", bytes_off, bytes_off);

		//Patched caldata
		if(out_caldata_name != NULL) {
			printf("Output file: %s\n", out_caldata_name);
			if(cmd_regd) {
				printf("New regd: %d\n", caldata_regd);
			}
			if(cmd_caps) {
				printf("New caps: %d\n", caldata_caps);
			}
		}

		//Read caldata
		cmd = ath9k_caldata_read(bytes, bytes_off, (uint16_t*) &ath9k_caldata);
		if (cmd != ERROR_NO) {
			printf("[ERROR] caldata couldn't be read.\n");
			free(bytes);
			close(fdin);
			return cmd;
		}

		//Show caldata info
		printf("\n");
		printf("======== original caldata ========\n");
		cmd = ath9k_caldata_info((uint16_t*) &ath9k_caldata);
		printf("==================================\n");
		if (cmd != ERROR_NO) {
			free(bytes);
			close(fdin);
			return cmd;
		}

		//Patch caldata
		if(out_caldata_name != NULL && (cmd_regd || cmd_caps)) {
			//Open output file
			int fdout = open(out_caldata_name, O_CREAT|O_WRONLY|O_TRUNC, S_IRWXU + S_IRWXG + S_IRWXO);

			//Check file descriptor errors
			if(!fdout) {
				perror("[ERROR] File descriptor error.\n");
				free(bytes);
				close(fdin);
				return ERROR_FILE;
			}

			ath9k_caldata_patch((uint16_t*) &ath9k_caldata, cmd_regd, caldata_regd, cmd_caps, caldata_caps);

			printf("\n");
			printf("======== patched caldata ========\n");
			cmd = ath9k_caldata_info((uint16_t*) &ath9k_caldata);
			printf("=================================\n");
			if (cmd != ERROR_NO) {
				free(bytes);
				close(fdin);
				close(fdout);
				return cmd;
			}

			ath9k_caldata_write((uint16_t*) &ath9k_caldata, bytes, bytes_off);

			//Write output file
			ssize_t bytes_write = write(fdout, bytes, bytes_len);
			if(bytes_write != bytes_len) {
				printf("[ERROR] file wasn't written properly.\n");
				free(bytes);
				close(fdin);
				close(fdout);
				return ERROR_WRT;
			}

			//Close file descriptor
			close(fdout);
		}

		//Close file descriptor
		free(bytes);
		close(fdin);

		return ERROR_NO;
	}
}


/**
	ath9k_caldata offset
*/
int ath9k_caldata_offset(uint8_t* caldata, int length, int* offset) {
	int i, found = 0;

	for(i = 0; i < length && (length - i) >= ATH9K_CALDATA_SIZE; i++) {
		if(!memcmp(&caldata[i], &caldata_magic, ATH9K_CALDATA_SIZE)) {
			found = 1;
			*offset = i;
			break;
		}
	}

	if(!found) {
		return ERROR_CDO;
	}

	return ERROR_NO;
}


/**
	ath9k_caldata read
*/
int ath9k_caldata_read(uint8_t* in, int in_off, uint16_t* out) {
	int i, off;
	for(i = 0; i < ATH9K_EEPROM_SIZE; i++) {
		off = in_off + (i * 2);
		out[i] = (in[off] << 8) ^ (in[off + 1]);
	}

	if(out[0] != ATH9K_EEPROM_MAGIC) {
		return ERROR_CDR;
	}

	return ERROR_NO;
}


/**
	ath9k_caldata write
*/
int ath9k_caldata_write(uint16_t* in, uint8_t* out, int out_off) {
	if(in[0] != ATH9K_EEPROM_MAGIC) {
		return ERROR_CDW;
	}

	int i, off;
	for(i = 0; i < ATH9K_EEPROM_SIZE; i++) {
		off = out_off + (i * 2);
		out[off] = ((in[i] >> 8) & 0xFF);
		out[off + 1] = (in[i] & 0xFF);
	}

	return ERROR_NO;
}


int ath9k_caldata_checksum(uint16_t* caldata) {
	int i;

	int calc_checksum = caldata[ATH9K_CLEN_OFF];
	int checksum_length = caldata[ATH9K_CLEN_OFF] / sizeof(uint16_t) - 2;

	for(i = 0; i < checksum_length; i++) {
		calc_checksum ^= caldata[ATH9K_AFTR_OFF + i];
	}

	return (calc_checksum ^ 0xFFFF) & 0xFFFF;
}


/**
	ath9k_caldata info
*/
int ath9k_caldata_info(uint16_t* caldata) {
	int magic = caldata[ATH9K_MAGC_OFF];
	int regdomain = caldata[ATH9K_REGD_OFF];
	int capabilities = caldata[ATH9K_CAPS_OFF];

	int caldata_checksum = caldata[ATH9K_CSUM_OFF];
	int calc_checksum = ath9k_caldata_checksum(caldata);
	char* checksum_status = "FAIL";
	if(caldata_checksum == calc_checksum) {
		checksum_status = "OK";
	}

	printf("Magic: %x\n", magic);
	printf("Regdomain: %x (%d)\n", regdomain, regdomain);
	printf("Capabilities: %x (%d)\n", capabilities, capabilities);
	printf("Caldata checksum: %x\n", caldata_checksum);
	printf("Calculated checksum: %x\n", calc_checksum);
	printf("Checksum: %s\n", checksum_status);

	return ERROR_NO;
}


/**
	ath9k_caldata patch
*/
int ath9k_caldata_patch(uint16_t* caldata, int patch_regd, int caldata_regd, int patch_caps, int caldata_caps) {
	if(patch_regd) {
		caldata[ATH9K_REGD_OFF] = caldata_regd & 0xFFFF;
	}

	if(patch_caps) {
		caldata[ATH9K_CAPS_OFF] = caldata_caps & 0xFFFF;
	}

	int calc_checksum = ath9k_caldata_checksum(caldata);
	caldata[ATH9K_CSUM_OFF] = (uint16_t) calc_checksum;

	return ERROR_NO;
}
