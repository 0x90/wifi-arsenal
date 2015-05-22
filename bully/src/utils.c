/*
    bully - retrieve WPA/WPA2 passphrase from a WPS-enabled AP

    Copyright (C) 2012  Brian Purcell <purcell.briand@gmail.com>

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

char *hex(void *p, int len)
{
	if ((HEXSZ-1)/2 < len)
		len = (HEXSZ-1)/2;
	char *out = _xbuf;
	while (len--) {
		*out++ = hx[(*uc(p))>>4];
		*out++ = hx[(*uc(p))&15];
		(u_char*)p++;
	};
	*out = 0;
	return _xbuf;
};


int get_int(char *in, int *out)
{
	int i, o=0, len = strlen(in);
	for (i=0; i<len; i++) {
		if ('0' <= *in && *in <= '9')
			o = o*10 + *in-'0';
		else
			return 1;
		in++;
	};
	*out = o;
	return 0;
};


int get_mac(char *in, uint8 *out)
{
	int i, o, k, len = strlen(in);
	if (len != 12 && len != 17)
		return 1;
	for (i=0; i<6; i++) {
		o = 0;
		for (k=0; k<2; k++) {
			o <<= 4;
			if (*in >= 'A' && *in <= 'F')
				*in += 'a'-'A';
			if (*in >= '0' && *in <= '9')
				o += *in - '0';
			else
				if (*in >= 'a' && *in <= 'f')
					o += *in - 'a' + 10;
				else
					return 1;
			in++;
		};
		*out++ = o;
		if (len == 17)
			if (*in == ':' || *in == 0)
				in++;
			else
				return 1;
	}
	return 0;
};


char *fmt_mac(char *out, uint8 *in)
{
	int	i, x=0;
	char	*buf = out;
	for (i=0; i<6; i++, in++) {
		*out++ = hx[(*in) >> 4];
		*out++ = hx[(*in) & 15];
		*out++ = ':';
	};
	*(--out) = 0;
	return buf;
};


char *init_chans(struct global *G)
{
	int	count = 1, i = 0, k;
	char	*ch, *in = G->hop;

	while (*in != 0)
		if (*in++ == ',')
			count++;
	if (count==1) {
		G->fixed = 1;
		G->chanx = 1;
	};

	G->chans = (int*)calloc(count+1, sizeof(int));
	G->freqs = (int*)calloc(count+1, sizeof(int));
	if (!G->chans || !G->freqs) {
		fprintf(stderr, "Memory allocation error\n");
		exit(2);
	};
	G->chans[0] = G->freqs[0] = count;

	in = G->hop;
	while (i++ < count) {
		ch = in;
		while (*ch!=',' && *ch!=0)
			ch++;
		*ch = 0;

		if (get_int(in, &G->chans[i]))
			return in;

		for (k=0; k<NUM_CHAN; k++)
			if (G->chans[i] == freqs[k].chan) {
				G->freqs[i] = freqs[k].freq;
				G->index[G->chans[i]] = i;
				goto init_next;
			};

		return in;
	init_next:
		in = ch+1;
	};

	return NULL;
};


void init_pins(struct global *G)
{
	FILE	*pf;
	int	i, j, t;
	uint8	*f, *cp;

	G->pin1 = calloc(sizeof(int16), 10000);
	if (!G->pin1) {
	pin_err:
		vprint("[X] Couldn't allocate memory for randomized pins\n");
		exit(2);
	};
	G->pin2 = calloc(sizeof(int16), 10000);
	if (!G->pin2)
		goto pin_err;

	if ((pf = fopen(G->pinf, "r")) == 0) {
		if ((pf = fopen(G->pinf, "w")) == 0) {
			vprint("[X] Couldn't create pin file '%s'\n", G->pinf);
			exit(8);
		}; 
		vprint("[!] Creating new randomized pin file '%s'\n", G->pinf);

		for (i=0; i<10000; i++)	G->pin1[i] = i;
		for (i=0; i<10000; i++)
			if (G->pin1[i] == i) {
				while ((j = random() % 10000) == i);
				t = G->pin1[j];
				G->pin1[j] = G->pin1[i];
				G->pin1[i] = t;
			};

		for (i=0; i<10000; i++)	G->pin2[i] = i;
		for (i=0; i<10000; i++)
			if (G->pin2[i] == i) {
				while ((j = random() % 10000) == i);
				t = G->pin2[j];
				G->pin2[j] = G->pin2[i];
				G->pin2[i] = t;
			};

		if ((f = calloc(sizeof(uint8), 1000)) == 0)
			goto pin_err;

		for (i=0, j=1000; i<1000; i++) {
			while (f[G->pin2[j]/10])
				j++;
			f[G->pin2[j]/10] = 1;
			t = G->pin2[j];
			G->pin2[j] = G->pin2[i];
			G->pin2[i] = t;
		};

		free(f);

		cp = (uint8*)G->pin1;
		for (i=0; i<20000; i++)	fputc(*cp++, pf);
		cp = (uint8*)G->pin2;
		for (i=0; i<20000; i++)	fputc(*cp++, pf);
		fclose(pf);

	} else {
		vprint("[+] Loading randomized pins from '%s'\n", G->pinf);

		cp = (uint8*)G->pin1;
		for (i=0; i<20000; i++)
			if ((t = fgetc(pf)) != EOF)
				*cp++ = t;
			else {
			eof_pins:
				vprint("[X] Random pin file has incorrect size, exiting\n");
				exit(8);
			};
		cp = (uint8*)G->pin2;
		for (i=0; i<20000; i++)
			if ((t = fgetc(pf)) != EOF)
				*cp++ = t;
			else
				goto eof_pins;
		if (fgetc(pf) != EOF)
			goto eof_pins;
		fclose(pf);

		for (i=0; i<9999; i++)
			if (G->pin1[i]<0 || 9999<G->pin1[i] || G->pin1[i]==i) {
			bad_pins:
				vprint("[X] Random pin file appears corrupted, exiting\n");
				exit(8);
			};
		for (i=0; i<9999; i++)
			if (G->pin2[i]<0 || 9999<G->pin2[i])
				goto bad_pins;
	};
};


int get_start(struct global *G)
{
	FILE	*rf;
	int	index, pin, broken;
	int	pin2max = (G->broken ? 10000 : 1000);
	int	pin2div = (G->broken ? 1 : 10);
	char	*line, *last = "00000000:00000000:0::\n";

	char *oldf = malloc(strlen(G->warpath) + 23);
	strcpy(oldf, G->warpath);
	strcat(oldf, "/");
	strcat(oldf, G->ssids);
	strcat(oldf, ".run");
	if ((rf = fopen(oldf, "r")) != NULL)
		rename(oldf, G->runf);
	free(oldf);

	if ((rf = fopen(G->runf, "r")) == NULL) {
		if ((rf = fopen(G->runf, "w")) != NULL) {
			fprintf(rf, "# DO NOT MODIFY CONTENTS OF THIS FILE\n# '%s' (%s)\n", G->essid, G->ssids);
			fclose(rf);
		};
		return 0;
	};

	vprint("[!] Restoring session from '%s'\n", G->runf);

	while ((line = fgets(G->error, 256, rf)) != NULL)
		last = line;

	if ((sscanf(last, "%8d:%8d:%1d:", &index, &pin, &broken)) != 3) {
		vprint("[X] Session save file appears corrupted, exiting\n");
		exit(8);
	};

	if (G->broken) {
		if (!broken) {
			vprint("[!] WARNING: WPS checksum was autogenerated in prior session, now bruteforced\n");
			if (!G->force) {
			force_exit:
				vprint("[X] Use --force to ignore above warning(s) and continue anyway\n");
				exit(10);
			};
		};
	} else {
		index /= 10;
		pin /= 10;
		if (broken) {
			vprint("[!] WARNING: WPS checksum was bruteforced in prior session, now autogenerated\n");
			if (!G->force)	goto force_exit;
		};
	};

	if (G->random) {
		if (index == pin) {
			vprint("[!] WARNING: Randomized search requested but prior session was sequential\n");
			if (!G->force)	goto force_exit;
		} else
			if (pin != G->pin1[index/pin2max] * pin2max + G->pin2[index%pin2max] / pin2div) {
				vprint("[!] WARNING: Randomized pin file modified after last run, can't continue\n");
				if (!G->force)	goto force_exit;
			};
	} else
		if (index != pin) {
			vprint("[!] WARNING: Sequential search requested but prior session was randomized\n");
			if (!G->force)	goto force_exit;
		};

	return index;
};

