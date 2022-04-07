#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <time.h>

#define MAXLEN 255
#define PORT 2021
#define LISTEN 5

void die(char *);
void handleClient(int);
int autenticazione(int);
int port_pasv(int);
int eseguiComando(int, int, char *, int);
int conn_pass(int, int);
int conn_att(int, char *);
void cifra (char *, char *, char *);
void cifrafile(char *, int, char *, char *);
int interpreta(char *);

typedef struct{
    char nome[MAXLEN];
    char pass[MAXLEN];
}utente;

struct arrayUtenti{
    utente *p;
    int dim;
};

struct arrayUtenti ut;

int main() {

	int s_control;
	struct sockaddr_in bind_ip_port, client_ip_port;
	int bind_ip_port_length = sizeof(bind_ip_port);
	int client_ip_port_length = sizeof(client_ip_port);
	pid_t pid;

	if((s_control = socket(AF_INET, SOCK_STREAM, 0)) < 0) die("socket() error");
	printf("socket() ok.\n");

	if (setsockopt(s_control, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0)
        error("setsockopt(SO_REUSEADDR) failed");

	bind_ip_port.sin_family = AF_INET;
	//bind_ip_port.sin_addr.s_addr = inet_addr("127.0.0.1");
    bind_ip_port.sin_addr.s_addr = inet_addr("10.0.0.10");
	bind_ip_port.sin_port = htons(PORT);

	if (bind(s_control, (struct sockaddr *) &bind_ip_port, bind_ip_port_length) < 0) die("bind() error");
	printf("bind() ok.\n");

	if (listen(s_control, LISTEN) < 0) die("listen() error");
	printf("listen() ok.\n");

	while (1) {

		int c_control = accept(s_control, NULL, NULL);

		pid = fork();

		if (pid < 0) die("fork() error");
		else if (pid > 0) close(c_control);
		else {

			close(s_control);
			handleClient(c_control);
			close(c_control);
			exit(0);

		}

	}

	close(s_control);

	return 0;

}

void handleClient(int sd) {
    int autenticato, connessione, byterecvd, chiudi;
    char comando[MAXLEN];

    memset(comando, 0, MAXLEN);

    //autenticato definisce l'utente - lo 0 indica anonimo
    autenticato = autenticazione(sd);

    //>0 attiva - <0 passiva | il valore assoluto è la porta
    connessione = port_pasv(sd);

    do{
        byterecvd = recv(sd, comando, MAXLEN, 0);
        if (byterecvd <= 0) die("recv() error");
        //printf("Ho ricevuto %s", comando);
        chiudi = eseguiComando(sd, connessione, comando, autenticato);
    }while(chiudi == 0);
}

void die(char *error) {
	fprintf(stderr, "%s.\n", error);
	exit(1);
}

int autenticazione(int sd){
	//struct arrayUtenti ut;
    int i = 0, utvalido = -1, passvalida = -1, byterecvd, bytesent;
    char *lettura;
    char cestino[MAXLEN];
    FILE *fu, *fa;
    char sendbuff[MAXLEN], user[MAXLEN], password[MAXLEN], nonce[5], chiave[13], mail[MAXLEN], messaggio[MAXLEN], ricevuto[MAXLEN];

	//Perchè conteggio fa un giro in più
    ut.dim = -1;

    //Conteggio utenti per capire memoria necessaria
    if((fu = fopen("Utenti.txt", "r")) == NULL) die("450 - Errore in apertura file utenti");
    do{
        lettura = fgets(cestino, MAXLEN, fu);
        lettura = fgets(cestino, MAXLEN, fu);
        ut.dim++;
    }while(lettura != NULL);
    fclose(fu);

    //Allocazione memoria necessaria
    ut.p = malloc(ut.dim*sizeof(utente));

    printf("Tentativo di accesso\n");

    //Lettura nome-password
    if((fu = fopen("Utenti.txt", "r")) == NULL) die("450 - Errore in apertura file utenti");
    for(i=0; i<ut.dim; i++){
        fgets(ut.p[i].nome, MAXLEN, fu);
        fgets(ut.p[i].pass, MAXLEN, fu);
    }
    fclose(fu);

    //Stampa user : pass
    /*printf("Numero utenti: %d:\n", ut.dim);
    for(i=0; i<ut.dim; i++){
        printf("%s:%s", ut.p[i].nome, ut.p[i].pass);
    }
    printf("\n");*/

    do{

        memset(user, 0, MAXLEN);
        //Controllo username
        byterecvd = recv(sd, user, MAXLEN, 0);
        if (byterecvd <= 0) die("recv() error");
        //printf("Ho ricevuto %sControllo...\n", user);

        //Autenticazione anonima
        if(strcmp(user, "anonimo\n") == 0){
            utvalido = 0;
        }
        else{
            //Autenticazione da user
            for(i=0; i<ut.dim; i++){
                if(strcmp(ut.p[i].nome, user) == 0){
                    utvalido = i+1; //Lo 0 è riservato all'anonimo
                }
            }
        }

        //Invio esito
        utvalido = htonl(utvalido);
        bytesent = send(sd, &utvalido, sizeof(int), 0);
        if (bytesent <= 0) die("send() error");
        utvalido = ntohl(utvalido);
        //printf("Esito user: %d\n", utvalido);

    }while(utvalido < 0);

    //Calcolo e invio nonce
    for(i=0; i<4; i++){
        nonce[i] = 48 + rand()%75;
        if(nonce[i] == '\0') nonce[i] = '?';
    }
    nonce[i] = '\0';
    bytesent = send(sd, nonce, 5, 0);
    if (bytesent <= 0) die("send() error");
    //printf("Nonce: %s\n", nonce);

    do{

        //Email per gli anonimi
        if(utvalido == 0){
            passvalida = 0;
            byterecvd = recv(sd, mail, MAXLEN, 0);
            if (byterecvd <= 0) die("recv() error");
            //printf("Ho ricevuto %sInserisco nel log...\n", mail);
            //Iscrizione nel log anonimi
            if((fa = fopen("Anonimi.txt", "a")) == NULL) die("450 - Errore apertura file per il log degli anonimi");
            mail[strlen(mail) - 1] = NULL; //Per eliminare il carattere a capo
            fprintf(fa, "%s\n", mail);
            fclose(fa);
        }else{
            //Controllo challenge
            memset(chiave, 0, 13);
            strcpy(chiave, "$1$");
            memset(messaggio, 0, MAXLEN);
            //memset(password, 0, MAXLEN);

            strncat(chiave, ut.p[utvalido - 1].pass, 8);
            strcpy(messaggio, crypt(nonce, chiave));
            //azzero i primi bit con la chiave
            for (i=0; i<12; i++){
                messaggio[i]='0';
            }
            //printf("Challenge s: %s\n", messaggio);
            byterecvd = recv(sd, ricevuto, MAXLEN, 0);
            if (byterecvd <= 0) die("recv() error");

            if(strcmp(ricevuto, messaggio) == 0)
                passvalida = 1;
        }

        //Invio esito
        passvalida = htonl(passvalida);
        bytesent = send(sd, &passvalida, sizeof(int), 0);
        if (bytesent <= 0) die("send() error");
        passvalida = ntohl(passvalida); //Inutile - solo per test qua sotto
        //printf("Esito pass %d\n", passvalida);

        if(passvalida < 0) printf("Autenticazione fallita\n");

    }while(passvalida < 0);

    if(utvalido != 0) printf("Si è autenticato %s\n", ut.p[utvalido - 1].nome);
    if(utvalido == 0) printf("Si è autenticato %s in maniera anonima\n\n", mail);

    return utvalido;
}

int port_pasv(int sd){
    int decisione, porta, bytesent, byterecvd, controllo=-1;
    char ip[16];
    in_addr_t indirizzo;

    srand(time(NULL));

    //Ricezione decisione
    byterecvd = recv(sd, &decisione, sizeof(int), 0);
    if (byterecvd <= 0) die("recv() error");
    decisione = ntohl(decisione);

    if(decisione == 1){
        //Modalità attiva
        do{
            byterecvd = recv(sd, &porta, sizeof(int), 0);
            if (byterecvd <= 0) die("recv() error");
            porta = ntohl(porta);
            if(porta < 1024){
                controllo = -1;
            }else{
                controllo = 1;
            }
            controllo = htonl(controllo);
            bytesent = send(sd, &controllo, sizeof(int), 0);
            if (bytesent <= 0) die("send() error");
            controllo = ntohl(controllo);
        }while(controllo == -1);
        printf("Attiva. Porta:%d\n", porta);
        return porta;
    }
    if(decisione == 2){
        //Modalità passiva
        porta = htonl(((rand()%256)*256) + (rand()%256) + 1024);
        bytesent = send(sd, &porta, sizeof(int), 0);
        if (bytesent <= 0) die("send() error");
        porta = ntohl(porta);
        printf("Passiva. Porta: %d\n", porta);
        return porta*(-1);
    }
}

int eseguiComando(int sd, int porta_s, char *comando, int utente){
    int s_data, c_data, bytesent, byterecvd, fb, i, controllo=-1, dimensione, fine=0;
    char *sorgente, *cifrato;
    unsigned letto;
	struct stat file_s;
	FILE *fr, *fu, *fs;
    char ris[MAXLEN], riga[MAXLEN], argomenti[MAXLEN], percorso[MAXLEN+6], ip[MAXLEN], cifr[MAXLEN];

	memset(ris, 0, MAXLEN);
	memset(riga, 0, MAXLEN);
	memset(argomenti, 0, MAXLEN);
	memset(cifr, 0, MAXLEN);
	memset(ip, 0, MAXLEN);
	memset(percorso, 0, MAXLEN+6);
	strcpy(percorso, "Files/");

	//Creazione descrittore socket dati lato server (per conn. passiva)
	if((s_data = socket(AF_INET, SOCK_STREAM, 0)) < 0) die("socket() dati error");
	//printf("socket() dati ok.\n");
	if (setsockopt(s_data, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0)
        error("setsockopt(SO_REUSEADDR) failed");

    switch (interpreta(comando)){

        case 1:
            //LIST
            fb = htonl(1);
            bytesent = send(sd, &fb, sizeof(int), 0);
            if (bytesent <= 0) die("send() error");

            //Leggi e invia temp.txt
            if((fr = fopen("temp.txt", "r")) == NULL) die("450 - Errore in apertura file temp");
            while(!feof(fr)){
                fgets(riga, MAXLEN, fr);
                if(!feof(fr)) strcat(ris, riga);
            }
            //Stabilimento connessione dati
            if(porta_s < 0){
                porta_s = porta_s*(-1);
                c_data = conn_pass(porta_s, s_data);
            }else{
                //Ricevo indirizzo IP client
                byterecvd = recv(sd, ip, MAXLEN, 0);
                if (byterecvd <= 0) die("recv() error");
                c_data = conn_att(porta_s, ip);
            }
            //Se l'utente è autenticato cifra la comunicazione
            if(utente == 0){
                bytesent = send(c_data, ris, strlen(ris) + 1, 0);
                if (bytesent <= 0) die("send() error");
            }else{
                cifra(cifr, ris, ut.p[utente -1].pass);
                bytesent = send(c_data, cifr, strlen(ris) + 1, 0);
                if (bytesent <= 0) die("send() error");
            }
            close(c_data);
            fclose(fr);
            break;

        case 2:
            //?
            fb = htonl(2);
            bytesent = send(sd, &fb, sizeof(int), 0);
            if (bytesent <= 0) die("send() error");

            strcpy(ris, "? - Visualizza la lista dei comandi\nLS - Visualizza la lista dei file e cartelle\nADDUSER - Aggiungi un nuovo utente, solo per l'amministratore\nRETR - Scarica un file dal server\nQUIT - Chiudi la sessione\n");

            //Stabilimento connessione dati
            if(porta_s < 0){
                porta_s = porta_s*(-1);
                c_data = conn_pass(porta_s, s_data);
            }else{
                //Ricevo indirizzo IP client
                byterecvd = recv(sd, ip, MAXLEN, 0);
                if (byterecvd <= 0) die("recv() error");
                c_data = conn_att(porta_s, ip);
            }
            //Se l'utente è autenticato cifra la comunicazione
            if(utente == 0){
                bytesent = send(c_data, ris, strlen(ris) + 1, 0);
                if (bytesent <= 0) die("send() error");
            }else{
                cifra(cifr, ris, ut.p[utente -1].pass);
                bytesent = send(c_data, cifr, strlen(ris) + 1, 0);
                if (bytesent <= 0) die("send() error");
            }
            close(c_data);
            break;

        case 3:
            //ADDUSER
            fb = htonl(3);
            bytesent = send(sd, &fb, sizeof(int), 0);
            if (bytesent <= 0) die("send() error");

            utente = htonl(utente);
            bytesent = send(sd, &utente, sizeof(int), 0);
            if (bytesent <= 0) die("send() error");
            utente = ntohl(utente);

            if(utente == 1){ //L'utente è root
                do{
                    byterecvd = recv(sd, argomenti, MAXLEN, 0); //Ricevo nome utente
                    if (byterecvd <= 0) die("recv() error");
                    controllo = -1;  //Flag per utente con nome uguale
                    for(i=0; i<ut.dim; i++){
                        if(strcmp(argomenti, ut.p[i].nome) == 0) controllo = i; //Trovato utente con lo stesso nome
                    }
                    controllo = htonl(controllo);
                    bytesent = send(sd, &controllo, sizeof(int), 0);
                    if (bytesent <= 0) die("send() error");
                }while(controllo != -1);

                if((fu = fopen("Utenti.txt", "a")) == NULL) die("450 - Errore in apertura file temp");

                fprintf(fu, "%s", argomenti); //Scrivo username
                printf("Aggiungo utente %s...\n", argomenti);

                byterecvd = recv(sd, argomenti, MAXLEN, 0); //Ricevo password
                if (byterecvd <= 0) die("recv() error");
                cifra(cifr, argomenti, ut.p[0].pass);
                controllo = fprintf(fu, "%s", cifr); //Scrivo password

                if(controllo == strlen(cifr)){
                    printf("Password: %s", cifr);
                }else{
                    printf("Utente non aggiunto correttamente\n");
                    fprintf(fu, "---\n"); //Per riempire lo spazio
                }
                fclose(fu);

                controllo = htonl(controllo);
                bytesent = send(sd, &controllo, sizeof(int), 0);
                if (bytesent <= 0) die("send() error");

            }else{
                printf("Permesso negato\n");
            }
            break;

        case 4:
            //RETR
            fb = htonl(4);
            bytesent = send(sd, &fb, sizeof(int), 0);
            if (bytesent <= 0) die("send() error");

            byterecvd = recv(sd, argomenti, MAXLEN, 0); //Ricevo nome file
            if (byterecvd <= 0) die("recv() error");

            strcat(percorso, argomenti); //Indirizzo nella cartella giusta
            //printf("File: %s.\n", percorso);

            dimensione = stat(percorso, &file_s); //0 successo; -1 insuccesso
            if(dimensione == 0)
                dimensione = (int)file_s.st_size;
            dimensione = htonl(dimensione);
            bytesent = send(sd, &dimensione, sizeof(int), 0); //Invio la dimensione del file
            if (bytesent <= 0) die("send() error");
            dimensione = ntohl(dimensione);

            if(dimensione >= 0){
                if(utente == 0){
                    printf("E' stato richiesto %s.\n", percorso);
                }else{
                    printf("%sha richiesto %s.\n", ut.p[utente-1].nome, percorso);
                }
                //Acquisizione contenuto
                if((fs = fopen(percorso, "r")) == NULL) die("450 - Errore in apertura file");
                sorgente = (char *) malloc(dimensione);
                //cifrato = (char *) malloc(dimensione);
                letto = fread(sorgente, 1, dimensione, fs);
                fclose(fs);
                //printf("Ho letto %u bytes: %s.\n", letto, sorgente);

                //Controllo sulla lettura integrale
                if(letto != dimensione){
                    fb = htonl(-1);
                    printf("451 - Errore in lettura\n");
                }else{
                    fb = htonl(0);
                }
                //Invio feedback su lettura
                bytesent = send(sd, &fb, sizeof(int), 0);
                if (bytesent <= 0) die("send() error");
                fb = ntohl(fb);

                if(fb == 0){ //Tutto ok
                    //Stabilimento connessione dati
                    if(porta_s < 0){
                        porta_s = porta_s*(-1);
                        c_data = conn_pass(porta_s, s_data);
                    }else{
                        //Ricevo indirizzo IP client
                        byterecvd = recv(sd, ip, MAXLEN, 0);
                        if (byterecvd <= 0) die("recv() error");
                        c_data = conn_att(porta_s, ip);
                    }
                    if(utente != 0){
                        cifrafile(sorgente, dimensione, sorgente, ut.p[utente-1].pass);
                    }
                    bytesent = send(c_data, sorgente, dimensione, 0); //Invio il file
                    if (bytesent < dimensione) die("send() file error");
                    close(c_data);
                }
                free(sorgente);
                sorgente = NULL;
            }
            break;

        case 5:
            //QUIT
            fb = htonl(5);
            bytesent = send(sd, &fb, sizeof(int), 0);
            if (bytesent <= 0) die("send() error");
            fine = 1;
            break;

        case 6:
            //Non riconosciuto
            fb = htonl(6);
            bytesent = send(sd, &fb, sizeof(int), 0);
            if (bytesent <= 0) die("send() error");
            break;
		}

	close(s_data);

	return fine;
}

int interpreta(char *comando){

    printf("Eseguo %s", comando);

    if(strcmp(comando, "ls\n") == 0 || strcmp(comando, "LIST\n") == 0 || strcmp(comando, "List\n") == 0){
        system("cd Files; ls > ../temp.txt");
        return 1;
    }else if(strcmp(comando, "?\n") == 0){
        return 2;
    }else if(strcmp(comando, "adduser\n") == 0 || strcmp(comando, "ADDUSER\n") == 0){
        return 3;
    }else if(strcmp(comando, "retr\n") == 0 || strcmp(comando, "RETR\n") == 0){
        return 4;
    }else if(strcmp(comando, "quit\n") == 0 || strcmp(comando, "QUIT\n") == 0){
        return 5;
    }
    return 6;
}

int conn_pass(int porta_s, int s_data){
	struct sockaddr_in bind_ip_port, client_ip_port;
	int bind_ip_port_length = sizeof(bind_ip_port);
	int client_ip_port_length = sizeof(client_ip_port);

	bind_ip_port.sin_family = AF_INET;
	//bind_ip_port.sin_addr.s_addr = inet_addr("127.0.0.1");
    bind_ip_port.sin_addr.s_addr = inet_addr("10.0.0.10");
	bind_ip_port.sin_port = htons(porta_s);

	if (bind(s_data, (struct sockaddr *) &bind_ip_port, bind_ip_port_length) < 0) die("bind() dati error");
	//printf("bind() dati ok.\n");

	if (listen(s_data, 1) < 0) die("listen() dati error");
	//printf("listen() dati ok.\n");

    int c_data = accept(s_data, NULL, NULL);

    return c_data;

}

int conn_att(int porta_s, char *ip){
    int c_data, connesso=0;
    struct sockaddr_in server_ip_port;
	int server_ip_port_length = sizeof(server_ip_port);

	if((c_data = socket(AF_INET, SOCK_STREAM, 0)) < 0) die("socket() error");
	//printf("socket() dati ok.\n");
	if (setsockopt(c_data, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0)
        error("setsockopt(SO_REUSEADDR) failed");

	server_ip_port.sin_family = AF_INET;
	//server_ip_port.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_ip_port.sin_addr.s_addr = inet_addr(ip);
	server_ip_port.sin_port = htons(porta_s);

	//printf("Connessione in corso... ");

	do{
        connesso = connect(c_data, (struct sockaddr *) &server_ip_port, server_ip_port_length);
        //printf("Elaboro");
	}while(connesso < 0);
	//printf("connect() dati ok.\n");

	return c_data;
}

void cifra (char critto[MAXLEN], char testo[MAXLEN], char passwd[MAXLEN]){
    int i;

    for(i=0; i<MAXLEN; i++){
        critto[i] = testo[i] ^ passwd[i%strlen(passwd)];
    }
}

void cifrafile(char *file, int dimensione, char *cifrato, char passwd[MAXLEN]){
    int i;

    for(i=0; i<dimensione; i++){
        cifrato[i] = file[i] ^ passwd[i%strlen(passwd)];
    }
}


