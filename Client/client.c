#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <arpa/inet.h>

#define MAXLEN 255
#define  PORT 2021

char passwd[MAXLEN];
int utente;

void die(char *);
int autenticazione(int);
int port_pasv(int);
int eseguiComando(int, int, char *, char *);
int conn_pass(int, char *);
int conn_att(int, int, char *);
void decifra (char *, char *, char *);
void cifrafile(char *, int, char *, char *);


int main(int argc, char *argv[]) {
	int autenticato, c_control, connessione, porta_dati, bytesent, byterecvd, chiudi;
	char sendbuff[MAXLEN], recvbuff[MAXLEN], comando[MAXLEN];

	struct sockaddr_in server_ip_port;
	int server_ip_port_length = sizeof(server_ip_port);

	memset(sendbuff, 0, MAXLEN);
	memset(recvbuff, 0, MAXLEN);

	if((c_control = socket(AF_INET, SOCK_STREAM, 0)) < 0) die("socket() error");
	//printf("socket() ok.\n");

	server_ip_port.sin_family = AF_INET;
	server_ip_port.sin_addr.s_addr = inet_addr(argv[1]);
	server_ip_port.sin_port = htons(PORT);

	if (connect(c_control, (struct sockaddr *) &server_ip_port, server_ip_port_length) < 0) die("connect() error - Indirizzo non raggiungibile");
	//printf("connect() ok.\n");

	autenticato = autenticazione(c_control);

    //>0 attiva - <0 passiva
	porta_dati = port_pasv(c_control);
    do{
        printf("--------------------\n\nInserire il comando - usa ? per visualizzare la lista:\n");
        fgets(comando, MAXLEN, stdin);
        //Invio comando
        bytesent = send(c_control, comando, MAXLEN, 0);
        if (bytesent <= 0) die("send() error");
        chiudi = eseguiComando(c_control, porta_dati, argv[1], comando);
    }while(chiudi == 0);

	close(c_control);

	return 0;

}

void die(char *error) {
	fprintf(stderr, "%s.\n", error);
	exit(1);
}

int autenticazione(int sd){
    char user[MAXLEN], nonce[5], chiave[13], messaggio[MAXLEN];
    int bytesent, byterecvd, i;
    int utvalido = -1, passvalida = -1;

    do{
        memset(user, 0, MAXLEN);

        printf("Prego autenticarsi\nUsername:\n");

        //Invio username
        fgets(user, MAXLEN, stdin);
        bytesent = send(sd, user, MAXLEN, 0);
        if (bytesent <= 0) die("send() error");
        //printf("Ho inviato %s...\n", user);

        //Ricezione esito
        byterecvd = recv(sd, &utvalido, sizeof(int), 0);
        if (byterecvd <= 0) die("recv() error");
        utvalido = ntohl(utvalido);
        utente = utvalido;

        //Controllo username
        if(utvalido == 0){
            printf("231 - Autenticato come anonimo\nPrego inserire il proprio indirizzo mail come password:\n");
        }
        if(utvalido > 0){
            printf("330 - Username ok\nPrego inserire la password:\n");
        }
        if(utvalido < 0){
            printf("530 - Username non valido\n");
        }
    }while(utvalido < 0);

    //Ricezione nonce
    byterecvd = recv(sd, nonce, 5, 0);
    if (byterecvd <= 0) die("recv() error");
    //printf("Nonce: %s\n", nonce);

    do{
        memset(passwd, 0, MAXLEN);
        fgets(passwd, MAXLEN, stdin);

        if(utvalido == 0){
            //Invio mail da inserire nel log
            bytesent = send(sd, passwd, MAXLEN, 0);
            if (bytesent <= 0) die("send() error");
        }else{
            //Risposta challenge
            memset(chiave, 0, 13);
            strcpy(chiave, "$1$");
            memset(messaggio, 0, MAXLEN);

            strncat(chiave, passwd, 8);
            strcpy(messaggio, crypt(nonce, chiave));
            //azzero i primi bit con la chiave in chiaro
            for (i=0; i<12; i++){
                messaggio[i]='0';
            }
            //printf("Challenge c: %s\n", messaggio);
            bytesent = send(sd, messaggio, MAXLEN, 0);
            if (bytesent <= 0) die("send() error");
        }

        //Ricezione esito
        byterecvd = recv(sd, &passvalida, sizeof(int), 0);
        if (byterecvd <= 0) die("recv() error");
        passvalida = ntohl(passvalida);
        //printf("Esito pass %d\n", passvalida);

        if(passvalida == 1){
            printf("230 - Password ok\n");
        }
        if(passvalida == 0){
            printf("232 - Accesso come anonimo eseguito\n");
        }
        if(passvalida < 0){
            printf("531 - Password errata, riprovare.\n");
        }

    }while(passvalida < 0);

    return passvalida;
}

int port_pasv(int sd){
    int bytesent, byterecvd, com_valido=0, moltipl_porta=0, add_porta=0, porta, controllo=0;
    char comando[MAXLEN], ip[16];

    do{
        printf("Scegliere il tipo di connessione:\n- attiva (comando PORT)\n- passiva (comando PASV)\n");
        fgets(comando, MAXLEN, stdin);
        if((strcmp(comando, "PORT\n") == 0) || (strcmp(comando, "port\n") == 0)){
            //Invio decisione attiva
            com_valido = htonl(1);
            bytesent = send(sd, &com_valido, sizeof(int), 0);
            if (bytesent <= 0) die("send() error");
            com_valido = ntohl(com_valido);

            do{
                printf("320 - Specificare la porta:\n");
                //printf("Porta: ");
                scanf("%d, %d", &moltipl_porta, &add_porta);
                while (getchar()!='\n'); //Per svuotare stdin
                porta = htonl((moltipl_porta*256) + add_porta);
                //Invio porta
                bytesent = send(sd, &porta, sizeof(int), 0);
                if (bytesent <= 0) die("send() error");
                porta = ntohl(porta);
                //Controllo per porte non well-known
                byterecvd = recv(sd, &controllo, sizeof(int), 0);
                if (byterecvd <= 0) die("recv() error");
                controllo = ntohl(controllo);
                if(controllo == -1) printf("Parametri non validi, riprovare.\n");
            }while(controllo == -1);

            printf("221 - PORT ok\n");
            return porta;

        }else if((strcmp(comando, "PASV\n") == 0) || (strcmp(comando, "pasv\n") == 0)){
            //Invio decisione passiva
            com_valido = htonl(2);
            bytesent = send(sd, &com_valido, sizeof(int), 0);
            if (bytesent <= 0) die("send() error");
            com_valido = ntohl(com_valido);
            //Ricezione porta
            byterecvd = recv(sd, &porta, sizeof(int), 0);
            if (byterecvd <= 0) die("recv() error");
            porta = ntohl(porta);
            printf("222 - PASV ok\n");
            return porta*(-1);

        }else{
            printf("Comando non riconosciuto, prego riprovare\n");
        }
	}while(com_valido == 0);
}

int eseguiComando(int sd, int porta_s, char *ip, char *comando){
    int c_data, s_data, connesso=0, byterecvd, bytesent, fb, controllo=-1, dimensione, /*fr,*/ fine=0;
    unsigned scritto;
	char *fr, ris[MAXLEN], argomenti[MAXLEN], percorso[MAXLEN+6], rimuovi[MAXLEN+9], decifr[MAXLEN];
	FILE *f, *fip;

	memset(ris, 0, MAXLEN);
	memset(argomenti, 0, MAXLEN);
    memset(decifr, 0, MAXLEN);
	memset(percorso, 0, MAXLEN+6);
    memset(rimuovi, 0, MAXLEN+9);
	strcpy(percorso, "Downloads/");
	strcpy(rimuovi, "rm ");

	//Creazione descrittore socket dati lato client (per conn. attiva)
	if((s_data = socket(AF_INET, SOCK_STREAM, 0)) < 0) die("socket() dati error");
	//printf("socket() dati ok.\n");
	if (setsockopt(s_data, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0)
        error("setsockopt(SO_REUSEADDR) failed");

	//printf("Mi connetto a %s:%d\n", ip, porta_s);

	//Ricezione feedback sul comando
	byterecvd = recv(sd, &fb, sizeof(int), 0);
    if (byterecvd <= 0) die("recv() error");
    fb = ntohl(fb);

    switch (fb){

    case 1:
        //LS
        //Stabilimnento connessione dati
        if(porta_s < 0){
            porta_s = porta_s*(-1);
            c_data = conn_pass(porta_s, ip);
        }else{
            //Ottengo e invio indirizzo IP locale
            //system("hostname -i > ip.txt");
            system("hostname -I | sed 's/ /:/g' | cut -d: -f1 > ip.txt");
            if((fip = fopen("ip.txt", "r")) == NULL) die("450 - Errore in apertura file temp");
            fgets(argomenti, MAXLEN, fip);
            fclose(fip);
            system("rm ip.txt");
            argomenti[strlen(argomenti) - 1] = '\0';
            bytesent = send(sd, argomenti, MAXLEN, 0);
            if (bytesent <= 0) die("send() error");

            c_data = conn_att(porta_s, s_data, argomenti);
        }
        //Se l'utente è autenticato decifra la comunicazione
        if(utente == 0){
            byterecvd = recv(c_data, ris, MAXLEN, 0);
            if (byterecvd <= 0) die("recv() error");
            printf("250 - LIST ok:\n\n%s", ris);
        }else{
            byterecvd = recv(c_data, ris, MAXLEN, 0);
            if (byterecvd <= 0) die("recv() error");
            decifra(decifr, ris, passwd);
            printf("250 - LIST ok:\n\n%s", decifr);
        }
        close(c_data);
        break;

    case 2:
        //?
        //Stabilimnento connessione dati
        if(porta_s < 0){
            porta_s = porta_s*(-1);
            c_data = conn_pass(porta_s, ip);
        }else{
            //Ottengo e invio indirizzo IP locale
            //system("hostname -i > ip.txt");
            system("hostname -I | sed 's/ /:/g' | cut -d: -f1 > ip.txt");
            if((fip = fopen("ip.txt", "r")) == NULL) die("450 - Errore in apertura file temp");
            fgets(argomenti, MAXLEN, fip);
            fclose(fip);
            system("rm ip.txt");
            argomenti[strlen(argomenti) - 1] = '\0';
            bytesent = send(sd, argomenti, MAXLEN, 0);
            if (bytesent <= 0) die("send() error");

            c_data = conn_att(porta_s, s_data, argomenti);
        }
        //Se l'utente è autenticato decifra la comunicazione
        if(utente == 0){
            byterecvd = recv(c_data, ris, MAXLEN, 0);
            if (byterecvd <= 0) die("recv() error");
            printf("250 - Lista dei comandi:\n\n%s", ris);
        }else{
            byterecvd = recv(c_data, ris, MAXLEN, 0);
            if (byterecvd <= 0) die("recv() error");
            decifra(decifr, ris, passwd);
            printf("250 - Lista dei comandi:\n\n%s", decifr);
        }
        close(c_data);
        break;

    case 3:
        //ADDUSER
        byterecvd = recv(sd, &utente, sizeof(int), 0);
        if (byterecvd <= 0) die("recv() error");
        utente = ntohl(utente);

        if(utente == 1){ //Solo root è autorizzato
            printf("331 - Inserire il nome:\n");
            do{
                fgets(argomenti, MAXLEN, stdin);
                bytesent = send(sd, argomenti, MAXLEN, 0);
                if (bytesent <= 0) die("send() error");

                byterecvd = recv(sd, &controllo, sizeof(int), 0);
                if (byterecvd <= 0) die("recv() error");
                controllo = ntohl(controllo);

                if(controllo != -1) printf("532 - Nome gia' esistente, sceglierne un altro\n");
            }while(controllo != -1);

            printf("Nome ok, inserire la password\n");
            fgets(argomenti, MAXLEN, stdin);
            decifra(decifr, argomenti, passwd);
            bytesent = send(sd, decifr, MAXLEN, 0);
            if (bytesent <= 0) die("send() error");

            byterecvd = recv(sd, &controllo, sizeof(int), 0);
            if (byterecvd <= 0) die("recv() error");
            controllo = ntohl(controllo);

            if(controllo > 0){
                printf("250 - Utente aggiunto correttamente\n");
            }else{
                printf("453 - Errore nell'aggiunta dell'utente\n");
            }

        }else{
            printf("533 - Permesso negato\n");
        }
        break;

    case 4:
        //RETR
        printf("RETR ok, specificare il nome del file:\n");
        fgets(argomenti, MAXLEN, stdin);
        argomenti[strlen(argomenti)-1]=NULL; //Per togliere \n
        bytesent = send(sd, argomenti, MAXLEN, 0);
        if (bytesent <= 0) die("send() error");

        byterecvd = recv(sd, &dimensione, sizeof(int), 0);
        if (byterecvd <= 0) die("recv() dimensione error");
        dimensione = ntohl(dimensione);

        system("mkdir Downloads 2>/dev/null");
        strcat(percorso, argomenti); //Indirizzo nella cartella giusta

        //printf("dim: %d\n", dimensione);

        if(dimensione >= 0){
            //Ricezione feedback su lettura
            byterecvd = recv(sd, &fb, sizeof(int), 0);
            if (byterecvd <= 0) die("recv() feedback error");
            fb = ntohl(fb);

            if(fb == 0){ //Tutto ok

                fr = (char *) malloc(dimensione); //Alloco lo spazio necessario

                //Stabilimnento connessione dati
                if(porta_s < 0){
                    porta_s = porta_s*(-1);
                    c_data = conn_pass(porta_s, ip);
                }else{
                    //Ottengo e invio indirizzo IP locale
                    //system("hostname -i > ip.txt");
                    system("hostname -I | sed 's/ /:/g' | cut -d: -f1 > ip.txt");
                    if((fip = fopen("ip.txt", "r")) == NULL) die("450 - Errore in apertura file temp");
                    fgets(argomenti, MAXLEN, fip);
                    fclose(fip);
                    system("rm ip.txt");
                    argomenti[strlen(argomenti) - 1] = '\0';
                    bytesent = send(sd, argomenti, MAXLEN, 0);
                    if (bytesent <= 0) die("send() error");

                    c_data = conn_att(porta_s, s_data, argomenti);
                }

                byterecvd = recv(c_data, fr, dimensione, 0);
                if (byterecvd < dimensione) printf("421 - Errore in ricezione del file, riprovare\n");
                if(utente != 0){
                    cifrafile(fr, dimensione, fr, passwd);
                }
                close(c_data);

                //printf("ho ricevuto: %s\n", fr);

                f = fopen(percorso, "w");
                scritto = fwrite(fr, 1, dimensione, f);
                fclose(f);

                free(fr);
                fr = NULL;

                if(scritto != dimensione){
                    printf("452 - Errore in scrittura del file, riprovare\n");
                }
                else{
                    printf("220 - File trasferito con successo\n");
                }
            }
            else{
                printf("451 - Errore del server, riprovare\n");
            }
        }else{
            printf("400 - Il file richiesto non esiste\n");
            strcat(rimuovi, percorso);
            system(rimuovi);
        }
        break;

    case 5:
        printf("224 - Sessione chiusa, arrivederci\n");
        fine = 1;
        break;

    case 6:
        printf("500 - Comando non riconosciuto, prego riprovare\n");
        break;
    }

    close(s_data);

    return fine;
}

int conn_pass(int porta_s, char *ip){
    int c_data, connesso=0;
    struct sockaddr_in server_ip_port;
	int server_ip_port_length = sizeof(server_ip_port);

	if((c_data = socket(AF_INET, SOCK_STREAM, 0)) < 0) die("socket() error");
	//printf("socket() dati ok.\n");
	if (setsockopt(c_data, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0)
        error("setsockopt(SO_REUSEADDR) failed");

	server_ip_port.sin_family = AF_INET;
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

int conn_att(int porta_s, int s_data, char *ip){
	struct sockaddr_in bind_ip_port, client_ip_port;
	int bind_ip_port_length = sizeof(bind_ip_port);
	int client_ip_port_length = sizeof(client_ip_port);

	//printf("ip client: %s.\n", ip);

	bind_ip_port.sin_family = AF_INET;
	//bind_ip_port.sin_addr.s_addr = inet_addr("127.0.0.1");
	bind_ip_port.sin_addr.s_addr = inet_addr(ip);
	bind_ip_port.sin_port = htons(porta_s);

	if (bind(s_data, (struct sockaddr *) &bind_ip_port, bind_ip_port_length) < 0) die("bind() dati error");
	//printf("bind() dati ok.\n");

	if (listen(s_data, 1) < 0) die("listen() dati error");
	//printf("listen() dati ok.\n");

    int c_data = accept(s_data, NULL, NULL);

    return c_data;

}

void decifra(char decritto[MAXLEN], char cifrato[MAXLEN], char passwd[MAXLEN]){
    int i;

    for(i=0; i<MAXLEN; i++){
        decritto[i] = cifrato[i] ^ passwd[i%strlen(passwd)];
    }
}

void cifrafile(char *file, int dimensione, char *cifrato, char passwd[MAXLEN]){
    int i;

    for(i=0; i<dimensione; i++){
        cifrato[i] = file[i] ^ passwd[i%strlen(passwd)];
    }
}
