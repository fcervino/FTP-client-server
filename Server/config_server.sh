#!/bin/bash

echo "------------------------------------"
echo "~   Corso di Reti di Calcolatori   ~"
echo "~ Universita degli Studi di Milano ~"
echo "------------------------------------"

echo "Progetto - Protocollo FTP - Federico Cervino (923330)"
echo

Color_Off='\e[0m' 
bldgrn='\e[1;32m'

ok_colorato_per_log() {
        RED=$(tput setaf 1)
        GREEN=$(tput setaf 2)
        NORMAL=$(tput sgr0)
        LENMSG="$1"
        let COL=$(tput cols)-${LENMSG}
        printf "%${COL}s%s%s%s%s%s" "$NORMAL" "[" "$GREEN" "OK" "$NORMAL" "]"
}
do_cmd() {
	local cmd;
	local msg;
	cmd="$1"
	msg="$2"
	echo
	echo -e $bldgrn $cmd $Color_Off;
	eval "$cmd"  2>/dev/null
	echo
	echo -n "$msg"
	ok_colorato_per_log ${#msg}
	read -rsp $'\nPremere invio per continuare...\n'
}

sudo -i exit

do_cmd "sudo himage host1 mkdir FTP"						"Creo la cartella FTP"
do_cmd "sudo hcp server host1:/FTP"						"Copio l'eseguibile"
do_cmd "sudo hcp Utenti.txt host1:/FTP"						"Copio il file per gli accessi"
do_cmd "sudo himage host1 mkdir FTP/Files"					"Creo la cartella Files"
do_cmd "sudo hcp Files/Testo1.txt host1:/FTP/Files"				"Copio file"
do_cmd "sudo hcp Files/Testo2.txt host1:/FTP/Files"				"Copio file"
do_cmd "sudo hcp Files/Testo3.txt host1:/FTP/Files"				"Copio file"
do_cmd "sudo hcp Files/img.jpeg host1:/FTP/Files"				"Copio file"
echo
