#!/bin/bash

gcc -Wall -o dovecot-ocf -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -lplumb -lssl -lcrypto ocf.c iface.c utils.c dovecot.c iostream.c imap.c pop3.c main.c
