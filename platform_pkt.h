/*
  PKTAPI Source, Version 1.00

  (c) & (p) 1999-2000 by Oliver 'Attila' Grimm

  Alle Rechte vorbehalten.
*/


#ifndef __PLATFORM_H
#define __PLATFORM_H

#include "pktdef.h"

int readPKT2MSGHEADER(int fd,  PKT2MSGHEADER *hdr);
int writePKT2MSGHEADER(int fd,  PKT2MSGHEADER *hdr);
int readPKTHEADER(int fd, PKTHEADER *hdr);
int writePKT2PHEADER(int fd, PKT2PHEADER *hdr);

#endif