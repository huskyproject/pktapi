/*
  PKTAPI Source, Version 1.00

  (c) & (p) 1999-2000 by Oliver 'Attila' Grimm

  Alle Rechte vorbehalten.
*/


#ifndef __API_PKT2_H
#define __API_PKT2_H

#include "pktdef.h"

#define P2d ((PKT2DATA *)(hp->apidata))

typedef struct _pkt2data
{
  
  int  pfd;               /* Pkt Handle */
  int  in_msg;            /* Steht der Lese-Pointer in einer Msg ? */

  HPKT next;              /* Next open Area */
} PKT2DATA;

/* Prototypes */

void PKTAPI _Pkt2ClosePackets(void);

HPKT PKTAPI Pkt2OpenPkt(byte far *name, word mode, word type);
sword PKTAPI Pkt2ClosePkt(HPKT hp);
sword PKTAPI Pkt2ReadMsg(HPKT hp, XMSG *xmsg, dword len, char *textptr);
sword PKTAPI Pkt2WriteMsg(HPKT hp, XMSG *xmsg, word fAppend, char *textptr);

sword PKTAPI Pkt2ReadMsgComplete(HPKT hp, XMSG *xmsg, char **textptr);


#endif