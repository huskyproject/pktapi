/*
  PKTAPI Source, Version 1.00

  (c) & (p) 1999-2000 by Oliver 'Attila' Grimm

  Alle Rechte vorbehalten.
*/


#ifndef __PKTAPI_H
#define __PKTAPI_H

#include <prog.h>
#include <msgapi.h>

#define PKTAPI
#define PKTAPI_VERSION    0
#define PKTAPI_SUBVERSION 0

#define PERR_BADH 0
#define PERR_BADM 1
#define PERR_BADSIGN 2
#define PERR_BADMSG 3
#define PERR_EOF 3
#define PERR_NOMEM 4

struct _pktapi;

typedef struct _pktapi OS2FAR *HPKT;


/* mode - PktOpenPkt() */

#define PKTMODE_READ  1
#define PKTMODE_WRITE 2

#define PKTTYPE_UNKNOWN 0
#define PKTTYPE_2       0x01
#define PKTTYPE_2_PLUS  0x03
#define PKTTYPE_2_2     0x05
#define PKTTYPE_3       0x08

struct _pktapi
{
  #define PKTAPI_ID 0x63630232

  dword   id;

  word    len;
  word    type;
  word    mode;

  NETADDR orig;
  NETADDR dest;

  byte    password[8];

  struct _stamp date_written;

  word  prod_code;
  
  word  capability;

  struct _papifuncs
  {
    sword  (*MAPIENTRY ClosePkt)(HPKT ph);
    sword  (*MAPIENTRY ReadMsg)(HPKT ph, XMSG *xmsg, dword len, char *textptr);
    sword  (*MAPIENTRY WriteMsg)(HPKT ph, XMSG *xmsg, word fAppend, char *textptr);
    sword  (*MAPIENTRY ReadMsgComplete)(HPKT ph, XMSG *xmsg, char **textptr);

  } OS2FAR *api;

  void *apidata;

  sword sem;
};

typedef struct _ADDRBUF
{
  dword    num_addr;
  NETADDR *addr;
} ADDRBUF;

typedef struct _PKTCTRLBUF
{
  ADDRBUF seenby;
  ADDRBUF path;
} PKTCTRLBUF;

#ifdef OS_2 /* Imported .DLL variables are not in DGROUP */
extern word far _stdc pktapierr;
#else
extern word _stdc pktapierr;
#endif


#define PktClosePkt(ph)          (*(ph)->api->ClosePkt)(ph)
#define PktReadMsg(ph, x, l, t)  (*(ph)->api->ReadMsg)(ph, x, l, t)
#define PktWriteMsg(ph, x, f, t) (*(ph)->api->WriteMsg)(ph, x, f, t)
#define PktReadMsgComplete(ph, x, t) (*(ph)->api->ReadMsgComplete)(ph, x, t)

#define PktFreeText(t) free(t)

cpp_begin()

  sword MAPIENTRY PktOpenApi(struct _minf OS2FAR *minf);
  sword MAPIENTRY PktCloseApi(void);

  HPKT MAPIENTRY PktOpenPkt(byte far *name, word mode, word type);
  sword MAPIENTRY PktInvalidPh(HPKT hp);
  
  sword MAPIENTRY PktCopyPktHdr(HPKT dest, HPKT src);

  sword MAPIENTRY PktCreateCtrlBuf(char *sztext, PKTCTRLBUF *ctrlbuf);
  sword MAPIENTRY PktFreeCtrlBuf(PKTCTRLBUF *ctrl);

  char * MAPIENTRY PktConvertCtrlToText(PKTCTRLBUF *ctrl);

  sword MAPIENTRY PktCtrlAddSeenby(PKTCTRLBUF *ctrl, NETADDR *addr);
  sword MAPIENTRY PktCtrlAddPath(PKTCTRLBUF *ctrl, NETADDR *addr);
  sword MAPIENTRY PktCtrlChkPath(PKTCTRLBUF *ctrl, NETADDR *addr);

cpp_end()

#endif
