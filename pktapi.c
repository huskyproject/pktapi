/*
  PKTAPI Source, Version 1.00

  (c) & (p) 1999-2000 by Oliver 'Attila' Grimm

  Alle Rechte vorbehalten.
*/

#define INCL_DOSPROCESS
#include "pktapi.h"
#include "api_pkt2.h"
#include "pktapip.h"

#include <os2.h>
#include <string.h>

#ifdef OS_2
  word _stdc far pktapierr=0;   
#else
  word _stdc pktapierr=0;       
#endif

static void _dll_end(dword p)
{
  _Pkt2ClosePackets();
}

sword MAPIENTRY PktOpenApi(struct _minf OS2FAR *minf)
{
  DosExitList(EXLST_ADD, (PFNEXITLIST) _dll_end);

  return MsgOpenApi(minf);
}

sword MAPIENTRY PktCloseApi()
{
/* _dll_end() do this work */
/*  _Pkt2ClosePackets(); */
  return MsgCloseApi();
}

HPKT MAPIENTRY PktOpenPkt(byte far *name, word mode, word type)
{
  if (type & PKTTYPE_2)
    return (Pkt2OpenPkt(name,mode,type));
  return 0;
}

sword MAPIENTRY PktInvalidPh(HPKT hp)
{
  if (hp==NULL || hp->id != PKTAPI_ID)
  {
    pktapierr = PERR_BADH;
    return TRUE;
  }

  return FALSE;
}

sword MAPIENTRY PktCopyPktHdr(HPKT dest, HPKT src)
{
  if (PktInvalidPh(dest) ||
      PktInvalidPh(src) )
  {
    return -1;
  }

  /* Nicht schoen, aber schnell */
  memcpy(&dest->orig, &src->orig, (dword)&dest->api - (dword)&dest->orig );

  return 0;
}

