/*
  PKTAPI Source, Version 1.00

  (c) & (p) 1999-2000 by Oliver 'Attila' Grimm

  Alle Rechte vorbehalten.
*/

#include <fcntl.h>
#include <sys\stat.h>
#include <share.h>
#include <io.h>
#include <string.h>

#include "pktapi.h"
#include "api_pkt2.h"
#include "platform_pkt.h"

static sword  _Pkt2ReadMsgHdr(HPKT hp, PKT2MSGHEADER *msghdr)
{
  if (readPKT2MSGHEADER(P2d->pfd, msghdr) < 2l)
  {
    pktapierr = PERR_BADMSG;
    return -1;
  }

  if (msghdr->signatur == 0)
  {
    pktapierr = PERR_EOF;
    return -1; /* EOF Packet */
  }

  if (msghdr->signatur != 2)
  {
    pktapierr = PERR_BADSIGN;
    return -1; /* Bad packet */
  }

  return 0; /* Ok */
}

static sword _Pkt2ReadField(HPKT hp, char *buf, int len)
{
  dword fpos=tell(P2d->pfd);
  dword rlen;
  sword rc = 1; 

  if (read(P2d->pfd, buf, len) == 0)
  {
    pktapierr = PERR_EOF;
    return -1;
  }

  buf[len] = 0;

  rlen = strlen(buf);

  /* Filepos = Filepos + Length of String */
  fpos += rlen;

  /* If Length of String < Requested Len, rc = 0 */
  if (rlen != len)
  {
    fpos ++;
    rc = 0;
    P2d->in_msg = 0;
  }

  lseek(P2d->pfd, fpos, SEEK_SET);

  return rc;
}

/* Convert P2-Msghdr Information to XMSG Structur */

static void _Pkt2ConvertMsghdrToXmsg(XMSG *xmsg, PKT2MSGHEADER *msghdr)
{
  xmsg->orig.node = msghdr->orig_node;
  xmsg->dest.node = msghdr->dest_node;
  xmsg->orig.net  = msghdr->orig_net;
  xmsg->dest.net  = msghdr->dest_net;
  xmsg->attr      = msghdr->attrib;

  /* Copy 19 byte to make sure, Byte 20 is '\0' */
  memcpy(xmsg->__ftsc_date, msghdr->datetime, 19);
  
  MsgCvtFTSCDateToBinary(xmsg->__ftsc_date, (union stamp_combo *)&xmsg->date_written);
}

sword PKTAPI Pkt2ReadMsg(HPKT hp, XMSG *xmsg, dword textlen, byte *textptr)
{
  PKT2MSGHEADER msghdr;
  sword rc;

  if (PktInvalidPh(hp))
    return -1;

  if (hp->mode != PKTMODE_READ)
  {
    pktapierr = PERR_BADM;
    return -1;
  }

  /* When XMSG = 0, then read Text */
  if (xmsg)
  {
    memset(xmsg, 0, sizeof(XMSG));

    if (P2d->in_msg)
    {
      char *buf = malloc(4096);
      while (_Pkt2ReadField(hp, buf, 4095) == 1);
      free(buf);
    }

    if ((rc=_Pkt2ReadMsgHdr(hp, &msghdr)) != 0)
      return rc;

    _Pkt2ConvertMsghdrToXmsg(xmsg, &msghdr);

    _Pkt2ReadField(hp, xmsg->to  , 35);

    _Pkt2ReadField(hp, xmsg->from, 35);

    _Pkt2ReadField(hp, xmsg->subj, 71);
   
    /* Filepointer is in Mail */
    P2d->in_msg = 1;
  }

  /* If Body is'nt requested, don't read Body */
  /* If we're not in a message - do nothing */
  if (P2d->in_msg && textptr && (textlen > 1))
    return _Pkt2ReadField(hp, textptr, textlen-1);
  else 
    if (textptr) 
      *textptr = 0;  

  return P2d->in_msg;
}

sword PKTAPI Pkt2ReadMsgComplete(HPKT hp, XMSG *xmsg, byte **textptr)
{
  dword len = 8192;
  dword ofs = 0;

  if (Pkt2ReadMsg(hp, xmsg, 0, 0) == -1)
    return -1;

  *textptr = realloc(*textptr, len);

  while (Pkt2ReadMsg(hp, 0, 8192, (*textptr)+ofs) == 1)
  {
    ofs += 8191;
    len += 8192;
    *textptr = realloc(*textptr, len);
  }

  return 0;
}
