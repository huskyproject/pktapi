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

static sword  _Pkt2WriteMsgHdr(HPKT hp, PKT2MSGHEADER *msghdr)
{
  if (writePKT2MSGHEADER(P2d->pfd, msghdr) != sizeof(PKT2MSGHEADER))
  {
    return -1;
  }

  return 0; /* Ok */
}

static sword _Pkt2WriteField(HPKT hp, char *buf, dword len)
{
  char endmark = 0;

  if (!buf)
  {
    buf = &endmark;
    len = 1;
  }

  if (write(P2d->pfd, buf, len) != len)
  {
    return -1;
  }

  return 0;
}

/* Convert P2-Msghdr Information to XMSG Structur */

static void _Pkt2ConvertXmsgToMsghdr(PKT2MSGHEADER *msghdr, XMSG *xmsg)
{
  msghdr->signatur  = 2;
  msghdr->orig_node = xmsg->orig.node;
  msghdr->dest_node = xmsg->dest.node;

  msghdr->orig_net = xmsg->orig.net;
  msghdr->dest_net = xmsg->dest.net;
  msghdr->attrib   = (word) (xmsg->attr & 0xFFFF);

  /* Copy 19 byte to make sure, Byte 20 is '\0' */
  memcpy(msghdr->datetime, xmsg->__ftsc_date, 19);
}

sword PKTAPI Pkt2WriteMsg(HPKT hp, XMSG *xmsg, word fAppend, byte *textptr)
{
  PKT2MSGHEADER msghdr;
  sword rc;

  if (PktInvalidPh(hp))
    return -1;

  if (hp->mode != PKTMODE_WRITE)
  {
    pktapierr = PERR_BADM;
    return -1;
  }

  /* When XMSG = 0, then write Text */
  if (xmsg)
  {
    memset(&msghdr, 0, sizeof(PKT2MSGHEADER));

    if (P2d->in_msg)
    {
      _Pkt2WriteField(hp, 0, 0);
      P2d->in_msg = 0;
    }

    _Pkt2ConvertXmsgToMsghdr(&msghdr, xmsg);

    if ((rc=_Pkt2WriteMsgHdr(hp, &msghdr)) != 0)
      return rc;

    _Pkt2WriteField(hp, xmsg->to, strlen(xmsg->to)+1);

    _Pkt2WriteField(hp, xmsg->from, strlen(xmsg->from)+1);

    _Pkt2WriteField(hp, xmsg->subj, strlen(xmsg->subj)+1);
   
    /* Filepointer is in Mail */
  }

  if (fAppend)
  {
    P2d->in_msg = 1;
    /* If fAppend != 0 and textptr = 0 -> messagebody is written later */
    if (textptr)
      _Pkt2WriteField(hp, textptr, strlen(textptr));
  }
  else
  {
    /* If fAppend = 0 and textptr = 0 -> no messagebody ! */
    P2d->in_msg = 0; 
    _Pkt2WriteField(hp, textptr, strlen(textptr)+1);
  }

  return 0;
}
