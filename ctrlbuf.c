/*
  PKTAPI Source, Version 1.00

  (c) & (p) 1999-2000 by Oliver 'Attila' Grimm

  Alle Rechte vorbehalten.
*/

#include "pktapi.h"
#include "api_pkt2.h"
#include "pktapip.h"

#include <string.h>
#include <search.h>

#define ADDR_BUFFER_SIZE 64

static void _PktAddCtrlAddr(ADDRBUF *ctrl, NETADDR *addr)
{
  if (ctrl->num_addr % ADDR_BUFFER_SIZE == 0)
    ctrl->addr = realloc(ctrl->addr, sizeof(NETADDR) * ADDR_BUFFER_SIZE * ((dword)(ctrl->num_addr / ADDR_BUFFER_SIZE) + 1) );

  memcpy(&ctrl->addr[ctrl->num_addr], addr, sizeof(NETADDR));
  ctrl->num_addr ++;
}

static int _Optlink _PktSortFkt(const void *_a, const void *_b)
{
#define a ((NETADDR *) _a)
#define b ((NETADDR *) _b)

  if (a->zone > b->zone) return 1;
  if (a->zone < b->zone) return -1;
  if (a->net > b->net) return 1;
  if (a->net < b->net) return -1;
  if (a->node > b->node) return 1;
  if (a->node < b->node) return -1;
  if (a->point > b->point) return 1;
  if (a->point < b->point) return -1;
  return 0;

#undef a
#undef b
}

static void _PktSortCtrlBuf(ADDRBUF *ctrl)
{
  qsort(ctrl->addr, ctrl->num_addr, sizeof(NETADDR), _PktSortFkt);
}

static char * _PktCvtASCIIToCtrl(ADDRBUF *ctrl, char *buf)
{
  char *rc;
  int a, b;
  NETADDR addr;

  memset(&addr, 0, sizeof(NETADDR));

  rc = strchr(buf, '\r');
  if (!rc)
  {
     rc = buf;
     while (*rc) rc++;
  }
  if (*rc)
    rc ++;

  buf = strchr(buf, 32);
  while (buf && buf<rc)
  {
    while (*buf == 32) buf++;

    a = b = -1;
    sscanf(buf, "%d/%d", &a, &b);
    if (b == -1)
      addr.node = a;
    else
    {
      addr.node = b;
      addr.net  = a;
    }
    if (a != -1)
      _PktAddCtrlAddr(ctrl, &addr);

    buf = strchr(buf, 32);
  }

  return rc;
}


sword MAPIENTRY PktCreateCtrlBuf(char *sztext, PKTCTRLBUF *ctrlbuf)
{
  char *origin, *buf;

  if (!ctrlbuf) 
    return 1;

  origin = strrstr(sztext, "\r * Origin:");
  if (origin)
    origin ++;
  else
  {
    /* No Originline detected */
    return 1;
  }

  PktFreeCtrlBuf(ctrlbuf);

  /* No Additional Infos -> Empty ctrlbuf */

  origin = strchr(origin, '\r');
  if (origin)
    origin ++;
 
  while (origin && *origin)
  {
    buf = origin;
    if (strncmp(buf, "SEEN-BY:", 8) == 0)
    {
       buf = _PktCvtASCIIToCtrl(&ctrlbuf->seenby, buf);
       strocpy(origin, buf);
    }
    else if (strncmp(buf, "\001PATH:", 6) == 0)
    {
       buf = _PktCvtASCIIToCtrl(&ctrlbuf->path, buf);
       strocpy(origin, buf);
    }
    else 
    {
       origin = strchr(origin,'\r');
       if (origin)
         origin ++;
    }
  }

  _PktSortCtrlBuf(&ctrlbuf->seenby);

  return 0;
}
                                         
sword MAPIENTRY PktFreeCtrlBuf(PKTCTRLBUF *ctrl)
{
  if (ctrl)
  {
    if (ctrl->seenby.addr)
      free(ctrl->seenby.addr);
    if (ctrl->path.addr)
      free(ctrl->path.addr);

    memset(ctrl, 0, sizeof(PKTCTRLBUF));
    return 0;
  }
  return 1;
}

static void _PktCvtCtrlToText(char *buf, ADDRBUF *ctrl, char *tag, int maxlen)
{
  int lastnet = -1;
  char tmp[16];
  int len,i;

  if (ctrl->num_addr)
  {
    strcat(buf,tag);
    len = strlen(tag);

    for (i=0; i<ctrl->num_addr; i++)
    {
      if (lastnet != ctrl->addr[i].net)
      {
        lastnet = ctrl->addr[i].net;
        sprintf(tmp," %d/%d", lastnet, ctrl->addr[i].node);
      }
      else
      {
        sprintf(tmp," %d", ctrl->addr[i].node);
      }
    
      len += strlen(tmp);
      if (len > maxlen)
      {
        strcat(buf,"\r");
        strcat(buf,tag);

        sprintf(tmp," %d/%d", lastnet, ctrl->addr[i].node);
        len = strlen(tag) + strlen(tmp);
      }

      strcat(buf, tmp);
    }
    strcat(buf,"\r");
  }
}

char * MAPIENTRY PktConvertCtrlToText(PKTCTRLBUF *ctrl)
{
  char *buf;
  int i, len, lastnet = -1;
  char tmp[16];

  if (!ctrl)
  {
    pktapierr = PERR_BADH;
    return 0;
  }

  buf = malloc((ctrl->seenby.num_addr + ctrl->path.num_addr) * 16 + 64);

  if (!buf)
  {
    pktapierr = PERR_NOMEM;
    return 0;
  }

  *buf = 0;

  _PktCvtCtrlToText(buf, &ctrl->seenby, "SEEN-BY:", 80);

  _PktCvtCtrlToText(buf, &ctrl->path, "\001PATH:", 80);

  return buf;
}

sword MAPIENTRY PktCtrlAddSeenby(PKTCTRLBUF *ctrl, NETADDR *addr)
{
  if (bsearch(addr, 
              ctrl->seenby.addr, 
              ctrl->seenby.num_addr, 
              sizeof(NETADDR), 
              _PktSortFkt) == 0)
  {
    _PktAddCtrlAddr(&ctrl->seenby, addr);
    _PktSortCtrlBuf(&ctrl->seenby);
    return 0;
  }

  return 1;
}

sword MAPIENTRY PktCtrlAddPath(PKTCTRLBUF *ctrl, NETADDR *addr)
{
  _PktAddCtrlAddr(&ctrl->path, addr);
  return 0;
}

sword MAPIENTRY PktCtrlChkPath(PKTCTRLBUF *ctrl, NETADDR *addr)
{
  unsigned int s = ctrl->path.num_addr;

  return (lfind((char *)addr, 
                (char *)ctrl->path.addr, 
                &s, 
                sizeof(NETADDR), 
                _PktSortFkt)) ? 1 : 0;
}
