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

static HPKT hpOpen = 0;

static struct _papifuncs pkt2_funcs =
{
  Pkt2ClosePkt,
  Pkt2ReadMsg,
  Pkt2WriteMsg,
  Pkt2ReadMsgComplete 
};

static HPKT NewHpkt(word type, word mode)
{
  HPKT hp;

  if ((hp=calloc(sizeof(*hp),1))==NULL)
    return NULL;

  hp->id = PKTAPI_ID;
  hp->len = sizeof(struct _pktapi);
  hp->type = type;
  hp->mode = mode;

  hp->prod_code = 0xFE;

  return hp;
}

static sword _Pkt2OpenFile(HPKT hp, byte far *name, word mode)
{
  /* All PKT-Files opened in DENY_READ and DENY_WRITE-Modes */

  if ((P2d->pfd=sopen(name, 
                      mode | O_RDWR | O_BINARY, 
                      SH_DENYRW,
                      S_IREAD | S_IWRITE)) == -1)
  {
    return 0;
  }

  return 1;
}

static void _Pkt2GetStoneAge(HPKT hp, PKT2HEADER *pkth)
{
  hp->orig.zone = pkth->orig_zone;
  hp->orig.net  = pkth->orig_net;
  hp->orig.node = pkth->orig_node;

  hp->dest.zone = pkth->dest_zone;
  hp->dest.net  = pkth->dest_net;
  hp->dest.node = pkth->dest_node;

  memcpy(hp->password, pkth->passwd, 8);

  hp->date_written.date.yr = pkth->year - 1900;
  hp->date_written.date.mo = pkth->month+1;
  hp->date_written.date.da = pkth->day;
  hp->date_written.time.hh = pkth->hour;
  hp->date_written.time.mm = pkth->min;
  hp->date_written.time.ss = pkth->sec;

  hp->prod_code = pkth->prod_code;

  hp->type = PKTTYPE_2;
}

static void _Pkt2Get2Plus(HPKT hp, PKT2PHEADER *pkth)
{
  _Pkt2GetStoneAge(hp, (PKT2HEADER *)pkth);

  hp->orig.point= pkth->orig_point;

  hp->dest.point= pkth->dest_point;

  hp->capability= pkth->cap_word;

  hp->type = PKTTYPE_2_PLUS;
}

static void _Pkt2Get2_2(HPKT hp, PKT22HEADER *pkth)
{
  _Pkt2GetStoneAge(hp, (PKT2HEADER *)pkth);

  hp->orig.point= pkth->orig_point;

  hp->dest.point= pkth->dest_point;

  memset(&hp->date_written, 0, sizeof(struct _stamp));

  hp->type = PKTTYPE_2_2;
}

static sword _Pkt2OpenExisting(HPKT hp, byte far *name)
{
  PKT2PHEADER pkth;
  word endmark;

  memset(&pkth, 0, sizeof(pkth));

  /* Try to open an EXISTING File */

  if (!_Pkt2OpenFile(hp, name, 0))
    return 0;

  if (!(readPKTHEADER(P2d->pfd,(PKTHEADER *) &pkth) & PKTTYPE_2))
  {
    close(P2d->pfd);
    P2d->pfd = 0;
    return 0;
  }

  if (pkth.pkt_ver != 2)
  {
    close(P2d->pfd);
    P2d->pfd = 0;
    return 0;
  }

  lseek(P2d->pfd, -sizeof(endmark), SEEK_END);

  if (read(P2d->pfd, &endmark, sizeof(endmark)) != sizeof(endmark))
  {
    close(P2d->pfd);
    P2d->pfd = 0;
    return 0;
  }

  if (endmark != 0)
  {
    close(P2d->pfd);
    P2d->pfd = 0;
    return 0;
  }

  if (hp->mode == PKTMODE_WRITE)
  {

     _chsize(P2d->pfd, _filelength(P2d->pfd)-sizeof(endmark));

     lseek(P2d->pfd, 0, SEEK_END);

  }
  else
    lseek(P2d->pfd, sizeof(pkth), SEEK_SET);

  if (pkth.baud == 2)
  {
    _Pkt2Get2_2(hp, (PKT22HEADER *) &pkth);
    return 1;
  }

  if ( ((byte *)&pkth.cap_word)[0] != ((byte *)&pkth.cwcopy)[1] ||
       ((byte *)&pkth.cap_word)[1] != ((byte *)&pkth.cwcopy)[0])
  {
    _Pkt2GetStoneAge(hp, (PKT2HEADER *) &pkth);   
    return 1;
  }

  _Pkt2Get2Plus(hp, (PKT2PHEADER *) &pkth);

  return 1;
}

static sword _Pkt2OpenCreate(HPKT hp, byte far *name)
{
  PKT2PHEADER pkth;
  time_t timeval;
  struct tm *tim;

  /* Try to create a NEW file ! Error, when file exists */

  if (!_Pkt2OpenFile(hp, name, O_CREAT))
    return 0;

  timeval = time(0);
  tim = localtime(&timeval);

  memset(&pkth, 0, sizeof(pkth));

  pkth.pkt_ver = 2;

  pkth.year = tim->tm_year+1900;
  pkth.month = tim->tm_mon-1;
  pkth.day = tim->tm_mday;
  pkth.hour = tim->tm_hour;
  pkth.min = tim->tm_min;
  pkth.sec = tim->tm_sec;

  pkth.prod_code = 0xFE;

  writePKT2PHEADER(P2d->pfd, &pkth);

  return 1;
}

HPKT PKTAPI Pkt2OpenPkt(byte far *name, word mode, word type)
{
  HPKT hp;
  sword fopened = 0;

  if ((hp=NewHpkt(type, mode)) == NULL)
    return NULL;

  if ((hp->apidata=malloc(sizeof(PKT2DATA))) == NULL)
  {
    free(hp);
    return NULL;
  }

  memset(hp->apidata, 0, sizeof(PKT2DATA));

  /* Allocate memory to hold the function pointers */

  if ((hp->api=(struct _papifuncs *)malloc(sizeof(struct _papifuncs)))==NULL)
  {
    free(hp->apidata);
    free(hp);
    return NULL;
  }

  *hp->api=pkt2_funcs;

  if (mode == PKTMODE_READ || mode == PKTMODE_WRITE)
    fopened = _Pkt2OpenExisting(hp, name);

  if (!fopened && mode == PKTMODE_WRITE)
    fopened = _Pkt2OpenCreate(hp, name);

  if (!fopened)
  {
    free(hp->api);
    free(hp->apidata);
    free(hp);
    return NULL;
  }
 
  /* Add to linked list of open packets */ 
  P2d->next = hpOpen;
  hpOpen = hp;
  
  return hp;
}

static sword _Pkt2ClosePkt(HPKT hp)
{
  word endmark = 0l;
  PKT2PHEADER pkth;

  if (hp->mode == PKTMODE_WRITE)
  {
    /* If in-message, when closing area, write end-of-mail tag first */
    if (P2d->in_msg)
    {
      byte endmark = 0;
      write(P2d->pfd, &endmark, 1);
      P2d->in_msg = 0;
    }

    memset(&pkth, 0, sizeof(pkth));

    /* _ever_ write 2+ Header */
    pkth.orig_node = hp->orig.node;
    pkth.dest_node = hp->dest.node;
    pkth.year      = hp->date_written.date.yr+1900;
    pkth.month     = hp->date_written.date.mo-1;
    pkth.day       = hp->date_written.date.da;
    pkth.hour      = hp->date_written.time.hh;
    pkth.min       = hp->date_written.time.mm;
    pkth.sec       = hp->date_written.time.ss;
    pkth.pkt_ver   = 2;
    pkth.orig_net  = hp->orig.net;
    pkth.dest_net  = hp->dest.net;
    pkth.prod_code = hp->prod_code;
    memcpy(pkth.passwd, hp->password, 8);
    pkth.orig_zone = hp->orig.zone;
    pkth.dest_zone = hp->dest.zone;

    /* Neue/Modifizierte Packete sind _immer_ Typ 2+ */
    pkth.cap_word  = 0x2;
    pkth.cwcopy = 0x200;

    pkth.orig_point = hp->orig.point;
    pkth.dest_point = hp->dest.point;

    lseek(P2d->pfd, 0, SEEK_SET);
    writePKT2PHEADER(P2d->pfd, &pkth);

    /* write EOP-Mark */

    lseek(P2d->pfd, 0, SEEK_END);
    write(P2d->pfd, &endmark, sizeof(endmark));    
  }

  close(P2d->pfd);

  return 0;
}

sword PKTAPI Pkt2ClosePkt(HPKT hp)
{
  HPKT p;

  if (PktInvalidPh(hp))
    return 1;

  _Pkt2ClosePkt(hp);

  /* Remove from openarealist */
  if (hpOpen == hp)
    hpOpen = P2d->next;
  else
  {   
    p = hpOpen;
    while (p)
    {
      if (((PKT2DATA *)p->apidata)->next == hp)
      {
        ((PKT2DATA *)p->apidata)->next = P2d->next;
        p = 0;
      }
      else
        p = ((PKT2DATA *)p->apidata)->next;
    }
  }

  free(hp->api);
  free(hp->apidata);
  free(hp);

  return 0;
}

void PKTAPI _Pkt2ClosePackets()
{
  while (hpOpen)
  {
    printf("PKTAPI is closing an open PKT...\n");
    if (Pkt2ClosePkt(hpOpen)) 
      return;
  }
}

