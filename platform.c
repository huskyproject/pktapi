/*
  PKTAPI Source, Version 1.00

  (c) & (p) 1999-2000 by Oliver 'Attila' Grimm

  Alle Rechte vorbehalten.
*/


#include "pktapi.h"
#include "pktdef.h"
#include "platform_pkt.h"

#include <io.h>
#include <string.h>

#ifndef __INTEL__

static void WordToI(word *val)
{
  byte dest[2];

  dest[0] = (byte) (*val & 0xff);
  dest[1] = (byte) ((*val >> 8) & 0xff);

  *val = *((word *)dest);
}

static void DwordToI(dword *val)
{
  byte dest[4];

  dest[0] = (byte) (*val & 0xff);
  dest[1] = (byte) ((*val >> 8) & 0xff);
  dest[2] = (byte) ((*val >> 16) & 0xff);
  dest[3] = (byte) ((*val >> 24) & 0xff);

  *val = *((dword *)dest);
}

static void WordFromI(word *val)
{
  word dest = (word)((byte *)val)[0] | ((word) ((byte *)val)[1]) << 8;
  *val = dest;
}

static void DwordFromI(dword *val)
{
  dword dest = (dword)((byte *)val)[0] | ((dword)((byte *)val)[1]) << 8 |
               ((dword)((byte *)val)[2])<<16 | ((dword)((byte *)val)[3]) << 24;
  *val = dest;
}

static void NETADDRFromI(NETADDR *addr)
{
  WordFromI(&addr->zone);
  WordFromI(&addr->net);
  WordFromI(&addr->node);
  WordFromI(&addr->point);
}

static void NETADDRToI(NETADDR *addr)
{
  WordToI(&addr->zone);
  WordToI(&addr->net);
  WordToI(&addr->node);
  WordToI(&addr->point);
}

void PKT2MSGHEADERFromI(PKT2MSGHEADER *hdr)
{
  WordFromI(&hdr->signatur);
  WordFromI(&hdr->orig_node);
  WordFromI(&hdr->dest_node);
  WordFromI(&hdr->orig_net);
  WordFromI(&hdr->dest_net);
  WordFromI(&hdr->attrib);
  WordFromI(&hdr->cost);
}

void PKT2MSGHEADERToI(PKT2MSGHEADER *hdr)
{
  WordToI(&hdr->signatur);
  WordToI(&hdr->orig_node);
  WordToI(&hdr->dest_node);
  WordToI(&hdr->orig_net);
  WordToI(&hdr->dest_net);
  WordToI(&hdr->attrib);
  WordToI(&hdr->cost);
}

void PKT3HEADERFromI(PKT3HEADER *hdr)
{
  NETADDRFromI(&hdr->orig);
  NETADDRFromI(&hdr->dest);
  DwordFromI(&hdr->datetime);
  WordFromI(&hdr->prod_code);
  WordFromI(&hdr->prod_ver);
  WordFromI(&hdr->capability);
}

void PKT3HEADERToI(PKT3HEADER *hdr)
{
  NETADDRToI(&hdr->orig);
  NETADDRToI(&hdr->dest);
  WordToI(&hdr->pkt_subver);
  WordToI(&hdr->pkt_ver);
  DwordToI(&hdr->datetime);
  WordToI(&hdr->prod_code);
  WordToI(&hdr->prod_ver);
  WordToI(&hdr->capability);
}

void PKTHEADERFromI(PKTHEADER *hdr)
{
  WordFromI(&hdr->baud);
  WordFromI(&hdr->pkt_ver);
}

void PKT2HEADERFromI(PKT2HEADER *hdr)
{
  WordFromI(&hdr->orig_node);
  WordFromI(&hdr->dest_node);
  WordFromI(&hdr->year);
  WordFromI(&hdr->month);
  WordFromI(&hdr->day);
  WordFromI(&hdr->hour);
  WordFromI(&hdr->min);
  WordFromI(&hdr->sec);
  WordFromI(&hdr->orig_net);
  WordFromI(&hdr->dest_net);
  WordFromI(&hdr->prod_code);
  WordFromI(&hdr->orig_zone);
  WordFromI(&hdr->dest_zone);
}

void PKT2PHEADERFromI(PKT2PHEADER *hdr)
{
  WordFromI(&hdr->aux_net);
  WordFromI(&hdr->cwcopy);
  WordFromI(&hdr->prg_code_2);
  WordFromI(&hdr->cap_word);
  WordFromI(&hdr->orig_zone_2);
  WordFromI(&hdr->dest_zone_2);
  WordFromI(&hdr->orig_point);
  WordFromI(&hdr->dest_point);
}

void PKT2PHEADERToI(PKT2PHEADER *hdr)
{
  WordToI(&hdr->orig_node);
  WordToI(&hdr->dest_node);
  WordToI(&hdr->year);
  WordToI(&hdr->month);
  WordToI(&hdr->day);
  WordToI(&hdr->hour);
  WordToI(&hdr->min);
  WordToI(&hdr->sec);
  WordToI(&hdr->baud);
  WordToI(&hdr->pkt_ver);
  WordToI(&hdr->orig_net);
  WordToI(&hdr->dest_net);
  WordToI(&hdr->prod_code);
  WordToI(&hdr->orig_zone);
  WordToI(&hdr->dest_zone);
  WordToI(&hdr->aux_net);
  WordToI(&hdr->cwcopy);
  WordToI(&hdr->prg_code_2);
  WordToI(&hdr->cap_word);
  WordToI(&hdr->orig_zone_2);
  WordToI(&hdr->dest_zone_2);
  WordToI(&hdr->orig_point);
  WordToI(&hdr->dest_point);
}

#else

#define PKT2MSGHEADERFromI(d)
#define PKT2MSGHEADERToI(d)

#define PKTHEADERFromI(d)
#define PKT2HEADERFromI(d)
#define PKT2PHEADERFromI(d)
#define PKT2PHEADERToI(d)

#define PKT3HEADERFromI(d)
#define PKT3HEADERToI(d)

#endif

int readPKT2MSGHEADER(int fd,  PKT2MSGHEADER *hdr)
{
  int rc = read(fd, hdr, sizeof(PKT2MSGHEADER));
  PKT2MSGHEADERFromI(hdr);
  return rc;
}

int writePKT2MSGHEADER(int fd, PKT2MSGHEADER *_hdr)
{
#ifndef __INTEL__
  PKT2MSGHEADER hdrcp;
  memcpy(&hdrcp, _hdr, sizeof(PKT2MSGHEADER));
  #define hdr (&hdrcp)
#else
  #define hdr _hdr
#endif

  PKT2MSGHEADERToI(hdr);
  return write(fd, hdr, sizeof(PKT2MSGHEADER));

#undef hdr
}


/* Read PKT 2/2+/2.2/3 Header */

int readPKTHEADER(int fd, PKTHEADER *hdr)
{
  if (read(fd, hdr, sizeof(PKTHEADER)) != sizeof(PKTHEADER))
    return PKTTYPE_UNKNOWN;

  PKTHEADERFromI(hdr);

  if (hdr->pkt_ver == 3)
  {
    PKT3HEADERFromI((PKT3HEADER *) hdr);
    return PKTTYPE_3;
  }

  if (hdr->pkt_ver == 2)
  {
#define hdr2 ((PKT2PHEADER *) hdr)

    PKT2HEADERFromI((PKT2HEADER *) hdr);
    if (hdr->baud == 2)
      return PKTTYPE_2_2;

    if ( ((byte *)&hdr2->cap_word)[0] != ((byte *)&hdr2->cwcopy)[1] ||
         ((byte *)&hdr2->cap_word)[1] != ((byte *)&hdr2->cwcopy)[0])
    {
      PKT2PHEADERFromI(hdr2); 
      
      return PKTTYPE_2_PLUS;
    }
    return PKTTYPE_2;

#undef hdr2
  }

  return PKTTYPE_UNKNOWN;
}

int writePKT2PHEADER(int fd, PKT2PHEADER *_hdr)
{
#ifndef __INTEL__
  PKT2PHEADER hdrcp;
  memcpy(&hdrcp, _hdr, sizeof(PKT2PHEADER));
  #define hdr (&hdrcp)
#else
  #define hdr _hdr
#endif

  PKT2PHEADERToI(hdr);
  return write(fd, hdr, sizeof(PKT2PHEADER));

#undef hdr
}
