/*
  PKTAPI Source, Version 1.00

  (c) & (p) 1999-2000 by Oliver 'Attila' Grimm

  Alle Rechte vorbehalten.
*/


#ifndef _pktdef_h
#define _pktdef_h

typedef struct TYP_X_HEADER
{
  byte    filler1[16];
  word    baud;
  word    pkt_ver;
  byte    filler2[38];
} PKTHEADER;

typedef struct TYP_2_HEADER
{
  word orig_node;
  word dest_node;
  word year;
  word month;
  word day;
  word hour;
  word min;
  word sec;
  word baud;
  word pkt_ver;
  word orig_net;
  word dest_net;
  word prod_code;   
  char passwd[8];
  word orig_zone;
  word dest_zone;

  byte filler[20];
} PKT2HEADER;

typedef struct TYP_2_2_HEADER
{
  word orig_node;
  word dest_node;
  word orig_point;
  word dest_point;
  byte filler[8];
  word pkt_subver;  
  word pkt_ver;
  word orig_net;
  word dest_net;
  word prod_code;   
  char passwd[8];
  word orig_zone;
  word dest_zone;
  byte orig_domain[8];
  byte dest_domain[8];
  byte prg_data[4];
} PKT22HEADER;

typedef struct TYP_2P_HEADER
{
  word orig_node;
  word dest_node;
  word year;
  word month;
  word day;
  word hour;
  word min;
  word sec;
  word baud;        
  word pkt_ver;
  word orig_net;
  word dest_net;
  word prod_code;  
  char passwd[8];
  word orig_zone;
  word dest_zone;
  word aux_net;
  word cwcopy;
  word prg_code_2;  
  word cap_word;
  word orig_zone_2;
  word dest_zone_2;
  word orig_point;
  word dest_point;
  byte prg_data[4];
} PKT2PHEADER;


typedef struct TYP_2_MSG_HEADER
{
  word signatur;  
  word orig_node;
  word dest_node;
  word orig_net;
  word dest_net;
  word attrib;
  word cost;
  char datetime[20];
} PKT2MSGHEADER;

typedef struct TYP_3_HEADER
{
  NETADDR orig;
  NETADDR dest;
  word    pkt_subver;
  word    pkt_ver;
  dword   datetime;
  word    prod_code;
  word    prod_ver;
  byte    organisation[16];
  word    capability;
  byte    passwd[8];
  byte    filler[4];
} PKT3HEADER;

typedef struct TYP_3_MSG_HEADER
{
  word  size;
  word  flags;
  dword datetime;
  dword msgid;
  dword replyid;
  dword msglen;
  NETADDR orig;
  NETADDR dest;
  byte charset;
  byte type;
} PKT3MSGHEADER;

#endif