/*

Ein ganz einfaches Beispiel-Programm was ein File TEST.PKT einliesst, die 
Adresse 200/200 in Path und Seen-By an jeder Mail einfÅgt und eine neues 
Pkt TEST2.PKT erzeugt.

  (c) & (p) 1999-2000 by Oliver 'Attila' Grimm

  Alle Rechte vorbehalten.

*/


#include "pktapi.h"
#include <string.h>

void main()
{
  struct _minf mi;
  HPKT hp, hp2;
  XMSG xmsg;
  char *buf = 0;
  sword rc;
  PKTCTRLBUF ctrlbuf;
  int i; 
  char *buf2 = 0;

  memset(&ctrlbuf, 0, sizeof(PKTCTRLBUF));

  printf("Scheisse !\n");
  memset(&mi,0, sizeof(mi));
  PktOpenApi(&mi);

  hp = PktOpenPkt("test.pkt", PKTMODE_READ, PKTTYPE_2);
  hp2 = PktOpenPkt("test2.pkt", PKTMODE_WRITE, PKTTYPE_2);
 
  PktCopyPktHdr(hp2, hp);

  if (hp)
  {
    printf("Pkt from: %d:%d/%d.%d\n", hp->orig.zone, hp->orig.net, hp->orig.node, hp->orig.point);
    printf("Pkt To  : %d:%d/%d.%d\n", hp->dest.zone, hp->dest.net, hp->dest.node, hp->dest.point);

    while ((rc=PktReadMsgComplete(hp, &xmsg, &buf)) != -1)
    {
       NETADDR addr = {0, 200, 200, 0};

       printf("Msg From: %s (%d)\n", xmsg.__ftsc_date, rc);
       printf("%d %d\n", xmsg.orig.net, xmsg.orig.node);

       PktCreateCtrlBuf(buf, &ctrlbuf);

       PktCtrlAddSeenby(&ctrlbuf, &addr);
       PktCtrlAddPath(&ctrlbuf, &addr);

       PktWriteMsg(hp2, &xmsg, 1, buf);

       buf2 = PktConvertCtrlToText(&ctrlbuf);
       if (buf2)
       {
         printf("%s\n",buf2);
         PktWriteMsg(hp2, 0, 0, buf2);
         PktFreeText(buf2);
       }

       PktFreeCtrlBuf(&ctrlbuf);
       PktFreeText(buf);
    }

    PktClosePkt(hp); 
  }
  
   PktClosePkt(hp2); 

   PktCloseApi();

}