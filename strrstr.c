/*
  PKTAPI Source, Version 1.00

  (c) & (p) 1999-2000 by Oliver 'Attila' Grimm

  Alle Rechte vorbehalten.
*/


#include <string.h>

char * strrstr(char *str1, char *str2)
{
  char *p, *rc=0;

  p = str1;

  do
  {
    p = strstr(p, str2);
    if (p)
    {
      rc = p;
      p++;
    }
  }
  while (p);
  
  return rc;
}

char * strocpy(char *d, char *s)
{
  memmove(d, s, strlen(s)+1);
  return s;
}

