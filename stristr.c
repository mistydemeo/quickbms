// from http://c.snippets.org/code/stristr.c without the usage of NUL and NULL

#ifndef STRISTR
#define STRISTR

#include <ctype.h>

//static
char *stristr(const char *String, const char *Pattern)
{
      char *pptr, *sptr, *start;

      for (start = (char *)String; *start; start++)
      {
            /* find start of pattern in string */
            for ( ; (*start && (toupper(*start) != toupper(*Pattern))); start++)
                  ;
            if (!*start)
                  return 0;

            pptr = (char *)Pattern;
            sptr = (char *)start;

            while (toupper(*sptr) == toupper(*pptr))
            {
                  sptr++;
                  pptr++;

                  /* if end of pattern then pattern was found */

                  if (!*pptr)
                        return (start);
            }
      }
      return 0;
}

#endif
