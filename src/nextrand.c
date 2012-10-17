/*
Simple tool to generate the next [num] subsequent random numbers using Java
Random.nextInt(), given any two sequential outputs of this method.

Copyright (C) 2012 Virtual Security Research, LLC
Author: Dan J. Rosenberg
Updates by: Timothy D. Morgan

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License, version 3,
 as published by the Free Software Foundation.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>

#define MULTIPLIER 25214903917L
#define ADDEND 11L
#define MASK ((1L << 48) - 1) 

unsigned long long seed;

int nextInt()
{
  seed = (seed * MULTIPLIER + ADDEND) & MASK;
  return (int) (seed >> 16);
}


int main(int argc, char **argv)
{
  int i, num;
  unsigned long long r1, r2;
  
  if (argc != 4) 
  {
    fprintf(stderr, "[-] Usage: %s rand1 rand2 num\n", argv[0]);
    fprintf(stderr, 
            "[-] Note that rand1 and rand2 must be signed integers returned in sequence\n"
            "    from a single Java Random instance.  Values provided must be generated\n"
            "    by Random.nextInt() which was called with no arguments.\n");
    return 1;
  }
  
  r1 = atoi(argv[1]);
  r2 = atoi(argv[2]);
  num = atoi(argv[3]);
  
  for (i = 0; i < 65536; i++) 
  {
    seed = (r1 << 16) + i;
    if ((unsigned int)(((seed * MULTIPLIER + ADDEND) & MASK) >> 16) == (unsigned int)r2) 
      break;
    
    seed = 0;
  }
  
  if (!seed) {
    fprintf(stderr, "[-] Seed not found.\n");
    return 1;
  }
  
  fprintf(stderr, "[+] Seed %.12llX found based on provided values: ", seed);
  fprintf(stderr, "%d %d\n", (int)r1, nextInt());
  fprintf(stderr, "[+] Next %d values:\n", num);
  
  for (i = 0; i < num; i++) 
    printf("%d\n", nextInt());
  
  return 0;
}
