/*
Simple tool to generate the next [num] subsequent random numbers using Java
Random.nextInt(), given any two sequential outputs of this method.

Copyright (C) 2012 Virtual Security Research, LLC
Author: Dan J. Rosenberg

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


	if (argc != 4) {
		printf("[-] Usage: %s rand1 rand2 num\n", argv[0]);
		return 1;
	}

	r1 = atoi(argv[1]);
	r2 = atoi(argv[2]);
	num = atoi(argv[3]);

	for (i = 0; i < 65536; i++) {
		seed = (r1 << 16) + i;
		if ((unsigned int)(((seed * MULTIPLIER + ADDEND) & MASK) >> 16) == (unsigned int)r2) {
			break;
		}
		seed = 0;
	}

	if (!seed) {
		printf("[-] Seed not found.\n");
		return 1;
	}

	/* Uncomment to print the first two values, which were already provided */
//	printf("%d\n", (int)r1);
//	printf("%d\n", nextInt());

	for (i = 0; i < num; i++) {
		printf("%d\n", nextInt());
	}

	return 0;

}
