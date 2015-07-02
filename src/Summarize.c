/*
 ============================================================================
 Name        : Summarize.c
 Author      : Clark Dong
 Version     : 1.0.0.0
 Copyright   : Sodero Inc.
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>

#include "Debug.h"
#include "Context.h"

int main(int argc, char * argv[]) {
	puts("Summarize Engine");

	setenv("MALLOC_TRACE", "output", 1);

	debug(argc, argv);

	return EXIT_SUCCESS;
}
