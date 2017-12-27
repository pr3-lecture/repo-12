#include <stdio.h>
#include <string.h>
#include "crypto.h"

#define OK 0
#define LINE_LENGTH 50
#define XOR 1

void handleResult(int code, char* result) {
	switch (code) {
	case E_KEY_TOO_SHORT: fprintf(stderr, "Error: Key too short.\n"); break;
	case E_KEY_ILLEGAL_CHAR: fprintf(stderr, "Error: Key contains illegal caracter.\n"); break;
	case E_MESSAGE_ILLEGAL_CHAR: fprintf(stderr, "Error: Message contains illegal character.\n"); break;
	case E_CYPHER_ILLEGAL_CHAR: fprintf(stderr, "Error: Cypher contains illegal character.\n"); break;
	case OK: printf("%s", result); break;
	default: fprintf(stderr, "Application error.\n"); break;
	}
}

int main(int argc, char** argv) {
	KEY key;
	key.type = XOR;
	key.chars = argv[1];

	char* name = argv[0];
	char* fileName = argv[2];

	int(*func)(KEY, const char*, char*);
	if (!strcmp(name, "./encrypt")) {
		func = &encrypt;
	}
	else if (!strcmp(name, "./decrypt")) {
		func = &decrypt;
	}
	else {
		fprintf(stderr, "Invalid file name.\n");
		return 1;
	}

	if (key.chars == NULL) {
		printf("Usage: KEY [file name]\n");
		return 1;
	}

	FILE* file;
	if (fileName == NULL) {
		/* Use standard input */
		printf("Input text: ");
		file = stdin;
	}
	else {
		/* Use file input */
		file = fopen(fileName, "r");
	}


	if (!file) {
		fprintf(stderr, "ERROR: File does not exist.\n");
		return 1;
	}

	char line[50];
	int code = OK;
	while (fgets(line, LINE_LENGTH, file) && code == OK) {
		/* Print crypted line */
		char* result = strdup(line);
		code = (*func)(key, line, result);
		handleResult(code, result);

		if (file == stdin && strchr(line, '\n')) break;
	}

	printf("\n");

	if (file != stdin) {
		fclose(file);
	}

	return 0;
}