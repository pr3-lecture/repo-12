#include <stdio.h>
#include <string.h>
#include "crypto.h"

#define XOR 1
#define ENCRYPT 0
#define DECRYPT 1


int invalidChar(char* valid, const char* values, int errorNr) {
	for (int i = 0; i < strlen(values); i++) {
		if (!strchr(valid, values[i]) && values[i] != '\n'&& values[i] != '\n'&& values[i] != '\r') {
			return errorNr;
		}
	}
	return 0;
}

int cryptMessage(KEY key, const char* input, char* output, int mode) {
	char* outputChars;
	char* inputChars;
	int inputCharsError, inputShift = 0, outputShift = 0;
	if (mode == ENCRYPT) {
		inputChars = MESSAGE_CHARACTERS;
		outputChars = CYPHER_CHARACTERS;
		inputCharsError = E_MESSAGE_ILLEGAL_CHAR;
		inputShift = 1;
	}
	else {
		inputChars = CYPHER_CHARACTERS;
		outputChars = MESSAGE_CHARACTERS;
		inputCharsError = E_CYPHER_ILLEGAL_CHAR;
		outputShift = -1;
	}

	/* Check if key type matches */
	/*if (key.type != XOR) {
		return -1;
	}*/

	/* Check key for valid length */
	if (strlen(key.chars) <= 0) {
		return E_KEY_TOO_SHORT;
	}

	/* Check key for valid characters */
	if (invalidChar(KEY_CHARACTERS, key.chars, E_KEY_ILLEGAL_CHAR)) {
		return E_KEY_ILLEGAL_CHAR;
	}

	/* Check input for valid characters */
	if (invalidChar(inputChars, input, inputCharsError)) {
		return inputCharsError;
	}

	/* en-/decrypt with xor */
	for (int i = 0; i < strlen(input); i++) {
		if (input[i] == '\n' || input[i] == '\r') {
			continue;
		}

		char* messageChars = inputChars;
		int inputPos = strchr(messageChars, input[i]) - messageChars + inputShift;

		char* keyChars = KEY_CHARACTERS;
		char keyChar = key.chars[i % strlen(key.chars)];
		int keyPos = strchr(keyChars, keyChar) - keyChars + 1;

		output[i] = outputChars[((inputPos ^ keyPos) + outputShift) % strlen(outputChars)];

		/*printf("Val: Input: %c, Key: %c, Output: %c\n", input[i], keyChar, output[i]);
		printf("Pos: Input: %d, Key: %d, Output: %d\n", inputPos, keyPos, (inputPos ^ keyPos) + outputShift);*/
	}

	return 0;
}

int encrypt(KEY key, const char* input, char* output) {
	return cryptMessage(key, input, output, ENCRYPT);
}

int decrypt(KEY key, const char* cypherText, char* output) {
	return cryptMessage(key, cypherText, output, DECRYPT);
}
