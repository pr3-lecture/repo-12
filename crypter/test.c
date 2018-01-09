#include <stdio.h>
#include <stdlib.h>
#include "string.h"
#include "crypto.h"

#define mu_assert(message, test) do { if (!(test)) return message; } while (0)
#define mu_run_test(test) do { char *message = test(); tests_run++; if (message) return message; } while (0)

int tests_run = 0;

static char* encryptCorrect() {
	KEY key;
	key.type = 1;
	key.chars = "TPERULES";

	char* result = strdup("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	int code = encrypt(key, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", result);
	mu_assert("Encryption with correct parameters exits with error.", code == 0);
	mu_assert("Encryption with correct parameters returns wrong result.", !strcmp(result, "URFVPJB[]ZN^XBJCEBVF@ZRKMJ"));
	free(result);

	return 0;
}

static char* encryptKeyTooShort() {
	KEY key;
	key.type = 1;
	key.chars = "";

	char* result = strdup("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	int code = encrypt(key, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", result);
	mu_assert("Encryption with empty key returns with wrong error code.", code == E_KEY_TOO_SHORT);
	mu_assert("Encryption with empty key returns wrong result.", !strcmp(result, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
	free(result);

	return 0;
}

static char* encryptIllegalKeyChar() {
	KEY key;
	key.type = 1;
	key.chars = "TPERULES3";

	char* result = strdup("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	int code = encrypt(key, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", result);
	mu_assert("Encryption with illegal key returns with wrong error code.", code == E_KEY_ILLEGAL_CHAR);
	mu_assert("Encryption with illegal key returns wrong result.", !strcmp(result, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
	free(result);

	return 0;
}

static char* encryptIllegalMessageChar() {
	KEY key;
	key.type = 1;
	key.chars = "TPERULES";

	char* result = strdup("ABCDEFGHIJKLMNOPQ3RSTUVWXYZ");
	int code = encrypt(key, "ABCDEFGHIJKLMNOPQ3RSTUVWXYZ", result);
	mu_assert("Encryption with illegal message returns with wrong error code.", code == E_MESSAGE_ILLEGAL_CHAR);
	mu_assert("Encryption with illegal message returns wrong result.", !strcmp(result, "ABCDEFGHIJKLMNOPQ3RSTUVWXYZ"));
	free(result);

	return 0;
}

static char* decryptCorrect() {
	KEY key;
	key.type = 1;
	key.chars = "TPERULES";

	char* result = strdup("URFVPJB[]ZN^XBJCEBVF@ZRKMJ");
	int code = decrypt(key, "URFVPJB[]ZN^XBJCEBVF@ZRKMJ", result);
	mu_assert("Decryption with correct parameters exits with error.", code == 0);
	mu_assert("Decryption with correct parameters returns wrong result.", !strcmp(result, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
	free(result);

	return 0;
}

static char* decryptKeyTooShort() {
	KEY key;
	key.type = 1;
	key.chars = "";

	char* result = strdup("URFVPJB[]ZN^XBJCEBVF@ZRKMJ");
	int code = decrypt(key, "URFVPJB[]ZN^XBJCEBVF@ZRKMJ", result);
	mu_assert("Decryption with empty key returns with wrong error code.", code == E_KEY_TOO_SHORT);
	mu_assert("Decryption with empty key returns wrong result.", !strcmp(result, "URFVPJB[]ZN^XBJCEBVF@ZRKMJ"));
	free(result);

	return 0;
}

static char* decryptIllegalKeyChar() {
	KEY key;
	key.type = 1;
	key.chars = "TPERULES3";

	char* result = strdup("URFVPJB[]ZN^XBJCEBVF@ZRKMJ");
	int code = decrypt(key, "URFVPJB[]ZN^XBJCEBVF@ZRKMJ", result);
	mu_assert("Decryption with illegal key returns with wrong error code.", code == E_KEY_ILLEGAL_CHAR);
	mu_assert("Decryption with illegal key returns wrong result.", !strcmp(result, "URFVPJB[]ZN^XBJCEBVF@ZRKMJ"));
	free(result);

	return 0;
}

static char* decryptIllegalCypherChar() {
	KEY key;
	key.type = 1;
	key.chars = "TPERULES";

	char* result = strdup("3URFVPJB[]ZN^XBJCEBVF@ZRKMJ");
	int code = decrypt(key, "3URFVPJB[]ZN^XBJCEBVF@ZRKMJ", result);
	mu_assert("Decryption with illegal cypher returns with wrong error code.", code == E_CYPHER_ILLEGAL_CHAR);
	mu_assert("Decryption with illegal cypher returns wrong result.", !strcmp(result, "3URFVPJB[]ZN^XBJCEBVF@ZRKMJ"));
	free(result);

	return 0;
}

static char* allTests() {
	mu_run_test(encryptCorrect);
	mu_run_test(encryptKeyTooShort);
	mu_run_test(encryptIllegalKeyChar);
	mu_run_test(encryptIllegalMessageChar);

	mu_run_test(decryptCorrect);
	mu_run_test(decryptKeyTooShort);
	mu_run_test(decryptIllegalKeyChar);
	mu_run_test(decryptIllegalCypherChar);

	return 0;
}

int main(int argc, char** argv) {
	char *result = allTests();

	if (result != 0) printf("%s\n", result);
	else             printf("ALL TESTS PASSED\n");

	printf("Tests run: %d\n", tests_run);

	return result != 0;
}