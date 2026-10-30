#include <globalplatform/types.h>
#include <globalplatform/error.h>
#include <globalplatform/errorcodes.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

OPGP_ERROR_STATUS OPGP_initialize_crypto(void);
static unsigned int load_calls;

/* Replaces only provider discovery in a separately compiled init.c test object. */
OSSL_PROVIDER *gp_test_provider_load(OSSL_LIB_CTX *library_context, const char *name) {
    (void)library_context; (void)name;
    load_calls++;
    return NULL;
}

/* Avoid linking the rest of the SDK solely to format a synthetic failure. */
OPGP_STRING OPGP_stringify_error(DWORD code) {
    (void)code;
    return "Synthetic provider failure";
}

int main(void) {
    OPGP_ERROR_STATUS first = OPGP_initialize_crypto();
    OPGP_ERROR_STATUS second = OPGP_initialize_crypto();
    if (!OPGP_ERROR_CHECK(first) || !OPGP_ERROR_CHECK(second) ||
        first.errorCode != OPGP_ERROR_CRYPT || second.errorCode != OPGP_ERROR_CRYPT || load_calls != 2) return 1;
    puts("PASS provider failure returns an error, remains failed on repeat, process continues");
    return 0;
}
