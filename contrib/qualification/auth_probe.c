/* Synthetic-key, host-only SDK qualification. Never use production credentials. */
#include <stdio.h>
#include <openssl/provider.h>
#include <stdlib.h>
#include <string.h>
#include "globalplatform/globalplatform.h"

static OPGP_ERROR_STATUS exchange(OPGP_CARD_CONTEXT context, OPGP_CARD_INFO card,
        PBYTE command, DWORD length, PBYTE response, PDWORD capacity) {
    OPGP_ERROR_STATUS status = {0};
    char line[8192];
    size_t n;
    (void)context; (void)card;
    fputs("APDU ", stdout);
    for (DWORD i = 0; i < length; i++) printf("%02x", command[i]);
    puts(""); fflush(stdout);
    if (!fgets(line, sizeof(line), stdin) || line[0] == '!') {
        status.errorStatus = 1; status.errorCode = 123; return status;
    }
    n = strcspn(line, "\r\n");
    if (n % 2 || n < 4 || n / 2 > *capacity) { status.errorStatus = 1; return status; }
    for (size_t i = 0; i < n / 2; i++) {
        unsigned value;
        if (sscanf(line + 2 * i, "%2x", &value) != 1) { status.errorStatus = 1; return status; }
        response[i] = (BYTE)value;
    }
    *capacity = (DWORD)(n / 2);
    unsigned sw = ((unsigned)response[n / 2 - 2] << 8) | response[n / 2 - 1];
    status.errorCode = sw == 0x9000 ? 0 : OPGP_ISO7816_ERROR_PREFIX | sw;
    return status;
}

static int wire_suite(OPGP_CARD_CONTEXT context, OPGP_CARD_INFO card, GP211_SECURITY_INFO *security) {
    DWORD max = security->secureChannelProtocol == 3 && (security->secureChannelProtocolImpl & GP211_SCP03_IMPL_S16) ? 223 : 239;
    DWORD lengths[] = {0, 1, 15, 16, 31, max};
    BYTE command[300] = {0x80, 0xDA, 0, 0};
    BYTE response[1024];
    OPGP_ERROR_STATUS status;
    for (DWORD i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        DWORD n = lengths[i];
        DWORD capacity = sizeof(response);
        command[4] = (BYTE)n;
        for (DWORD j = 0; j < n; j++) command[5 + j] = (BYTE)j;
        status = OPGP_send_APDU(context, card, security, command, n ? 5 + n : 4, response, &capacity);
        if (OPGP_ERROR_CHECK(status) || capacity != 2) return 1;
    }
    /* A case-2 command also consumes the encryption counter without C-data. */
    DWORD emptyCapacity = sizeof(response);
    command[4] = 0;
    status = OPGP_send_APDU(context, card, security, command, 5, response, &emptyCapacity);
    if (OPGP_ERROR_CHECK(status) || emptyCapacity != 2) return 1;
    /* An oversized short command must fail locally without consuming state. */
    GP211_SECURITY_INFO before = *security;
    DWORD capacity = sizeof(response);
    command[4] = (BYTE)(max + 1);
    status = OPGP_send_APDU(context, card, security, command, 6 + max, response, &capacity);
    if (!OPGP_ERROR_CHECK(status) || memcmp(&before, security, sizeof(before))) return 1;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3 && argc != 4) return 2;
    const char *mode = argc == 4 ? argv[3] : "random";
#ifndef OPGP_STATIC_CALLBACKS
    if (!OSSL_PROVIDER_load(NULL, "default") || !OSSL_PROVIDER_load(NULL, "legacy")) return 3;
#endif
    OPGP_CARD_CONTEXT context = {0};
    context.connectionFunctions.sendAPDU = exchange;
#ifdef OPGP_STATIC_CALLBACKS
    OPGP_ERROR_STATUS established = OPGP_establish_context(&context);
    if (OPGP_ERROR_CHECK(established)) { puts("RESULT initialize 1"); return 3; }
#endif
    OPGP_CARD_INFO card = {0}; card.specVersion = GP_211;
    BYTE select[] = {0, 0xa4, 4, 0, 8, 0xa0, 0, 0, 1, 0x51, 0, 0, 0, 0};
    BYTE response[1024]; DWORD capacity = sizeof(response);
    OPGP_ERROR_STATUS status = OPGP_send_APDU(context, card, NULL, select, sizeof(select), response, &capacity);
    if (OPGP_ERROR_CHECK(status)) { puts("RESULT select 1"); return 0; }
    BYTE enc[16], mac[16], dek[16], challenge[16];
    for (int i = 0; i < 16; i++) { enc[i] = 0x10 + i; mac[i] = 0x20 + i; dek[i] = 0x30 + i; challenge[i] = (BYTE)i; }
    GP211_SECURITY_INFO security = {0};
    memcpy(security.invokingAid, select + 5, 8); security.invokingAidLength = 8;
    BYTE protocol = (BYTE)atoi(argv[1]), option = (BYTE)strtol(argv[2], NULL, 0);
    DWORD n = protocol == 3 && (option & GP211_SCP03_IMPL_S16) ? 16 : 8;
    PBYTE supplied = challenge;
    DWORD suppliedLength = n;
    BYTE level = 3;
    if (!strcmp(mode, "bad-length")) suppliedLength--;
    if (!strcmp(mode, "null-length")) { supplied = NULL; suppliedLength = 1; }
    if (!strcmp(mode, "missing-aid")) security.invokingAidLength = 0;
    if (!strcmp(mode, "rmac")) level = 0x13;
    if (!strcmp(mode, "random")) {
        status = GP211_mutual_authentication(context, card, NULL, enc, mac, dek, 16, 0, 0,
            protocol, option, level, OPGP_DERIVATION_METHOD_NONE, NULL, 0, NULL, 0, NULL, &security);
    } else {
        status = GP211_mutual_authentication_with_challenge(context, card, NULL, enc, mac, dek, 16, 0, 0,
            protocol, option, level, OPGP_DERIVATION_METHOD_NONE, NULL, 0, NULL, 0, NULL,
            supplied, suppliedLength, &security);
    }
    if (OPGP_ERROR_CHECK(status)) {
        printf("RESULT authenticate 1 code=%lu\n", (unsigned long)status.errorCode); return 0;
    }
    if (!strcmp(mode, "suite") && wire_suite(context, card, &security)) { puts("RESULT wire 1"); return 0; }
    GP211_APPLICATION_DATA apps[4] = {0}; DWORD count = 4;
    status = GP211_get_status(context, card, &security, 0x80, 2, apps, NULL, &count);
    printf("RESULT registry %ld count=%lu\n", (long)status.errorStatus, (unsigned long)count);
    memset(&security, 0, sizeof(security)); return 0;
}
