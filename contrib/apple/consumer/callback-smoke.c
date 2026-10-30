#include <globalplatform/globalplatform.h>
#include <globalplatform/debug.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(DWORD) == 4, "Callback DWORD ABI must be 32-bit");
_Static_assert(sizeof(LONG) == 4, "Callback LONG ABI must be 32-bit");
_Static_assert(sizeof(BOOL) == 4, "Callback BOOL ABI must be 32-bit");
_Static_assert(sizeof(USHORT) == 2, "Callback USHORT ABI must be 16-bit");

static DWORD reported_length = 2;
static unsigned int calls;
static int fail_transport;

static OPGP_ERROR_STATUS send_apdu(OPGP_CARD_CONTEXT context, OPGP_CARD_INFO card,
    PBYTE command, DWORD command_length, PBYTE response, PDWORD response_length) {
    OPGP_ERROR_STATUS status;
    (void)context; (void)card; (void)command; (void)command_length;
    calls++;
    if (fail_transport) {
        OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, "Synthetic transport failure");
        return status;
    }
    if (*response_length >= 2) {
        response[0] = 0x90;
        response[1] = 0;
    }
    *response_length = reported_length;
    OPGP_ERROR_CREATE_NO_ERROR(status);
    return status;
}

int main(void) {
    OPGP_CARD_CONTEXT context = {0};
    OPGP_CARD_INFO card = {0};
    OPGP_ERROR_STATUS status;
    BYTE command[] = {0x00, 0xA4, 0x04, 0x00, 0x00};
    BYTE response[258];
    DWORD length;
    FILE *trace;
    EVP_CIPHER *cipher;
    unsigned int mode;
    static const BYTE des_expected[8] = {0x8c, 0xa6, 0x4d, 0xe9, 0xc1, 0xb1, 0x23, 0xa7};
    static const BYTE aes_expected[16] = {0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
        0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e};
    const char *algorithms[] = {"DES-ECB", "AES-128-ECB"};
    const BYTE *expected[] = {des_expected, aes_expected};
    BYTE zero[16] = {0};
    BYTE encrypted[32];

    status = OPGP_establish_context(&context);
    if (!OPGP_ERROR_CHECK(status)) return 1;
    context.connectionFunctions.sendAPDU = send_apdu;
    status = OPGP_establish_context(&context);
    if (OPGP_ERROR_CHECK(status)) return 2;
    card.specVersion = GP_211;
    trace = tmpfile();
    if (trace == NULL) return 3;
    OPGP_enable_trace_mode(OPGP_TRACE_MODE_ENABLE, trace);
    setenv("GLOBALPLATFORM_DEBUG", "1", 1);
    OPGP_log_Hex("Must not log", command, sizeof(command));
    OPGP_log_Msg("Must not log a secret");

    for (mode = 0; mode < 3; mode++) {
        BYTE *commands[] = {command};
        DWORD command_lengths[] = {sizeof(command)};
        DWORD invalid_lengths[] = {0, 1, sizeof(response) + 1};
        unsigned int index;
        for (index = 0; index < 5; index++) {
            unsigned int before = calls;
            length = sizeof(response);
            reported_length = index < 3 ? invalid_lengths[index] : 2;
            fail_transport = index == 4;
            if (mode == 0) {
                status = OPGP_send_APDU(context, card, NULL, command, sizeof(command), response, &length);
            } else {
                /* >255 data is needed to select the extended transport branch. */
                BYTE extended[263] = {0x80, 0xE2, 0, 0, 0, 1, 0};
                BYTE *extended_commands[] = {extended};
                DWORD extended_lengths[] = {sizeof(extended)};
                card.extendedAPDUSupported = mode == 2;
                status = OPGP_send_chained_APDU_extended(context, card, NULL,
                    mode == 2 ? extended_commands : commands,
                    mode == 2 ? extended_lengths : command_lengths,
                    1, response, &length, mode == 2);
            }
            if (calls != before + 1) return 4;
            if ((index != 3) != !!OPGP_ERROR_CHECK(status)) return 5;
        }
    }
    fflush(trace);
    if (ftell(trace) != 0 || traceEnable != 0) return 7;
    fclose(trace);
    for (mode = 0; mode < 2; mode++) {
        EVP_CIPHER_CTX *cipher_context = EVP_CIPHER_CTX_new();
        int produced = 0, final_length = 0;
        int block_length = mode == 0 ? 8 : 16;
        cipher = EVP_CIPHER_fetch(NULL, algorithms[mode], NULL);
        if (cipher == NULL || cipher_context == NULL) return 8;
        if (!EVP_EncryptInit_ex(cipher_context, cipher, NULL, zero, NULL) ||
            !EVP_CIPHER_CTX_set_padding(cipher_context, 0) ||
            !EVP_EncryptUpdate(cipher_context, encrypted, &produced, zero, block_length) ||
            !EVP_EncryptFinal_ex(cipher_context, encrypted + produced, &final_length) ||
            produced + final_length != block_length || memcmp(encrypted, expected[mode], block_length)) return 9;
        EVP_CIPHER_CTX_free(cipher_context);
        EVP_CIPHER_free(cipher);
    }
    status = OPGP_release_context(&context);
    if (OPGP_ERROR_CHECK(status) || context.connectionFunctions.sendAPDU != NULL) return 10;
    printf("PASS callbacks, 32-bit ABI, 3 response paths, no replay, inert trace, static providers: %s\n",
        OpenSSL_version(OPENSSL_VERSION));
    return 0;
}
