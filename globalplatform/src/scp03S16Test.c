/*
 *  Copyright (c) 2005-2026, Karsten Ohme
 *  This file is part of GlobalPlatform.
 *
 *  GlobalPlatform is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GlobalPlatform is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with GlobalPlatform.  If not, see <https://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU Lesser General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.
 */

/* Card-free SCP03 S16 regression. All fixtures are synthetic. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/provider.h>
#include "globalplatform/globalplatform.h"
#include "crypto.h"
#include "scp.h"

static unsigned exchanges;
static int captureKind;
static BYTE expectedP2;
static int rejectCapture;

static OPGP_ERROR_STATUS unexpected_exchange(OPGP_CARD_CONTEXT context, OPGP_CARD_INFO card,
        PBYTE command, DWORD length, PBYTE response, PDWORD capacity) {
    OPGP_ERROR_STATUS status = {0};
    (void)context; (void)card; (void)command; (void)length; (void)response; (void)capacity;
    exchanges++;
    if (captureKind == 1) {
        assert(length == 13 && command[1] == 0xE4 && command[3] == expectedP2);
        assert(command[4] == 7 && command[5] == 0x4F && command[6] == 5);
        assert(command[12] == 0);
        if (rejectCapture) { status.errorStatus = 1; return status; }
    } else if (captureKind == 2) {
        assert(command[1] == 0xE8 && exchanges <= 2);
        assert(command[3] == exchanges - 1);
        if (exchanges == 1) {
            assert(command[2] == 0 && length == 260 && command[4] == 255);
            assert(!memcmp(command + 5, "\xC4\x82\x01\xF4", 4));
        } else {
            assert(command[2] == 0x80 && length == 255 && command[4] == 249 && command[254] == 0);
        }
    } else if (captureKind == 3) {
        assert(length == 11 && !memcmp(command, "\x00\xA4\x04\x00\x05", 5));
        assert(command[10] == 0);
    } else { status.errorStatus = 1; return status; }
    assert(*capacity >= 2);
    response[0] = 0x90; response[1] = 0;
    *capacity = 2;
    return status;
}

static void check_hex(const BYTE *actual, const char *expected, size_t n) {
    assert(strlen(expected) == 2 * n);
    for (size_t i = 0; i < n; i++) {
        unsigned value;
        assert(sscanf(expected + 2 * i, "%2x", &value) == 1);
        assert(actual[i] == value);
    }
}

static void test_kdf(void) {
    /* Independently generated with pyca CMAC, Amendment D v1.2 section 4.1.5.
     * key=00..(keyLength-1), context=host 00..0f || card 10..1f.
     * Derivation constants 04/00/01, lengths keyLength/16/16 respectively. */
    const char *expected[][3] = {
        {"00f996c51392e3b3ca3b692c5be4cc6c", "daefba9ad2029d3cbd0f598a640d2e0f", "e3cf6bd6be732a651a21e96e24ba2292"},
        {"baaf6f9c8eebb1e0258d4aa4f95a61f6341cc94dc3a0dbb7", "338211d58ac2386e22a56857c04d810d", "3c678adc3cf5ee374340342a3b47e184"},
        {"3bda2a9b9a4b411818686449ec4cf26c1d01f67ac6d9696644b1a3e520f1d391", "c359ec424218b1292878275f13ff6934", "ea42bb59a8bec3b8384b2ab0aa1e26ad"}
    };
    BYTE key[32], host[16], card[16], out[40];
    for (unsigned i = 0; i < 32; i++) key[i] = (BYTE)i;
    for (unsigned i = 0; i < 16; i++) { host[i] = (BYTE)i; card[i] = (BYTE)(16 + i); }
    for (unsigned k = 0; k < 3; k++) {
        DWORD keyLength = 16 + 8 * k;
        for (unsigned c = 0; c < 3; c++) {
            DWORD length = c ? 16 : keyLength;
            memset(out, 0xA5, sizeof(out));
            OPGP_ERROR_STATUS status = calculate_cryptogram_SCP03(key, keyLength, c ? c - 1 : 4,
                host, 16, card, 16, out, length * 8);
            assert(!OPGP_ERROR_CHECK(status));
            check_hex(out, expected[k][c], length);
            for (unsigned i = length; i < sizeof(out); i++) assert(out[i] == 0xA5);
        }
    }
    assert(OPGP_ERROR_CHECK(calculate_cryptogram_SCP03(key, 15, 4, host, 16, card, 16, out, 128)));
    assert(OPGP_ERROR_CHECK(calculate_cryptogram_SCP03(key, 16, 4, host, 17, card, 16, out, 128)));
    assert(OPGP_ERROR_CHECK(calculate_cryptogram_SCP03(key, 16, 4, host, 16, card, 16, out, 65)));
}

static void test_initialize_shapes(void) {
    BYTE response[80] = {0}, information[3] = {1, 3, 0};
    SCP_INITIALIZE_UPDATE_RESPONSE parsed;
    for (unsigned n = 8; n <= 16; n += 8) {
        for (unsigned pseudo = 0; pseudo < 2; pseudo++) {
            BYTE expected = (n == 16 ? 1 : 0) | (pseudo ? 0x10 : 0);
            DWORD correct = 15 + 2 * n + (pseudo ? 3 : 0);
            information[2] = expected;
            for (DWORD length = 0; length <= sizeof(response); length++) {
                BYTE option = expected;
                OPGP_ERROR_STATUS status = scp_parse_initialize_update_response(3, &option, 3,
                    information, response, length, &parsed);
                assert(OPGP_ERROR_CHECK(status) == (length != correct));
                if (length == correct) {
                    assert(parsed.cardChallengeLength == n);
                    assert(parsed.sequenceCounterLength == (pseudo ? 3 : 0));
                }
            }
            BYTE wrong = expected ^ 0x20;
            assert(OPGP_ERROR_CHECK(scp_parse_initialize_update_response(3, &wrong, 3,
                information, response, correct, &parsed)));
        }
    }
    for (unsigned option = 0; option < 256; option++) {
        information[2] = (BYTE)option;
        BYTE requested = (BYTE)option;
        DWORD correct = 15 + 2 * ((option & 1) ? 16 : 8) + ((option & 0x10) ? 3 : 0);
        int invalid = (option & 0x8E) || ((option & 0x40) && !(option & 0x20));
        OPGP_ERROR_STATUS status = scp_parse_initialize_update_response(3, &requested, 3,
            information, response, correct, &parsed);
        assert(!!OPGP_ERROR_CHECK(status) == !!invalid);
    }
    BYTE option = 1;
    information[2] = 1;
    assert(OPGP_ERROR_CHECK(scp_parse_initialize_update_response(3, &option, 0x13,
        information, response, 47, &parsed)));
}

static GP211_SECURITY_INFO session(BYTE option) {
    GP211_SECURITY_INFO info = {0};
    info.secureChannelProtocol = 3;
    info.secureChannelProtocolImpl = option;
    info.securityLevel = 3;
    info.keyLength = 16;
    info.sessionEncryptionCounter = 1;
    return info;
}

static void test_wrap_boundaries(void) {
    BYTE command[300] = {0x80, 0xDA, 0, 0}, out[400];
    for (unsigned n = 8; n <= 16; n += 8) {
        GP211_SECURITY_INFO info = session(n == 16 ? 1 : 0), before;
        DWORD capacity = sizeof(out);
        assert(!OPGP_ERROR_CHECK(wrap_command(command, 4, out, &capacity, &info)));
        assert(capacity == 5 + n && out[4] == n && info.sessionEncryptionCounter == 2);
        info = session(n == 16 ? 1 : 0);
        command[4] = 0; capacity = 5 + n;
        before = info;
        assert(OPGP_ERROR_CHECK(wrap_command(command, 5, out, &capacity, &info)));
        assert(memcmp(&before, &info, sizeof(info)) == 0); /* No room for Le. */
        unsigned max = n == 16 ? 223 : 239;
        command[4] = (BYTE)max; capacity = sizeof(out);
        assert(!OPGP_ERROR_CHECK(wrap_command(command, 5 + max, out, &capacity, &info)));
        assert(out[4] == ((max + 16) / 16) * 16 + n);
        command[4] = (BYTE)(max + 1); capacity = sizeof(out); before = info;
        assert(OPGP_ERROR_CHECK(wrap_command(command, 6 + max, out, &capacity, &info)));
        assert(memcmp(&before, &info, sizeof(info)) == 0);
        info = session(n == 16 ? 1 : 0); info.sessionEncryptionCounter = INT32_MAX;
        capacity = sizeof(out);
        assert(!OPGP_ERROR_CHECK(wrap_command(command, 4, out, &capacity, &info)));
        assert((uint32_t)info.sessionEncryptionCounter == UINT32_C(0x80000000));
        info.sessionEncryptionCounter = (LONG)UINT32_MAX; capacity = sizeof(out);
        assert(!OPGP_ERROR_CHECK(wrap_command(command, 4, out, &capacity, &info)));
        assert((uint32_t)info.sessionEncryptionCounter == 0);
        capacity = sizeof(out); before = info;
        assert(OPGP_ERROR_CHECK(wrap_command(command, 4, out, &capacity, &info)));
        assert(memcmp(&before, &info, sizeof(info)) == 0);
    }
}

static void test_scp02_empty_commands(void) {
    BYTE command[] = {0x80, 0xCA, 0, 0xE0, 0}, out[40];
    for (DWORD n = 4; n <= 5; n++) {
        GP211_SECURITY_INFO info = {0};
        info.secureChannelProtocol = 2; info.secureChannelProtocolImpl = 0x55;
        info.securityLevel = 3; info.keyLength = 16;
        DWORD capacity = sizeof(out);
        assert(!OPGP_ERROR_CHECK(wrap_command(command, n, out, &capacity, &info)));
        assert(capacity == n + 9);
        assert(out[4] == 8); /* Only C-MAC: no encrypted data field exists. */
        if (n == 5) assert(out[13] == 0);
    }
}

static void test_auth_input(OPGP_CARD_CONTEXT context) {
    OPGP_CARD_INFO card = {0}; card.specVersion = GP_211;
    BYTE key[32] = {0}, challenge[16] = {0};
    for (unsigned n = 8; n <= 16; n += 8) {
        for (DWORD length = 0; length <= 17; length++) {
            if (length == n) continue;
            GP211_SECURITY_INFO info = {0};
            OPGP_ERROR_STATUS status = GP211_mutual_authentication_with_challenge(context, card,
                NULL, key, key, key, 16, 0, 0, 3, n == 16 ? 1 : 0, 3, 0,
                NULL, 0, NULL, 0, NULL, challenge, length, &info);
            assert(OPGP_ERROR_CHECK(status) && exchanges == 0);
        }
    }
    GP211_SECURITY_INFO info = {0};
    assert(OPGP_ERROR_CHECK(GP211_mutual_authentication_with_challenge(context, card, NULL,
        key, key, key, 16, 0, 0, 3, 9, 3, 0, NULL, 0, NULL, 0, NULL, NULL, 0, &info)));
    assert(OPGP_ERROR_CHECK(GP211_mutual_authentication_with_challenge(context, card, NULL,
        key, key, key, 33, 0, 0, 3, 1, 3, 0, NULL, 0, NULL, 0, NULL, NULL, 0, &info)));
    assert(OPGP_ERROR_CHECK(GP211_mutual_authentication_with_challenge(context, card, NULL,
        key, key, key, 16, 0, 0, 3, 1, 0x13, 0, NULL, 0, NULL, 0, NULL, NULL, 0, &info)));
    assert(exchanges == 0);
    info = session(1);
    assert(OPGP_ERROR_CHECK(GP211_begin_R_MAC(context, card, &info, 0x10, NULL, 0)));
    assert(exchanges == 0);
    info.securityLevel = 0x13;
    BYTE command[4] = {0x80, 0xDA, 0, 0}, response[2] = {0x90, 0}, out[20];
    DWORD capacity = sizeof(out);
    assert(OPGP_ERROR_CHECK(unwrap_command(command, sizeof(command), response, sizeof(response), out, &capacity, &info)));
}

static void test_load_builder(void) {
    BYTE data[256], out[270];
    memset(data, 0xA5, sizeof(data));
    for (unsigned last = 0; last < 2; last++) {
        DWORD capacity = sizeof(out);
        assert(!OPGP_ERROR_CHECK(GP211_build_load_block(data, 255, 0xFF, last, out, &capacity)));
        assert(capacity == 260 + last && out[0] == 0x80 && out[1] == 0xE8);
        assert(out[2] == (last ? 0x80 : 0) && out[3] == 0xFF && out[4] == 255);
        assert(memcmp(out + 5, data, 255) == 0);
        if (last) assert(out[260] == 0);
        capacity = 259 + last; memset(out, 0xCC, sizeof(out));
        assert(OPGP_ERROR_CHECK(GP211_build_load_block(data, 255, 0, last, out, &capacity)));
        assert(capacity == 260 + last);
        for (unsigned i = 0; i < sizeof(out); i++) assert(out[i] == 0xCC);
    }
    DWORD capacity = sizeof(out);
    assert(OPGP_ERROR_CHECK(GP211_build_load_block(data, 256, 0, 0, out, &capacity)));
    assert(OPGP_ERROR_CHECK(GP211_build_load_block(NULL, 1, 0, 0, out, &capacity)));
    memcpy(out + 5, data, 12);
    assert(!OPGP_ERROR_CHECK(GP211_build_load_block(out + 5, 12, 3, 1, out, &capacity)));
    assert(memcmp(out + 5, data, 12) == 0 && capacity == 18);
}

static void test_scoped_delete(OPGP_CARD_CONTEXT context) {
    OPGP_CARD_INFO card = {0}; card.specVersion = GP_211;
    OPGP_AID aid = {0}; aid.AIDLength = 5;
    memcpy(aid.AID, "\xA0\x00\x00\x00\x01", 5);
    GP211_RECEIPT_DATA receipt = {0}; DWORD available = 0;
    captureKind = 1;
    for (int related = 0; related <= 1; related++) {
        exchanges = 0; expectedP2 = related ? 0x80 : 0;
        assert(!OPGP_ERROR_CHECK(GP211_delete_application_ex(context, card, NULL,
            &aid, 1, &receipt, &available, NULL, 0, related)));
        assert(exchanges == 1 && available == 0);
    }
    exchanges = 0; expectedP2 = 0x80;
    assert(!OPGP_ERROR_CHECK(GP211_delete_application(context, card, NULL,
        &aid, 1, &receipt, &available, NULL, 0)));
    assert(exchanges == 1);
    exchanges = 0; expectedP2 = 0; rejectCapture = 1;
    assert(OPGP_ERROR_CHECK(GP211_delete_application_ex(context, card, NULL,
        &aid, 1, &receipt, &available, NULL, 0, 0)));
    assert(exchanges == 1); /* No retry and no cascade fallback. */
    rejectCapture = 0; captureKind = 0; exchanges = 0;
}

static void test_load_workflow(OPGP_CARD_CONTEXT context) {
    OPGP_CARD_INFO card = {0}; card.specVersion = GP_211;
    GP211_RECEIPT_DATA receipt = {0}; DWORD available = 0;
    BYTE data[500]; memset(data, 0xA5, sizeof(data));
    captureKind = 2; exchanges = 0;
    assert(!OPGP_ERROR_CHECK(GP211_load_from_buffer(context, card, NULL, NULL, 0,
        data, sizeof(data), &receipt, &available, NULL)));
    assert(exchanges == 2 && available == 0);
    captureKind = 0; exchanges = 0;
}

static void test_key_blocks(void) {
    GP211_SECURITY_INFO info = session(1);
    BYTE key[32] = {0}, out[80], kcv[3];
    for (DWORD n = 16; n <= 32; n += 8) {
        DWORD capacity = sizeof(out);
        assert(!OPGP_ERROR_CHECK(get_key_data_field(&info, key, n, GP211_KEY_TYPE_AES,
            out, &capacity, kcv, 1)));
        DWORD cipherLength = n == 16 ? 16 : 32;
        assert(out[0] == 0x88 && out[1] == cipherLength + 1 && out[2] == n);
        assert(capacity == cipherLength + 7 && out[3 + cipherLength] == 3);
        assert(!memcmp(out + 4 + cipherLength, kcv, 3));
    }
    DWORD capacity = 3;
    assert(OPGP_ERROR_CHECK(get_key_data_field(&info, key, 16, GP211_KEY_TYPE_AES,
        out, &capacity, kcv, 1)));
}

int main(void) {
    OPGP_CARD_CONTEXT context = {0};
    context.connectionFunctions.sendAPDU = unexpected_exchange;
#ifdef OPGP_STATIC_CALLBACKS
    assert(!OPGP_ERROR_CHECK(OPGP_establish_context(&context)));
#else
    assert(OSSL_PROVIDER_load(NULL, "default") && OSSL_PROVIDER_load(NULL, "legacy"));
#endif
    test_kdf();
    test_initialize_shapes();
    test_wrap_boundaries();
    test_scp02_empty_commands();
    test_auth_input(context);
    test_load_builder();
    captureKind = 3; exchanges = 0;
    OPGP_CARD_INFO selectCard = {0};
    BYTE selectAid[] = {0xA0, 0, 0, 0, 1};
    assert(!OPGP_ERROR_CHECK(OPGP_select_application(context, selectCard, NULL, selectAid, sizeof(selectAid))));
    assert(exchanges == 1);
    captureKind = 0; exchanges = 0;
    test_scoped_delete(context);
    test_load_workflow(context);
    test_key_blocks();
    puts("SCP03 S16 KDF, framing, bounds, counter, and local-failure tests passed");
    return 0;
}
