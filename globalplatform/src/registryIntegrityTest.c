/*  Copyright (c) 2023, Karsten Ohme
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
/* Synthetic, card-free GET STATUS regression tests. No production keys or writes. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "globalplatform/globalplatform.h"

static unsigned tests;
static size_t allocationCalls, failAllocation, activeAllocations;
void *gp_registry_test_calloc(size_t count, size_t size) {
    allocationCalls++;
    if (allocationCalls == failAllocation) return NULL;
    void *result = calloc(count, size);
    if (result != NULL) activeAllocations++;
    return result;
}
void *gp_registry_test_realloc(void *memory, size_t size) {
    allocationCalls++;
    if (allocationCalls == failAllocation) return NULL;
    int fresh = memory == NULL;
    void *result = realloc(memory, size);
    if (result != NULL && fresh) activeAllocations++;
    return result;
}

void gp_registry_test_free(void *memory) {
    if (memory != NULL) { assert(activeAllocations > 0); activeAllocations--; }
    free(memory);
}

typedef struct { BYTE bytes[70000]; size_t length; } Buffer;
static Buffer payload;
static size_t cursor, firstChunk, chunkSize;
static unsigned calls, failCall, terminalSW, emptyContinuation, shortResponse, oversizedResponse, forceFinalPage;
static BYTE expectedElement, expectedFormat;

static void byte(Buffer *buffer, BYTE value) {
    assert(buffer->length < sizeof(buffer->bytes));
    buffer->bytes[buffer->length++] = value;
}
static void tlv(Buffer *buffer, unsigned tag, const BYTE *value, size_t length) {
    if (tag > 255) byte(buffer, tag >> 8);
    byte(buffer, tag);
    if (length >= 256) { byte(buffer, 0x82); byte(buffer, length >> 8); byte(buffer, length); }
    else if (length >= 128) { byte(buffer, 0x81); byte(buffer, length); }
    else byte(buffer, length);
    assert(buffer->length + length <= sizeof(buffer->bytes));
    if (length) memcpy(buffer->bytes + buffer->length, value, length);
    buffer->length += length;
}
static void aid(Buffer *buffer, unsigned tag, unsigned id, size_t length) {
    BYTE bytes[17] = {0xF0, 0, 0, 0, 1};
    bytes[3] = id >> 8; bytes[4] = id;
    tlv(buffer, tag, bytes, length);
}
static Buffer body(unsigned id, int application) {
    Buffer value = {{0},0}; BYTE state = 7;
    aid(&value, 0x4F, id, 5);
    tlv(&value, 0x9F70, &state, 1);
    if (application) tlv(&value, 0xC5, NULL, 0);
    return value;
}
static void record(const Buffer *value) { tlv(&payload, 0xE3, value->bytes, value->length); }
static void setup(BYTE element, BYTE format) {
    assert(activeAllocations == 0);
    memset(&payload, 0, sizeof(payload));
    cursor = 0; calls = 0; failCall = 0; terminalSW = 0x9000;
    emptyContinuation = shortResponse = oversizedResponse = forceFinalPage = 0;
    firstChunk = 0; chunkSize = 239; expectedElement = element; expectedFormat = format;
    allocationCalls = failAllocation = 0;
}
static OPGP_ERROR_STATUS exchange(OPGP_CARD_CONTEXT context, OPGP_CARD_INFO card,
        PBYTE command, DWORD length, PBYTE response, PDWORD capacity) {
    OPGP_ERROR_STATUS status = {0};
    size_t count;
    unsigned sw;
    (void)context; (void)card;
    assert(length == 8 && command[0] == 0x80 && command[1] == 0xF2);
    assert(command[2] == expectedElement && command[3] == (calls ? expectedFormat | 1 : expectedFormat));
    assert(command[4] == 2 && command[5] == 0x4F && command[6] == 0 && command[7] == 0);
    calls++;
    if (calls == failCall) { status.errorStatus = OPGP_ERROR_STATUS_FAILURE; status.errorCode = 123; return status; }
    if (shortResponse) { response[0] = 0x90; *capacity = 1; return status; }
    if (oversizedResponse) { *capacity += 1; return status; }
    if (emptyContinuation) { response[0] = 0x63; response[1] = 0x10; *capacity = 2; return status; }
    count = payload.length - cursor;
    if (count > (calls == 1 && firstChunk ? firstChunk : chunkSize)) count = calls == 1 && firstChunk ? firstChunk : chunkSize;
    assert(*capacity >= count + 2);
    if (count) memcpy(response, payload.bytes + cursor, count);
    cursor += count;
    sw = cursor < payload.length ? 0x6310 : terminalSW;
    if (forceFinalPage) sw = count ? 0x6310 : 0x9000;
    response[count] = sw >> 8; response[count+1] = sw;
    *capacity = count + 2;
    /* Intentionally leave errorCode zero: response SW is authoritative. */
    return status;
}
static OPGP_CARD_CONTEXT test_context(void) {
    OPGP_CARD_CONTEXT context = {0};
    context.connectionFunctions.sendAPDU = exchange;
#ifdef OPGP_STATIC_CALLBACKS
    OPGP_ERROR_STATUS status = OPGP_establish_context(&context);
    assert(!OPGP_ERROR_CHECK(status));
#endif
    return context;
}
static void test_release(OPGP_CARD_CONTEXT *context) {
#ifdef OPGP_STATIC_CALLBACKS
    OPGP_ERROR_STATUS status = OPGP_release_context(context);
    assert(!OPGP_ERROR_CHECK(status));
#else
    (void)context;
#endif
}
static OPGP_ERROR_STATUS read_registry(GP211_REGISTRY_DATA **result) {
    OPGP_CARD_CONTEXT context = test_context(); OPGP_CARD_INFO card = {0};
    OPGP_ERROR_STATUS status = GP211_get_status_ex(context, card, NULL, expectedElement, expectedFormat, result);
    test_release(&context);
    return status;
}
static void reject(void) {
    GP211_REGISTRY_DATA *result = NULL;
    OPGP_ERROR_STATUS status = read_registry(&result);
    if (!OPGP_ERROR_CHECK(status) || result != NULL) fprintf(stderr, "unexpected accept: case=%u calls=%u size=%zu allocations=%zu fail=%zu\n", tests+1, calls, payload.length, allocationCalls, failAllocation);
    assert(OPGP_ERROR_CHECK(status) && result == NULL);
    assert(activeAllocations == 0);
    tests++;
}
static GP211_REGISTRY_DATA *accept(unsigned count) {
    GP211_REGISTRY_DATA *result = NULL;
    OPGP_ERROR_STATUS status = read_registry(&result);
    assert(!OPGP_ERROR_CHECK(status) && result != NULL && result->count == count);
    assert(result->responseDataLength == payload.length);
    if (payload.length) assert(!memcmp(result->responseData, payload.bytes, payload.length));
    tests++;
    return result;
}
static void good_fields(void) {
    BYTE version[] = {0xE1, 0, 0x7F, 3, 9};
    setup(GP211_STATUS_APPLICATIONS, GP211_STATUS_FORMAT_NEW);
    Buffer value = body(1, 1); aid(&value, 0xC4, 2, 5); aid(&value, 0xCC, 3, 16);
    tlv(&value, 0xCE, version, sizeof(version)); tlv(&value, 0xD0, version, sizeof(version)); record(&value);
    GP211_REGISTRY_DATA *result = accept(1);
    GP211_REGISTRY_ENTRY *entry = &result->entries[0];
    assert(entry->privilegesPresent && entry->privileges == 0);
    assert(entry->executableLoadFileAIDPresent && entry->executableLoadFileAID.AID[4] == 2);
    assert(entry->associatedSecurityDomainAIDPresent && entry->associatedSecurityDomainAID.AIDLength == 16);
    assert(entry->versionNumberPresent && entry->versionNumberLength == sizeof(version));
    assert(!memcmp(entry->versionNumber, version, sizeof(version)));
    assert(entry->versionNumber >= result->responseData && entry->versionNumber + sizeof(version) <= result->responseData + result->responseDataLength);
    assert(calls == 1); GP211_free_status(result);
    setup(0x40, 2); value = body(1, 1); record(&value); result = accept(1);
    assert(!result->entries[0].versionNumberPresent && result->entries[0].versionNumberLength == 0 && result->entries[0].versionNumber == NULL);
    assert(!result->entries[0].executableLoadFileAIDPresent); GP211_free_status(result);
    setup(0x40, 2); value = body(1, 1); tlv(&value, 0xCE, NULL, 0); record(&value); reject();
    setup(0x40, 2); result = accept(0); assert(calls == 1); GP211_free_status(result);
    GP211_free_status(NULL);
    for (unsigned length = 1; length <= 3; length += 2) {
        setup(0x40, 2); value = body(1, 0); tlv(&value, 0xC5, version, length); record(&value);
        result = accept(1); assert(result->entries[0].privileges == (length == 1 ? 0xE10000 : 0xE1007F)); GP211_free_status(result);
    }
}
static void invalid_fields(void) {
    const unsigned singletons[] = {0x4F, 0x9F70, 0xC5, 0xCC, 0xC4, 0xCE};
    BYTE bytes[20] = {1};
    for (unsigned index = 0; index < sizeof(singletons)/sizeof(singletons[0]); index++) {
        setup(0x40, 2); Buffer value = body(1, 1); unsigned tag = singletons[index];
        if (tag == 0x4F || tag == 0xC4 || tag == 0xCC) aid(&value, tag, 2, 5);
        else tlv(&value, tag, bytes, 1);
        if (tag == 0xC4 || tag == 0xCC) aid(&value, tag, 2, 5);
        if (tag == 0xCE) tlv(&value, tag, bytes, 1);
        record(&value); reject();
    }
    for (unsigned missing = 0; missing < 3; missing++) {
        setup(0x40, 2); Buffer value = {{0},0};
        if (missing != 0) aid(&value, 0x4F, 1, 5);
        if (missing != 1) tlv(&value, 0x9F70, bytes, 1);
        if (missing != 2) tlv(&value, 0xC5, NULL, 0);
        record(&value); reject();
    }
    setup(0x40, 2); Buffer empty = {{0},0}; record(&empty); reject();
    const unsigned aidTags[] = {0x4F, 0xC4, 0xCC, 0x84};
    const unsigned invalidLengths[] = {0, 4, 17};
    for (unsigned tagIndex = 0; tagIndex < 4; tagIndex++) for (unsigned index = 0; index < 3; index++) {
        unsigned tag = aidTags[tagIndex];
        setup(tag == 0x84 ? 0x10 : 0x40, 2); Buffer value = tag == 0x4F ? empty : body(1, tag != 0x84);
        if (tag == 0x4F) { tlv(&value, 0x9F70, bytes, 1); tlv(&value, 0xC5, NULL, 0); }
        aid(&value, tag, 1, invalidLengths[index]); record(&value); reject();
    }
    for (unsigned length = 0; length < 3; length += 2) {
        setup(0x40, 2); Buffer value = empty; aid(&value, 0x4F, 1, 5);
        tlv(&value, 0x9F70, bytes, length); tlv(&value, 0xC5, NULL, 0); record(&value); reject();
    }
    for (unsigned length = 2; length <= 4; length += 2) {
        setup(0x40, 2); Buffer value = body(1, 0); tlv(&value, 0xC5, bytes, length); record(&value); reject();
    }
    setup(0x40, 2); Buffer value = body(1, 1); record(&value); record(&value); reject();
    setup(0x10, 2); value = body(1, 0); aid(&value, 0x84, 2, 5); aid(&value, 0x84, 2, 5); record(&value); reject();
    setup(0x20, 2); value = body(1, 0); record(&value); GP211_free_status(accept(1));
    setup(0x80, 2); value = body(1, 0); record(&value); reject();
}
static void paging_and_modules(void) {
    const unsigned counts[] = {0, 1, 30, 32, 64, 65};
    for (unsigned index = 0; index < 6; index++) {
        setup(0x10, 2); Buffer value = body(1, 0);
        for (unsigned module = 0; module < counts[index]; module++) aid(&value, 0x84, module+2, 6);
        record(&value);
        if (counts[index] > 64) reject();
        else { GP211_REGISTRY_DATA *result = accept(1); assert(result->entries[0].numExecutableModules == counts[index]); GP211_free_status(result); }
        assert(calls == (payload.length + 238)/239);
    }
    /* Every boundary through a BER-82 E3, including its tag/length header. */
    setup(0x10, 2); Buffer value = body(1, 0);
    for (unsigned module = 0; module < 32; module++) aid(&value, 0x84, module+2, 6);
    record(&value); size_t length = payload.length;
    assert(payload.bytes[0] == 0xE3 && payload.bytes[1] == 0x82);
    for (size_t split = 1; split < length && split <= 256; split++) {
        cursor = 0; calls = 0; firstChunk = split;
        GP211_REGISTRY_DATA *result = accept(1); assert(result->entries[0].numExecutableModules == 32); GP211_free_status(result);
    }
    firstChunk = 0;
    for (DWORD prefix = 1; prefix < length; prefix++) {
        payload.length = prefix; cursor = 0; calls = 0; reject();
    }
    setup(0x40, 2);
    for (unsigned id = 1; id <= 3; id++) { value = body(id, 1); record(&value); }
    chunkSize = 16; GP211_free_status(accept(3)); assert(calls == 3);
    /* The empty 9000 final page is permitted after a nonempty continuation. */
    setup(0x40, 2); value = body(1, 1); record(&value); forceFinalPage = 1;
    GP211_free_status(accept(1)); assert(calls == 2);
    /* Fail on first, middle, or final exchange, with no replay. */
    for (unsigned failure = 1; failure <= 3; failure++) {
        setup(0x10, 2); value = body(1, 0);
        for (unsigned module = 0; module < 64; module++) aid(&value, 0x84, module+2, 6);
        record(&value); failCall = failure; reject(); assert(calls == failure);
    }
    setup(0x40, 2); value = body(1, 1); record(&value); emptyContinuation = 1; reject(); assert(calls == 1);
    setup(0x40, 2); value = body(1, 1); record(&value); terminalSW = 0x6A80; reject(); assert(calls == 1);
    setup(0x10, 2); value = body(1, 0);
    for (unsigned module = 0; module < 64; module++) aid(&value, 0x84, module+2, 6);
    record(&value); terminalSW = 0x6A80; reject(); assert(calls == 3);
    setup(0x40, 2); value = body(1, 1); record(&value); terminalSW = 0x6310; reject(); assert(calls == 2);
    setup(0x40, 2); value = body(1, 1); record(&value); shortResponse = 1; reject(); assert(calls == 1);
    setup(0x40, 2); value = body(1, 1); record(&value); oversizedResponse = 1; reject(); assert(calls == 1);
    setup(0x40, 2); BYTE raw[1000] = {0}; value = body(1, 1); tlv(&value, 0xD0, raw, sizeof(raw)); record(&value);
    chunkSize = 16; GP211_free_status(accept(1)); assert(calls == 64);
    cursor = 0; calls = 0; forceFinalPage = 1; reject(); assert(calls == 64);
    setup(0x40, 2); value = body(1, 1); BYTE longer[1100] = {0}; tlv(&value, 0xD0, longer, sizeof(longer)); record(&value);
    chunkSize = 16; reject(); assert(calls == 64);
}
static void issuer_and_not_found(void) {
    Buffer value;
    setup(0x80, 2); value = body(1, 1); record(&value);
    GP211_free_status(accept(1)); assert(calls == 1);
    setup(0x80, 2); reject(); assert(calls == 1);
    setup(0x80, 2); value = body(1, 1); record(&value); value = body(2, 1); record(&value);
    reject(); assert(calls == 1);
    setup(0x80, 2); value = body(1, 1); record(&value); terminalSW = 0x6310;
    reject(); assert(calls == 1);
    const BYTE elements[] = {0x40, 0x20, 0x10};
    for (unsigned index = 0; index < sizeof(elements); index++) {
        GP211_REGISTRY_DATA *result = NULL;
        setup(elements[index], 2); terminalSW = 0x6A88;
        OPGP_ERROR_STATUS status = read_registry(&result);
        assert(OPGP_ERROR_CHECK(status) && status.errorCode == (OPGP_ISO7816_ERROR_PREFIX | 0x6A88));
        assert(result == NULL && calls == 1); tests++;
        setup(elements[index], 2); value = body(1, elements[index] == 0x40);
        BYTE padding[500] = {0}; tlv(&value, 0xD0, padding, sizeof(padding)); record(&value); terminalSW = 0x6A88;
        status = read_registry(&result);
        assert(OPGP_ERROR_CHECK(status) && status.errorCode == (OPGP_ISO7816_ERROR_PREFIX | 0x6A88));
        assert(result == NULL && calls == 3 && activeAllocations == 0); tests++;
    }
}
static void entry_and_version_limits(void) {
    Buffer value;
    for (unsigned count = 1024; count <= 1025; count++) {
        setup(0x40, 2); chunkSize = 256;
        for (unsigned id = 1; id <= count; id++) { value = body(id, 1); record(&value); }
        if (count == 1024) GP211_free_status(accept(count)); else reject();
    }
    setup(0x40, 2); value = body(1, 1);
    BYTE version[4096]; for (size_t index = 0; index < sizeof(version); index++) version[index] = index;
    tlv(&value, 0xCE, version, sizeof(version)); record(&value);
    GP211_REGISTRY_DATA *result = accept(1);
    assert(result->entries[0].versionNumberPresent && result->entries[0].versionNumberLength == sizeof(version));
    assert(!memcmp(result->entries[0].versionNumber, version, sizeof(version))); GP211_free_status(result);
    setup(0x40, 1); reject(); assert(calls == 0);
    setup(0x30, 2); reject(); assert(calls == 0);
}
static OPGP_ERROR_STATUS old_read(GP211_APPLICATION_DATA *output, PDWORD count) {
    OPGP_CARD_CONTEXT context = test_context(); OPGP_CARD_INFO card = {0};
    OPGP_ERROR_STATUS status = GP211_get_status(context, card, NULL, 0x40, 2, output, NULL, count);
    test_release(&context);
    return status;
}
static void compatibility_and_allocation(void) {
    BYTE version[] = {1,2,3,4}; GP211_APPLICATION_DATA output[2], before[2]; DWORD count;
    setup(0x40, 2); Buffer value = body(1, 1); aid(&value, 0xC4, 2, 5); tlv(&value, 0xCE, version, sizeof(version)); record(&value);
    count = 2; OPGP_ERROR_STATUS status = old_read(output, &count);
    assert(!OPGP_ERROR_CHECK(status) && count == 1 && output[0].versionNumber[0] == 1 && output[0].versionNumber[1] == 2); tests++;
    setup(0x40, 2); value = body(1, 1); record(&value); value = body(2, 1); record(&value);
    memset(output, 0xAA, sizeof(output)); memcpy(before, output, sizeof(output)); count = 1;
    status = old_read(output, &count); assert(OPGP_ERROR_CHECK(status) && count == 0 && !memcmp(output, before, sizeof(output))); tests++;
    setup(0x40, 2); value = body(1, 1); record(&value); byte(&payload, 0xE3);
    count = 2; status = old_read(output, &count); assert(OPGP_ERROR_CHECK(status) && count == 0 && !memcmp(output, before, sizeof(output))); tests++;
    setup(0x40, 2); value = body(1, 1); record(&value);
    count = 0; status = old_read(NULL, &count); assert(OPGP_ERROR_CHECK(status) && count == 0 && calls == 1); tests++;
    cursor = 0; calls = 0; count = 1; status = old_read(NULL, &count);
    assert(OPGP_ERROR_CHECK(status) && count == 0 && calls == 0); tests++;
    status = old_read(output, NULL); assert(OPGP_ERROR_CHECK(status) && calls == 0); tests++;
#ifdef GP_REGISTRY_TEST_ALLOCATIONS
    for (size_t failure = 1; failure <= 4; failure++) {
        setup(0x40, 2); value = body(1, 1); BYTE raw[1100] = {0}; tlv(&value, 0xD0, raw, sizeof(raw)); record(&value);
        failAllocation = failure; reject(); assert(allocationCalls == failure);
    }
#endif
    setup(0x40, 2); value = body(1, 1); record(&value);
    GP211_REGISTRY_DATA *result = accept(1), *original = result;
    cursor = 0; calls = 0; status = read_registry(&result);
    assert(OPGP_ERROR_CHECK(status) && calls == 0 && result == original); tests++; GP211_free_status(result);
}
static void legacy(void) {
    BYTE data[] = {5,0xF0,0,0,0,1,7,0};
    for (DWORD length = 1; length <= sizeof(data); length++) {
        setup(0x20, 0); memcpy(payload.bytes, data, length); payload.length = length;
        if (length < sizeof(data)) reject(); else GP211_free_status(accept(1));
    }
    setup(0x40, 0); memcpy(payload.bytes, data, sizeof(data)); payload.length = sizeof(data); chunkSize = 1;
    GP211_REGISTRY_DATA *result = accept(1); assert(calls == sizeof(data) && result->entries[0].privilegesPresent); GP211_free_status(result);
    data[0] = 4; setup(0x40, 0); memcpy(payload.bytes, data, sizeof(data)); payload.length = sizeof(data); reject();
    setup(0x10, 0); BYTE modules[] = {5,0xF0,0,0,0,1,7,0,1,5,0xF0,0,0,0,2};
    memcpy(payload.bytes, modules, sizeof(modules)); payload.length = sizeof(modules); result = accept(1);
    assert(result->entries[0].numExecutableModules == 1); GP211_free_status(result);
    for (size_t length = 1; length < sizeof(modules); length++) {
        setup(0x10, 0); memcpy(payload.bytes, modules, length); payload.length = length; reject();
    }
    setup(0x40, 0); memcpy(payload.bytes, data, sizeof(data)); payload.bytes[0] = 5; payload.length = sizeof(data); chunkSize = 1;
    OPGP_CARD_CONTEXT context = test_context(); OPGP_CARD_INFO card = {0};
    OP201_APPLICATION_DATA output[1]; DWORD count = 1;
    OPGP_ERROR_STATUS status = OP201_get_status(context, card, NULL, 0x40, output, &count);
    assert(!OPGP_ERROR_CHECK(status) && count == 1 && calls == sizeof(data)); tests++; test_release(&context);
}
int main(void) {
#ifdef NDEBUG
#error "Registry tests require assertions; compile without NDEBUG."
#endif
    good_fields(); invalid_fields(); paging_and_modules(); issuer_and_not_found(); entry_and_version_limits(); compatibility_and_allocation(); legacy();
    assert(activeAllocations == 0);
    printf("registry integrity: %u synthetic cases passed\n", tests);
    return 0;
}
