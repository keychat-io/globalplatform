/* Synthetic-key, host-only SDK qualification. Never use production credentials. */
#include <stdio.h>
#include <openssl/provider.h>
#include <stdlib.h>
#include <string.h>
#include "globalplatform/globalplatform.h"
static OPGP_ERROR_STATUS exchange(OPGP_CARD_CONTEXT context, OPGP_CARD_INFO card, PBYTE command, DWORD length, PBYTE response, PDWORD capacity) {
    (void)context; (void)card;
    OPGP_ERROR_STATUS status={0};
    fputs("APDU ",stdout);
    for(DWORD i=0;i<length;i++)printf("%02x",command[i]);
    puts("");fflush(stdout);
    char line[8192];
    if(!fgets(line,sizeof(line),stdin)||line[0]=='!'){status.errorStatus=1;status.errorCode=123;return status;}
    size_t n=strcspn(line,"\r\n");
    if(n%2||n<4||n/2>*capacity){status.errorStatus=1;return status;}
    for(size_t i=0;i<n/2;i++){unsigned value;if(sscanf(line+2*i,"%2x",&value)!=1){status.errorStatus=1;return status;}response[i]=value;}
    *capacity=n/2;
    unsigned sw=((unsigned)response[n/2-2]<<8)|response[n/2-1];
    status.errorCode=sw==0x9000?0:OPGP_ISO7816_ERROR_PREFIX|sw;
    return status;
}
int main(int argc,char **argv) {
    if(argc!=3)return 2;
#ifndef OPGP_STATIC_CALLBACKS
    if(!OSSL_PROVIDER_load(NULL,"default")||!OSSL_PROVIDER_load(NULL,"legacy"))return 3;
#endif
    OPGP_CARD_CONTEXT context={0};context.connectionFunctions.sendAPDU=exchange;
#ifdef OPGP_STATIC_CALLBACKS
    OPGP_ERROR_STATUS established=OPGP_establish_context(&context);
    if(OPGP_ERROR_CHECK(established)){puts("RESULT initialize 1");return 3;}
#endif
    OPGP_CARD_INFO card={0};card.specVersion=GP_211;
    BYTE select[]={0,0xa4,4,0,8,0xa0,0,0,1,0x51,0,0,0,0};
    BYTE response[1024];DWORD capacity=sizeof(response);
    OPGP_ERROR_STATUS status=OPGP_send_APDU(context,card,NULL,select,sizeof(select),response,&capacity);
    if(status.errorStatus){printf("RESULT select %ld\n",(long)status.errorStatus);return 0;}
    BYTE enc[16],mac[16],dek[16];for(int i=0;i<16;i++){enc[i]=0x10+i;mac[i]=0x20+i;dek[i]=0x30+i;}
    GP211_SECURITY_INFO security={0};
    memcpy(security.invokingAid,select+5,8);security.invokingAidLength=8;
    status=GP211_mutual_authentication(context,card,NULL,enc,mac,dek,16,0,0,atoi(argv[1]),strtol(argv[2],NULL,0),3,OPGP_DERIVATION_METHOD_NONE,NULL,0,NULL,0,NULL,&security);
    if(status.errorStatus){printf("RESULT authenticate %ld code=%lu\n",(long)status.errorStatus,(unsigned long)status.errorCode);return 0;}
    GP211_APPLICATION_DATA apps[4]={0};DWORD count=4;
    status=GP211_get_status(context,card,&security,0x80,2,apps,NULL,&count);
    printf("RESULT registry %ld count=%lu\n",(long)status.errorStatus,(unsigned long)count);
    memset(&security,0,sizeof(security));return 0;
}
