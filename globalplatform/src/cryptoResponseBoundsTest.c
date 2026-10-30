/* Response validation must precede R-MAC reads. Synthetic state only. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "globalplatform/globalplatform.h"
#include "crypto.h"
int main(void) {
    BYTE command[]={0x80,0xf2,0x40,2,2,0x4f,0,0};
    GP211_SECURITY_INFO security={0};
    security.secureChannelProtocol=GP211_SCP03;
    security.securityLevel=GP211_SCP03_SECURITY_LEVEL_C_MAC_R_MAC;
    security.keyLength=16;
    unsigned cases=0;
    for(unsigned protocol=2;protocol<=3;protocol++) {
        security.secureChannelProtocol=protocol;
        for(DWORD length=0;length<10;length++) {
            BYTE response[10]={0},output[10]; DWORD capacity=sizeof(output);
            if(length>=2)response[length-2]=0x90;
            memset(output,0xa5,sizeof(output));
            OPGP_ERROR_STATUS status=GP211_check_R_MAC(command,sizeof(command),response,length,output,&capacity,&security);
            assert(OPGP_ERROR_CHECK(status));
            for(unsigned i=0;i<sizeof(output);i++)assert(output[i]==0xa5);
            cases++;
        }
    }
    security.secureChannelProtocol=GP211_SCP03;
    BYTE rejected[]={0x69,0x85},output[2]={0xa5,0xa5};DWORD capacity=1;
    OPGP_ERROR_STATUS status=GP211_check_R_MAC(command,sizeof(command),rejected,2,output,&capacity,&security);
    assert(OPGP_ERROR_CHECK(status)&&output[0]==0xa5&&output[1]==0xa5);cases++;
    capacity=2;status=GP211_check_R_MAC(command,sizeof(command),rejected,2,output,&capacity,&security);
    assert(!OPGP_ERROR_CHECK(status)&&capacity==2&&!memcmp(output,rejected,2));cases++;
    status=GP211_check_R_MAC(command,sizeof(command),rejected,2,output,NULL,&security);
    assert(OPGP_ERROR_CHECK(status));cases++;
    printf("crypto response bounds: %u cases passed\n",cases);
    return 0;
}
