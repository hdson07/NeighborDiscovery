#ifndef _ND_DAR_HDR
#define _ND_DAR_HDR


#include "c2500_if.h"
#include "ipv6/ipv6.h"
void nd_init_dac(void *pSAP);

void nd_send_dac(ip6_addr_t *dst);


#pragma pack(push,1)
typedef struct __nd_dac_t
{
    uint8_t status;
    uint8_t rsvd;
    uint16_t registration_lifetime;
    uint8_t eui64[8];
    ip6_addr_t registered_address;

}nd_dac_t;
#pragma pack(pop)

#endif
