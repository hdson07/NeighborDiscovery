#ifndef _ND_DAC_HDR
#define _ND_DAC_HDR


#include "c2500_if.h"
#include "ipv6/ipv6.h"
void nd_init_dar(void *pSAP);
void nd_send_dar(ip6_addr_t *dst);

#pragma pack(push,1)
typedef struct __nd_dar_t
{
    uint8_t status;
    uint8_t rsvd;
    uint16_t registration_lifetime;
    uint8_t eui64[8];
    ip6_addr_t registered_address;

}nd_dar_t;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct __nd_dad_info_t
{
    uint8_t status;
    uint16_t registration_lifetime;
    uint8_t eui64[8];
    ip6_addr_t registered_address;
}nd_dad_info_t;
#pragma pack(pop)

extern nd_dad_info_t nd_dad_info;

#endif
