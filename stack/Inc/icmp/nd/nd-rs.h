#ifndef _ND_RS_HDR
#define _ND_RS_HDR


#include "ipv6/ipv6.h"

void nd_send_rs(ip6_addr_t *dst);
void nd_init_rs(void *pSAP);

#pragma pack(push,1)
typedef struct __nd_rs_t
{
    uint32_t rsvd;
}nd_rs_t;
#pragma pack(pop)





#endif
