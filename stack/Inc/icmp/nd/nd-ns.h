#ifndef _ND_NS_HDR
#define _ND_NS_HDR


#include "ipv6/ipv6.h"
void nd_send_ns(ip6_addr_t *dst);
void nd_init_ns(void *pSAP);

#pragma pack(push,1)
typedef struct __nd_ns_t
{
    uint32_t rsvd;
    ip6_addr_t target_address;
}nd_ns_t;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct __nd_ns_info_t
{
    ip6_addr_t target_address;
}nd_ns_info_t;
#pragma pack(pop)

extern nd_ns_info_t nd_ns_info;



#endif
