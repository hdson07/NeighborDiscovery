#ifndef _ND_NA_HDR
#define _ND_NA_HDR


#include "ipv6/ipv6.h"
void nd_init_na(void *pSAP);
void nd_send_na(ip6_addr_t *dst);

#pragma pack(push,1)
typedef struct __nd_na_t
{
    uint8_t flag;
    uint8_t rsvd;
    uint16_t rsvd2;
    ip6_addr_t target_address;
}nd_na_t;
#pragma pack(pop)

#define ND_NA_R_MASK 0x80
#define ND_NA_R_SHIFT 7
#define ND_NA_S_MASK 0x40
#define ND_NA_S_SHIFT 6
#define ND_NA_O_MASK 0x20
#define ND_NA_O_SHIFT 5

#pragma pack(push,1)
typedef struct __nd_na_info_t
{
    uint8_t R;
    uint8_t S;
    uint8_t O;
    ip6_addr_t target_address;
}nd_na_info_t;
#pragma pack(pop)

extern nd_na_info_t nd_na_info;

#endif
