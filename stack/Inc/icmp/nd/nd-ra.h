#ifndef _ND_RA_HDR
#define _ND_RA_HDR


#include "ipv6/ipv6.h"
#include "ipv6/route-table.h" //valid router lifetime info
void nd_init_ra(void *pSAP);
void nd_send_ra(ip6_addr_t *dst);

#ifndef ND_HOP_LIMIT
#define ND_HOP_LIMIT 0xFF
#endif

#pragma pack(push,1)
typedef struct __nd_ra_t
{
    uint8_t cur_hop_limit;
    uint8_t flag;
    uint16_t router_lifetime;
    uint32_t reachable_time;
    uint32_t retrans_timer;
}nd_ra_t;
#pragma pack(pop)

#define ND_RA_M_MASK 0x80
#define ND_RA_M_SHIFT 7
#define ND_RA_O_MASK 0x40
#define ND_RA_O_SHIFT 6
#define ND_RA_RSVD_MASK 0xF
#define ND_RA_RSVD_SHIFT 5

#pragma pack(push,1)
typedef struct __nd_ra_info_t
{
    uint8_t cur_hop_limit;
    uint8_t M;
    uint8_t O;
    uint32_t router_lifetime;
    uint32_t reachable_time;
    uint32_t retrans_timer;
}nd_ra_info_t;
#pragma pack(pop)

extern nd_ra_info_t nd_ra_info;




#endif
