#ifndef _ND_HDR
#define _ND_HDR

#include "ipv6/ipv6.h"
#include "net-config/net-core.h" // receive prefix on root
#include "ipv6/route-table.h" //valid router lifetime info
#include "c2500_if.h"



#ifndef ND_DEFAULT_LIFETIME
#define ND_DEFAULT_LIFETIME 0x04B0
#endif

#ifndef ND_INFINITE_LIFETIME
#define ND_INFINITE_LIFETIME 0xFFFFFFFF
#endif






void nd_init(void *pSAP);
uint8_t nd_send(ip6_addr_t *dst, uint8_t *pkt, uint8_t type, uint16_t pkt_size, void *ptr);

void nd_rpl_init(uint8_t is_root);
#pragma pack(push,1)
typedef struct __sllao_t
{
    uint8_t  type;
    uint8_t  length;
    uint8_t link_address[14];
}sllao_t;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct __aro_t
{
    uint8_t  type;
    uint8_t  length;
    uint8_t status;
    uint8_t rsvd;
    uint16_t rsvd2;
    uint16_t registration_lifetime;
    uint8_t eui64[8];
}aro_t;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct __abro_t
{
    uint8_t  type;
    uint8_t  length;
    uint16_t version_low;
    uint16_t version_high;
    uint16_t valid_lifetime;
    ip6_addr_t sixlbr_address;
}abro_t;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct __sixco_t
{
    uint8_t type;
    uint8_t length;
    uint8_t context_lenght;
    uint8_t flag;
    uint16_t rsvd2;
    uint16_t valid_lifetime;
    ip6_addr_t context_prefix;
}sixco_t;
#pragma pack(pop)

#define ND_6CO_C_MASK 0x10
#define ND_6CO_C_SHIFT 4
#define ND_6CO_CID_MASK 0x0F
#define ND_6CO_CID_SHIFT 3
#define ND_6CO_RSVD_MASK 0xE0
#define ND_6CO_RSVD_SHIFT 7
    // 6co->rsvd1 = 0;
    // 6co->rsvd1 |= (1 << ND_6CO_C_SHIFT);//4
    // 6co->rsvd1 |= (1 << ND_6CO_CID_SHIFT);//5


    
#pragma pack(push,1)
typedef struct __pio_t
{
    uint8_t type;
    uint8_t length;
    uint8_t prefix_length;
    uint8_t flag;
    uint32_t valid_lifetime;
    uint32_t preferred_lifetime;
    uint32_t rsvd2;
    ip6_addr_t prefix;
}pio_t;
#pragma pack(pop)

#define ND_PIO_L_MASK 0x80
#define ND_PIO_L_SHIFT 7
#define ND_PIO_A_MASK 0x40
#define ND_PIO_A_SHIFT 6
#define ND_PIO_RSVD_MASK 0xF
#define ND_PIO_RSVD_SHIFT 5
    // pio->rsvd1 = 0;
    // pio->rsvd1 |= (0 << ND_PIO_L_SHIFT);//1
    // pio->rsvd1 |= (1 << ND_PIO_A_SHIFT);//2

/**
 * The structure of a ND driver.
 */
typedef struct __nd_driver_t {
	char *name;
	
	uint8_t on;
    
    uint8_t is_root;
	
	/** Initialize the ND driver */
    /*
     * return : void
     * parameters : 
     *    pSAP - ND_init_sap_t;sent/recv callback function pointers
     */
	void (* init)(void *pSAP);

	/** Control the RPL driver */
    /*
     * return : result value
     * parameters : 
     *      cmd - command number
     *      arg - arguments
     *    value - extra value
     */
	// int (* control)(int cmd, void *arg, uint32_t value);
    void (* control)(ip6_addr_t *dst, uint8_t type);
} nd_driver_t;

#pragma pack(push, 1)
typedef struct __nd_init_sap_t {
    uint8_t is_root;
} nd_init_sap_t;
#pragma pack(pop)

typedef struct __nd_info_t{
    uint16_t cur_hop_limit;
    uint8_t M;
    uint8_t O;
    uint16_t router_lifetime;
    uint32_t rechable_time;
    uint32_t retrans_timer;
    uint32_t valid_lifetime;
    uint32_t preferred_lifetime;
    ip6_addr_t prefix;
    uint8_t prefix_length;
    uint8_t L;
    uint8_t A;
    uint8_t context_length;
    uint8_t C;
    uint8_t CID;
    ip6_addr_t context_prefix;
    uint16_t version_low;
    uint16_t version_high;
    uint16_t context_valid_lifetime;
    ip6_addr_t sixlbr_address;
    uint16_t registration_lifetime;
    uint8_t link_address[14];
    uint8_t eui64[16];
    uint8_t R;
    uint8_t S;
    ip6_addr_t target_address;
}nd_info_t;

#pragma pack(push, 1)
typedef struct __sllao_info_t{
    uint8_t link_address[14];    
}sllao_info_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct __pio_info_t{
    uint8_t prefix_length;
    uint8_t L;
    uint8_t A;
    uint32_t valid_lifetime;
    uint32_t preferred_lifetime;
    ip6_addr_t prefix;
}pio_info_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct __sixco_info_t{
    uint8_t context_length;
    uint8_t C;
    uint8_t CID;
    uint16_t valid_lifetime;
    ip6_addr_t context_prefix;
}sixco_info_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct __abro_info_t{
    uint16_t version_low;
    uint16_t version_high;
    uint16_t valid_lifetime;
    ip6_addr_t sixlbr_address;
}abro_info_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct __aro_info_t{
    uint8_t status;
    uint16_t registration_lifetime;
    uint8_t eui64[8];
}aro_info_t;
#pragma pack(pop)


extern sllao_info_t sllao_info;
extern pio_info_t pio_info;
extern sixco_info_t sixco_info;
extern abro_info_t abro_info;
extern aro_info_t aro_info;
extern nd_info_t nd_info;
extern nd_driver_t nd_driver;


#endif
