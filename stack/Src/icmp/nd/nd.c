#include "icmp/nd/nd.h"

#include "icmp/nd/nd-rs.h"
#include "icmp/nd/nd-ra.h"
#include "icmp/nd/nd-ns.h"
#include "icmp/nd/nd-na.h"
#include "icmp/nd/nd-dar.h"
#include "icmp/nd/nd-dac.h"

#include "ipv6/ipv6.h"
#include "ipv6/route-table.h"
#include "icmp/icmp.h"
#include "rpl/rpl.h"

#include "6lowpan/6lowpan.h"

#include "icmp/icmp.h"


#define ND_LOG(...)    dbg_print(0, 0, 0, __VA_ARGS__)
#define ND_LOG_LN(...) dbg_print(0, 0, 1, __VA_ARGS__)

void nd_init(void *pSAP);
void nd_receive(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint8_t code, uint16_t pkt_size, void *ptr);
void nd_send_done(ip6_hdr_t *ip6_hdr, uint16_t pkt_id, uint8_t code, uint16_t pkt_size, uint8_t result, uint8_t *pkt, void *ptr);

void nd_sent_meta_event(ip6_addr_t* ip6_addr, void * ptr);
void nd_recv_meta_event(ip6_addr_t* ip6_addr, void * ptr);

void nd_control(ip6_addr_t* dst, uint8_t type);

nd_info_t nd_info;
sllao_info_t sllao_info;
pio_info_t pio_info;
sixco_info_t sixco_info;
abro_info_t abro_info;
aro_info_t aro_info;

nd_driver_t nd_driver = {
 	.name 	 = "ND",
	.init 	 = nd_init,
    .control = nd_control,
};

// xTimerHandle nd_router_life_timer;

void nd_init(void *pSAP){

    //init icmp & nd
    nd_init_sap_t *nd_init_sap;
    icmp_init_sap_t *icmp_sap;
    icmp_register_sap_t icmp_register_sap;

    ip6_register_meta_t reg_meta_ev;
    nd_init_sap = (nd_init_sap_t*)pSAP;
    nd_driver.is_root = nd_init_sap->is_root;

    //ND had been init
    if (nd_driver.on == 1)
    {
        return;
    }
    nd_init_sap = (nd_init_sap_t *)pSAP;
    
    icmp_sap->id_nd = 1;
    icmp_driver.init(&icmp_sap);


    //Root init - set all ND info, RPL - Root  init
    memset(&nd_info,0,sizeof(nd_info_t));
    if(nd_driver.is_root == 1)
    {
        ND_LOG_LN("INIT ND ROOT");

        ip6_addr_t ip6_prefix;
        uint8_t ip6_prefix_len;

        link_addr_t *link_addr;
        link_addr = net_core_driver.get_linkaddr();


        ip6_driver.pton6(IP6_PREFIX, &ip6_prefix, &ip6_prefix_len);
        ip6_driver.set_addr(&ip6_prefix, ip6_prefix_len, 0, 0);

        //set sllao option
        memset(sllao_info.link_address,0,sizeof(sllao_info.link_address));
        memcpy(sllao_info.link_address,link_addr->addr,link_addr->len);
        
        
        //set pio option
        pio_info.L = 1;     // root init on-link flag
        pio_info.A = 1;
        ip6_driver.pton6(IP6_PREFIX,&pio_info.prefix,&pio_info.prefix_length);
        pio_info.valid_lifetime = ND_INFINITE_LIFETIME; //need to check
        pio_info.preferred_lifetime = ND_INFINITE_LIFETIME; //need to check
        

        //set abro_opiton
        abro_info.version_low = 0x5CD8; //need to check
        abro_info.version_high = 0x5D27; //need to check
        abro_info.valid_lifetime = 0xFFFF; //need to check
        ip6_driver.get_global_addr(&abro_info.sixlbr_address); //need to check
 
        
        //set sixco_option
        sixco_info.context_length = 0x80; //need to check
        sixco_info.C = 1;
        sixco_info.CID = sixlowpan_driver.get_context_id(&(sixco_info.context_prefix)); //need to check , get_context_id function hs error
        memcpy(&sixco_info.context_prefix,&ip6_prefix,sizeof(ip6_addr_t));//need to check
        sixco_info.valid_lifetime = 0xFFFF; //need to check

        //set aro_option
        aro_info.status = 0;
        aro_info.registration_lifetime = ND_DEFAULT_LIFETIME; //need to check
        memcpy(aro_info.eui64,link_addr->addr,link_addr->len);

        nd_rpl_init(1);

    }
    else
    {
    //Node init - set basic ND info ( ARO, sllao) and pio_flag 
        ND_LOG_LN("INIT ND NODE");
        link_addr_t *link_addr = net_core_driver.get_linkaddr();

        //set sllao option
        memset(sllao_info.link_address,0,sizeof(sllao_info.link_address));
        memcpy(sllao_info.link_address,link_addr->addr,link_addr->len);
        
        //set pio option
        pio_info.L = 0;
        pio_info.A = 1;        

        //set aro_option
        aro_info.status = 0;
        aro_info.registration_lifetime = ND_DEFAULT_LIFETIME;
        memcpy(aro_info.eui64,link_addr->addr,link_addr->len);
    }


    //whas is the purpose of this code, such as reg_meta_ev ans rpl_recv_meta_event ? 
    reg_meta_ev.meta_recv_event = nd_recv_meta_event;
    reg_meta_ev.meta_sent_event = nd_sent_meta_event;
    ip6_driver.register_meta_event(&reg_meta_ev);
    
    nd_driver.on = 1;

    nd_init_ns(nd_init_sap);
    nd_init_na(nd_init_sap);
    nd_init_rs(nd_init_sap);
    nd_init_ra(nd_init_sap);
    nd_init_dar(nd_init_sap);
    nd_init_dac(nd_init_sap);

    
    
}

uint8_t nd_send(ip6_addr_t *dst, uint8_t *pkt, uint8_t type, uint16_t pkt_size, void *ptr)
{
    return icmp_driver.send(dst, pkt, type, 0, pkt_size, ptr);
}
// void nd_parent_remove_timer_fired(xTimerHandle pxTimer);

void nd_receive(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint8_t code, uint16_t pkt_size, void *ptr)
{
    //TO DO
}

void nd_send_done(ip6_hdr_t *ip6_hdr, uint16_t pkt_id, uint8_t code, uint16_t pkt_size, uint8_t result, uint8_t *pkt, void *ptr)
{
    //TO DO
}

void nd_sent_meta_event(ip6_addr_t* ip6_addr, void * ptr){
    //TO DO
}
void nd_recv_meta_event(ip6_addr_t* ip6_addr, void * ptr){
    //TO DO
}

void  nd_control(ip6_addr_t* dst, uint8_t type){
    switch (type)
    {
    case icmp_type_router_solicitation:
        nd_send_rs(dst);
        break;
    case icmp_type_router_advertisement:
        nd_send_ra(dst);
        break;
    case icmp_type_neighbor_solicitation:
        nd_send_ns(dst);
        break;
    case icmp_type_neighbor_advertisement:
        nd_send_na(dst);
        break;
    case icmp_type_duplicate_address_request:
        nd_send_dar(dst);
        break;
    case icmp_type_duplicate_address_confirmation:
        nd_send_dac(dst);
        break;
    default:
        break;
    }
}

void nd_rpl_init(uint8_t is_root){
    rpl_init_sap_t rpl_init_sap;
    if (is_root == 0)
    {
        rpl_init_sap.is_root = 0;
    }
    else
    {
        rpl_init_sap.is_root = 1;
    }
    
    
    rpl_init_sap.send_dis = 1;
    rpl_driver.init(&rpl_init_sap);
}
