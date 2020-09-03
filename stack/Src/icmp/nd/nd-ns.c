#include "icmp/nd/nd-na.h"
#include "icmp/nd/nd-ns.h"
#include "icmp/nd/nd.h"
#include "icmp/nd/nd-ra.h"
#include "icmp/nd/nd-dar.h"

#include "icmp/icmp.h"
#include "ipv6/ipv6.h"
#include "rpl/rpl.h"

#define ND_NS_LOG(...)    {{dbg_print(0, 0, 0, __VA_ARGS__);}}
#define ND_NS_LOG_LN(...) {{dbg_print(0, 0, 1, __VA_ARGS__);}}


nd_ns_info_t nd_ns_info;

void nd_receive_ns(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint8_t code, uint16_t pkt_size, void *ptr);
void nd_send_ns_done(ip6_hdr_t *ip6_hdr, uint16_t pkt_id, uint8_t code, uint16_t pkt_size, uint8_t result, uint8_t *pkt, void *ptr);

nd_ns_info_t nd_ns_info;

void nd_init_ns(void *pSAP)
{
    icmp_register_sap_t icmp_register_sap;
    icmp_register_sap.type = icmp_type_neighbor_solicitation;
    icmp_register_sap.recv_callback = nd_receive_ns;
    icmp_register_sap.sent_callback = nd_send_ns_done;
    icmp_driver.register_type(&icmp_register_sap);
}


void nd_send_ns(ip6_addr_t *dst){

    uint16_t ND_NS_REQUIRED_LEN = 0;

    uint16_t ns_buf_len;
    uint8_t *ns_buf;

    ip6_hdr_t *ip6_hdr;

    ND_NS_REQUIRED_LEN = (sizeof(nd_ns_t) + sizeof(aro_t) + sizeof(sllao_t));

    ip6_hdr = (ip6_hdr_t *)icmp_driver.get_payload(&ns_buf_len,ND_NS_REQUIRED_LEN);
    ns_buf = ((icmp_hdr_t *)(ip6_hdr->payload))->payload;
    uint8_t *temp_ns_buf = ns_buf;

    nd_ns_t *ns = (nd_ns_t *)temp_ns_buf;
    temp_ns_buf = temp_ns_buf + sizeof(nd_ns_t);

    aro_t *aro = (aro_t *)temp_ns_buf;
    temp_ns_buf = temp_ns_buf + sizeof(aro_t);

    sllao_t *sllao = (sllao_t*)temp_ns_buf;
    temp_ns_buf = temp_ns_buf + sizeof(sllao_t);



    //configuration IPv6 address
    ns->rsvd = 0;
    ip6_addr_t ip6_prefix;
    uint8_t ip6_prefix_len;
    link_addr_t *link_addr = net_core_driver.get_linkaddr();
    ip6_driver.set_addr(&pio_info.prefix, pio_info.prefix_length, 0, 0);
    ip6_addr_t tentative_address;
    ip6_driver.get_global_addr(&tentative_address);

    //set tentative address 
    memcpy(&nd_ns_info.target_address, &tentative_address,sizeof(ip6_addr_t));
    memcpy(&ns->target_address,&nd_ns_info.target_address,sizeof(ip6_addr_t));



    aro->type = 33;
    aro->length = 2;
    aro->status = aro_info.status;
    aro->rsvd = 0;
    aro->rsvd2 = 0;
    aro->registration_lifetime = aro_info.registration_lifetime;
    memcpy(aro->eui64,aro_info.eui64,sizeof(aro_info.eui64));
    
    sllao->type = 1;
    sllao->length = 2;  

    memset(sllao->link_address,0,sizeof(sllao->link_address));
    memcpy(sllao->link_address,link_addr->addr,link_addr->len);
    

    ND_NS_LOG_LN("size = %d",ns_buf_len);

    ND_NS_LOG_LN("=================SEND-ND-NS==============");
    for (int i = 0; i < ns_buf_len; i++)
    {
        if (i%4 == 0)
        {
            ND_NS_LOG_LN("");
        }
        ND_NS_LOG("%02x ",*(ns_buf + i));

    }
    
    nd_send(dst,ns_buf,icmp_type_neighbor_solicitation,ns_buf_len,NULL);  
    
}

void nd_parse_ns(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint16_t pkt_size, void *ptr)
{
    uint8_t *ns_ext_buf = pkt;
    nd_ns_t *ns = (nd_ns_t*)ns_ext_buf;
    uint8_t ns_ext_len;

    ns_ext_buf = ns_ext_buf + sizeof(nd_ns_t);
    ns_ext_len = pkt_size - sizeof(nd_ns_t);
    aro_t *aro = (aro_t *)ns_ext_buf;

    memcpy(&nd_na_info.target_address,&ns->target_address,sizeof(nd_na_info.target_address));
    aro_info.registration_lifetime = aro->registration_lifetime;
    memcpy(aro_info.eui64,aro->eui64,sizeof(aro->eui64));
    

    ns_ext_buf = ns_ext_buf + sizeof(aro_t);
    ns_ext_len = pkt_size - sizeof(aro_t);
    sllao_t *sllao = (sllao_t *)ns_ext_buf;

    ND_NS_LOG_LN("=================RECV-ND-NS==============");
    for (int i = 0; i < pkt_size; i++)
    {
        if (i%4 == 0)
        {
            ND_NS_LOG_LN("");
        }
        ND_NS_LOG("%02x ",*(pkt + i));
    }
    ND_NS_LOG_LN("");
}



void nd_receive_ns(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint8_t code, uint16_t pkt_size, void *ptr)
{
    nd_parse_ns(ip6_hdr, pkt, pkt_size, ptr);

    if (nd_driver.is_root == 1)
    {
        //need to check tentative address in router table
        ND_NS_LOG_LN("ROOT) Check ECT");

        nd_driver.control(&ip6_hdr->src_address,icmp_type_neighbor_advertisement);
    }
    else
    {
        ND_NS_LOG_LN("NEED TO SEND DAR");

        //duplicated address detection to Root
        //sed dad info 
        //need to check, set that value in this file?? 
        //I think.... it is ambiguous mapping...
        //ns file connected with dar file... is it correct?



        nd_dad_info.registration_lifetime = aro_info.registration_lifetime;
        //ns src link address 
        memcpy(nd_dad_info.eui64,sllao_info.link_address,8);
        memcpy(&nd_dad_info.registered_address,&nd_na_info.target_address,sizeof(ip6_addr_t));
        nd_driver.control(&rpl_info.dodag_id,icmp_type_duplicate_address_request);
    }
       
}

void nd_send_ns_done(ip6_hdr_t *ip6_hdr, uint16_t pkt_id, uint8_t code, uint16_t pkt_size, uint8_t result, uint8_t *pkt, void *ptr)
{
    //If router can't receive na message within @@ times
    //retry autoconfiguration ipv6 address and send ns
}
