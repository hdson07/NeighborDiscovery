#include "icmp/nd/nd-rs.h"
#include "icmp/nd/nd.h"


#include "icmp/icmp.h"
#include "ipv6/ipv6.h"


#define ND_RS_LOG(...)    {{dbg_print(0, 0, 0, __VA_ARGS__);}}
#define ND_RS_LOG_LN(...) {{dbg_print(0, 0, 1, __VA_ARGS__);}}

uint8_t nd_rs_init_flag = 0;

void nd_parse_rs(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint16_t pkt_size, void *ptr);
void nd_receive_rs(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint8_t code, uint16_t pkt_size, void *ptr);
void nd_send_rs_done(ip6_hdr_t *ip6_hdr, uint16_t pkt_id, uint8_t code, uint16_t pkt_size, uint8_t result, uint8_t *pkt, void *ptr);

void nd_init_rs(void *pSAP)
{
    icmp_register_sap_t icmp_register_sap;
    icmp_register_sap.type = icmp_type_router_solicitation;
    icmp_register_sap.recv_callback = nd_receive_rs;
    icmp_register_sap.sent_callback = nd_send_rs_done;
    icmp_driver.register_type(&icmp_register_sap);
}

//receive eui64 
//c2500_info info;
//eui64 address = info.eui64




void nd_send_rs(ip6_addr_t *dst){
    ND_RS_LOG_LN("star rs send");

    uint16_t ND_RS_REQUIRED_LEN = 0;

    uint16_t rs_buf_len;
    uint8_t *rs_buf;

    ip6_hdr_t *ip6_hdr;

    ND_RS_REQUIRED_LEN = (sizeof(nd_rs_t) + sizeof(sllao_t));

    ip6_hdr = (ip6_hdr_t *)icmp_driver.get_payload(&rs_buf_len,ND_RS_REQUIRED_LEN);
    rs_buf = ((icmp_hdr_t *)(ip6_hdr->payload))->payload;
    uint8_t *temp_rs_buf = rs_buf;

    nd_rs_t *rs = (nd_rs_t *)temp_rs_buf;
    temp_rs_buf = temp_rs_buf + sizeof(nd_rs_t);

    sllao_t *sllao = (sllao_t*)temp_rs_buf;
    temp_rs_buf = temp_rs_buf + sizeof(sllao_t);


    rs->rsvd = 0;

    sllao->type = 1;
    sllao->length = 2;  

    link_addr_t *link_addr = net_core_driver.get_linkaddr();
    memset(sllao->link_address,0,sizeof(sllao->link_address));
    memcpy(sllao->link_address,link_addr->addr,link_addr->len);   
     ND_RS_LOG_LN("size = %d",rs_buf_len);
    ND_RS_LOG_LN("=================SEND-ND-RS==============");
    for (int i = 0; i < rs_buf_len; i++)
    {
        if (i%4 == 0)
        {
            ND_RS_LOG_LN("");
        }
        ND_RS_LOG("%02x ",*(rs_buf + i));

    }
    nd_send(dst,rs_buf,icmp_type_router_solicitation,rs_buf_len,NULL);  
}

void nd_send_rs_done(ip6_hdr_t *ip6_hdr, uint16_t pkt_id, uint8_t code, uint16_t pkt_size, uint8_t result, uint8_t *pkt, void *ptr)
{ 
    //TO DO
}

void nd_parse_rs(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint16_t pkt_size, void *ptr)
{
    uint8_t *rs_ext_buf = pkt;
    nd_rs_t *rs = (nd_rs_t*)rs_ext_buf;
    uint8_t rs_ext_len;


    ND_RS_LOG_LN("rs_rsvd : %08x",rs->rsvd);


    rs_ext_buf = rs_ext_buf + sizeof(nd_rs_t);
    rs_ext_len = pkt_size - sizeof(nd_rs_t);

    sllao_t *sllao = (sllao_t *)rs_ext_buf;

    memcpy(sllao_info.link_address,sllao->link_address,sizeof(sllao->link_address));
    


    ND_RS_LOG_LN("=================RECV-ND-RS==============");
    for (int i = 0; i < pkt_size; i++)
    {
        if (i%4 == 0)
        {
            ND_RS_LOG_LN("");
        }
        ND_RS_LOG("%02x ",*(pkt + i));

    }
}

void nd_receive_rs(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint8_t code, uint16_t pkt_size, void *ptr)
{
    nd_rs_t *rs = (nd_rs_t*)pkt;
    route_entry_t *entry;
    route_entry_t *dft_route;
    if ( nd_driver.on == 0 || nd_rs_init_flag) {
        return;
    }
    // Error:packet size is smaller than basic rs header
    if (pkt_size < sizeof(nd_rs_t))
    {
        return;
    }
    nd_parse_rs(ip6_hdr, pkt, pkt_size, ptr);
    nd_driver.control(&ip6_hdr->src_address,icmp_type_router_advertisement);
}

