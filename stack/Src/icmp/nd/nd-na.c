#include "icmp/nd/nd-na.h"
#include "icmp/nd/nd-ns.h"
#include "icmp/nd/nd.h"

#include "icmp/icmp.h"

#define ND_NA_LOG(...)    {{dbg_print(0, 0, 0, __VA_ARGS__);}}
#define ND_NA_LOG_LN(...) {{dbg_print(0, 0, 1, __VA_ARGS__);}}

void nd_receive_na(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint8_t code, uint16_t pkt_size, void *ptr);
void nd_send_na_done(ip6_hdr_t *ip6_hdr, uint16_t pkt_id, uint8_t code, uint16_t pkt_size, uint8_t result, uint8_t *pkt, void *ptr);

nd_na_info_t nd_na_info;

void nd_init_na(void *pSAP)
{   
    nd_na_info.R = 1;
    nd_na_info.S = 1;
    nd_na_info.O = 1;
    icmp_register_sap_t icmp_register_sap;
    icmp_register_sap.type = icmp_type_neighbor_advertisement;
    icmp_register_sap.recv_callback = nd_receive_na;
    icmp_register_sap.sent_callback = nd_send_na_done;
    icmp_driver.register_type(&icmp_register_sap);
}

void nd_send_na(ip6_addr_t *dst)
{

    uint16_t ND_NA_REQUIRED_LEN = 0;

    uint16_t na_buf_len;
    uint8_t *na_buf;



    ip6_hdr_t *ip6_hdr;

    ND_NA_REQUIRED_LEN = (sizeof(nd_na_t) + sizeof(aro_t) + sizeof(sllao_t));

    ip6_hdr = (ip6_hdr_t *)icmp_driver.get_payload(&na_buf_len,ND_NA_REQUIRED_LEN);
    na_buf = ((icmp_hdr_t *)(ip6_hdr->payload))->payload;
    uint8_t *temp_na_buf = na_buf;

    nd_na_t *na = (nd_na_t *)temp_na_buf;
    temp_na_buf = temp_na_buf + sizeof(nd_na_t);

    aro_t *aro = (aro_t *)temp_na_buf;
    temp_na_buf = temp_na_buf + sizeof(aro_t);

    sllao_t *sllao = (sllao_t*)temp_na_buf;
    temp_na_buf = temp_na_buf + sizeof(sllao_t);




    na->flag = 0;
    na->flag |= nd_na_info.R << ND_NA_R_SHIFT;
    na->flag |= nd_na_info.S << ND_NA_S_SHIFT;
    na->flag |= nd_na_info.O << ND_NA_O_SHIFT;
    na->rsvd = 0;
    na->rsvd2 = 0;
    memcpy(&na->target_address,&nd_na_info.target_address,sizeof(ip6_hdr_t));

    aro->type = 33;
    aro->length = 2;
    aro->status = aro_info.status;
    aro->rsvd = 0;
    aro->rsvd2 = 0;
    aro->registration_lifetime = aro_info.registration_lifetime;
    memcpy(aro->eui64,aro_info.eui64,sizeof(aro_info.eui64));
    
    sllao->type = 1;
    sllao->length = 2;  
    link_addr_t *link_addr = net_core_driver.get_linkaddr();
    memset(sllao->link_address,0,sizeof(sllao->link_address));
    memcpy(sllao->link_address,link_addr->addr,link_addr->len);
    

    ND_NA_LOG_LN("size = %d",na_buf_len);

    ND_NA_LOG_LN("=================SEND-ND-NA==============");
    for (int i = 0; i < na_buf_len; i++)
    {
        if (i%4 == 0)
        {
            ND_NA_LOG_LN("");
        }
        ND_NA_LOG("%02x ",*(na_buf + i));

    }
    
    nd_send(dst,na_buf,icmp_type_neighbor_advertisement,na_buf_len,NULL);  
    

}

void nd_parse_na(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint16_t pkt_size, void *ptr)
{
    uint8_t *na_ext_buf = pkt;
    nd_na_t *na = (nd_na_t*)na_ext_buf;
    uint8_t na_ext_len;

    na_ext_buf = na_ext_buf + sizeof(nd_na_t);
    na_ext_len = pkt_size - sizeof(nd_na_t);
    aro_t *aro = (aro_t *)na_ext_buf;



    na_ext_buf = na_ext_buf + sizeof(aro_t);
    na_ext_len = pkt_size - sizeof(aro_t);
    sllao_t *sllao = (sllao_t *)na_ext_buf;

    ND_NA_LOG_LN("=================RECV-ND-NA==============");
    for (int i = 0; i < pkt_size; i++)
    {
        if (i%4 == 0)
        {
            ND_NA_LOG_LN("");
        }
        ND_NA_LOG("%02x ",*(pkt + i));
    }
    ND_NA_LOG_LN("");

 
}



void nd_receive_na(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint8_t code, uint16_t pkt_size, void *ptr)
{
    pio_info.L = 1;
    nd_parse_na(ip6_hdr, pkt, pkt_size, ptr);
    nd_rpl_init(0);
}

void nd_send_na_done(ip6_hdr_t *ip6_hdr, uint16_t pkt_id, uint8_t code, uint16_t pkt_size, uint8_t result, uint8_t *pkt, void *ptr)
{
    //TO DO
}