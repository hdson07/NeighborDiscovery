#include "icmp/nd/nd-dac.h"
#include "icmp/nd/nd-dar.h"
#include "icmp/nd/nd.h"

#include "icmp/icmp.h"
#include "ipv6/route-table.h"

#define ND_DAR_LOG(...)    {{dbg_print(0, 0, 0, __VA_ARGS__);}}
#define ND_DAR_LOG_LN(...) {{dbg_print(0, 0, 1, __VA_ARGS__);}}

void nd_receive_dar(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint8_t code, uint16_t pkt_size, void *ptr);

void nd_send_dar_done(ip6_hdr_t *ip6_hdr, uint16_t pkt_id, uint8_t code, uint16_t pkt_size, uint8_t result, uint8_t *pkt, void *ptr);


void nd_init_dar(void *pSAP)
{
    icmp_register_sap_t icmp_register_sap;
    icmp_register_sap.type = icmp_type_duplicate_address_request;
    icmp_register_sap.recv_callback = nd_receive_dar;
    icmp_register_sap.sent_callback = nd_send_dar_done;
    icmp_driver.register_type(&icmp_register_sap);   

}



void nd_send_dar(ip6_addr_t *dst){
    ND_DAR_LOG_LN("star ns send");

    uint16_t ND_DAR_REQUIRED_LEN = 0;

    uint16_t dar_buf_len;
    uint8_t *dar_buf;

    ip6_hdr_t *ip6_hdr;

    ND_DAR_REQUIRED_LEN = (sizeof(nd_dar_t));

    ip6_hdr = (ip6_hdr_t *)icmp_driver.get_payload(&dar_buf_len,ND_DAR_REQUIRED_LEN);
    dar_buf = ((icmp_hdr_t *)(ip6_hdr->payload))->payload;
    uint8_t *temp_dar_buf = dar_buf;

    nd_dar_t *dar = (nd_dar_t *)temp_dar_buf;
    temp_dar_buf = temp_dar_buf + sizeof(nd_dar_t);

    //updated from ns
    dar->status = 0;
    dar->rsvd = 0;
    dar->registration_lifetime = nd_dad_info.registration_lifetime;
    memcpy(&dar->registered_address, &nd_dad_info.registered_address,sizeof(ip6_addr_t));
    memcpy(dar->eui64, nd_dad_info.eui64,sizeof(nd_dad_info.eui64));

    ND_DAR_LOG_LN("size = %d",dar_buf_len);

    ND_DAR_LOG_LN("=================SEND-ND-DAR==============");
    for (int i = 0; i < dar_buf_len; i++)
    {
        if (i%4 == 0)
        {
            ND_DAR_LOG_LN("");
        }
        ND_DAR_LOG("%02x ",*(dar_buf + i));

    }
    
    nd_send(dst,dar_buf,icmp_type_duplicate_address_request,dar_buf_len,NULL);  
    
}

void nd_parse_dar(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint16_t pkt_size, void *ptr)
{
    uint8_t *dar_ext_buf = pkt;
    nd_dar_t *dar = (nd_dar_t*)dar_ext_buf;
    uint8_t dar_ext_len;

    dar_ext_buf = dar_ext_buf + sizeof(nd_dar_t);
    dar_ext_len = pkt_size - sizeof(nd_dar_t);

    nd_dad_info.registration_lifetime = dar->registration_lifetime;
    memcpy(&nd_dad_info.registered_address,&dar->registered_address,sizeof(ip6_addr_t));
    memcpy(&nd_dad_info.eui64,&dar->eui64,sizeof(dar->eui64));
     

    ND_DAR_LOG_LN("=================RECV-ND-DAR==============");
    for (int i = 0; i < pkt_size; i++)
    {
        if (i%4 == 0)
        {
            ND_DAR_LOG_LN("");
        }
        ND_DAR_LOG("%02x ",*(pkt + i));
    }
    ND_DAR_LOG_LN("");

}


void nd_receive_dar(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint8_t code, uint16_t pkt_size, void *ptr)
{
    if (nd_driver.is_root == 0)
    {
        return;
    }
    
    nd_parse_dar(ip6_hdr, pkt, pkt_size, ptr);

    
    //************need to check duplicated address **************
    nd_driver.control(&ip6_hdr->src_address,icmp_type_duplicate_address_confirmation);
}

void nd_send_dar_done(ip6_hdr_t *ip6_hdr, uint16_t pkt_id, uint8_t code, uint16_t pkt_size, uint8_t result, uint8_t *pkt, void *ptr)
{
    //TO DO
}