#include "icmp/nd/nd-dac.h"
#include "icmp/nd/nd-dar.h"
#include "icmp/nd/nd.h"
#include "icmp/nd/nd-na.h"

#include "icmp/icmp.h"

#define ND_DAC_LOG(...)    {{dbg_print(0, 0, 0, __VA_ARGS__);}}
#define ND_DAC_LOG_LN(...) {{dbg_print(0, 0, 1, __VA_ARGS__);}}
void nd_receive_dac(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint8_t code, uint16_t pkt_size, void *ptr);

void nd_send_dac_done(ip6_hdr_t *ip6_hdr, uint16_t pkt_id, uint8_t code, uint16_t pkt_size, uint8_t result, uint8_t *pkt, void *ptr);
nd_dad_info_t nd_dad_info;

void nd_init_dac(void *pSAP)
{
    icmp_register_sap_t icmp_register_sap;
    icmp_register_sap.type = icmp_type_duplicate_address_confirmation;
    icmp_register_sap.recv_callback = nd_receive_dac;
    icmp_register_sap.sent_callback = nd_send_dac_done;
    icmp_driver.register_type(&icmp_register_sap);
}

void nd_send_dac(ip6_addr_t *dst){
    ND_DAC_LOG_LN("star ns send");

    uint16_t ND_DAC_REQUIRED_LEN = 0;

    uint16_t dac_buf_len;
    uint8_t *dac_buf;

    ip6_hdr_t *ip6_hdr;

    ND_DAC_REQUIRED_LEN = (sizeof(nd_dac_t));

    ip6_hdr = (ip6_hdr_t *)icmp_driver.get_payload(&dac_buf_len,ND_DAC_REQUIRED_LEN);
    dac_buf = ((icmp_hdr_t *)(ip6_hdr->payload))->payload;
    uint8_t *temp_dac_buf = dac_buf;

    nd_dac_t *dac = (nd_dac_t *)temp_dac_buf;
    temp_dac_buf = temp_dac_buf + sizeof(nd_dac_t);

    //lookup route table & compare ipv6 address & link address 
    if(0) 
    //(memcpy(&nd_dad_info.registered_address,&nd_dad_info.registered_address,sizeof(ip6_addr_t)));
    {
        dac->status = 1;
        //pass
    }
    else
    {
        dac->status = 0;
        // add route table 
    }

    //dad info updated when router received dar
    dac->rsvd = 0;
    dac->registration_lifetime = nd_dad_info.registration_lifetime;
    memcpy(&dac->registered_address, &nd_dad_info.registered_address,sizeof(ip6_addr_t));
    memcpy(dac->eui64, nd_dad_info.eui64,sizeof(nd_dad_info.eui64));
   
    ND_DAC_LOG_LN("size = %d",dac_buf_len);

    ND_DAC_LOG_LN("=================SEND-ND-DAC==============");
    for (int i = 0; i < dac_buf_len; i++)
    {
        if (i%4 == 0)
        {
            ND_DAC_LOG_LN("");
        }
        ND_DAC_LOG("%02x ",*(dac_buf + i));

    }
    nd_send(dst,dac_buf,icmp_type_duplicate_address_confirmation,dac_buf_len,NULL);  
}

void nd_parse_dac(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint16_t pkt_size, void *ptr)
{
    uint8_t *dac_ext_buf = pkt;
    nd_dac_t *dac = (nd_dac_t*)dac_ext_buf;
    uint8_t dac_ext_len;

    dac_ext_buf = dac_ext_buf + sizeof(nd_dac_t);
    dac_ext_len = pkt_size - sizeof(nd_dac_t);

    nd_dad_info.registration_lifetime = dac->registration_lifetime;
    nd_dad_info.status = dac->status;
    memcpy(&nd_dad_info.registered_address,&dac->registered_address,sizeof(ip6_addr_t));
    memcpy(&nd_dad_info.eui64,&dac->eui64,sizeof(dac->eui64));

    ND_DAC_LOG_LN("=================RECV-ND-DAC==============");
    for (int i = 0; i < pkt_size; i++)
    {
        if (i%4 == 0)
        {
            ND_DAC_LOG_LN("");
        }
        ND_DAC_LOG("%02x ",*(pkt + i));
    }
    ND_DAC_LOG_LN("");
}

void nd_receive_dac(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint8_t code, uint16_t pkt_size, void *ptr)
{
    nd_parse_dac(ip6_hdr, pkt, pkt_size, ptr);
    if (nd_dad_info.status == 0)
    {
        ip6_addr_t *dst;
        memset(dst, 0, sizeof(ip6_addr_t));
        dst->s6_addr16[0] = htons(0xfe80);
        
        for(int i = 0; i < 8; i++)
        {
            dst->s6_addr[8+i] = sllao_info.link_address[i];
        }
        dst->s6_addr[8] ^= 0x2;
        nd_driver.control(dst,icmp_type_neighbor_advertisement);
        //There is no duplicate address 
        //add info to router table 
        // nd_send_na(nd_dad_info.eui64);
        
    }else
    {
        ND_DAC_LOG_LN("ARO ERROR)) Duplicated Address Dectied!");
    }
}

void nd_send_dac_done(ip6_hdr_t *ip6_hdr, uint16_t pkt_id, uint8_t code, uint16_t pkt_size, uint8_t result, uint8_t *pkt, void *ptr)
{
    //TO DO
}