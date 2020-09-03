#include "icmp/nd/nd-ra.h"
//#include "icmp/nd/nd-rs.h"

#include "icmp/nd/nd.h"

#include "icmp/icmp.h"
#include "ipv6/ipv6.h"

#define ND_RA_LOG(...)    {{dbg_print(0, 0, 0, __VA_ARGS__);}}
#define ND_RA_LOG_LN(...) {{dbg_print(0, 0, 1, __VA_ARGS__);}}

nd_ra_info_t nd_ra_info;

void nd_receive_ra(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint8_t code, uint16_t pkt_size, void *ptr);
void nd_send_ra_done(ip6_hdr_t *ip6_hdr, uint16_t pkt_id, uint8_t code, uint16_t pkt_size, uint8_t result, uint8_t *pkt, void *ptr);
void nd_init_ra(void *pSAP)
{
    //init RA option
    nd_ra_info.cur_hop_limit = ND_HOP_LIMIT; //need to check
    nd_ra_info.M = 0; 
    nd_ra_info.O = 0;
    nd_ra_info.reachable_time = 0; //need to check
    nd_ra_info.retrans_timer = 0; //need to check
    nd_ra_info.router_lifetime = 0xFFFF; //need to check

    icmp_register_sap_t icmp_register_sap;
    icmp_register_sap.type = icmp_type_router_advertisement;
    icmp_register_sap.recv_callback = nd_receive_ra;
    icmp_register_sap.sent_callback = nd_send_ra_done;
    icmp_driver.register_type(&icmp_register_sap);
}


void nd_send_ra(ip6_addr_t *dst){
    ND_RA_LOG_LN("start reply send ra");
    uint16_t ND_RA_REQUIRED_LEN = 0;

    uint16_t ra_buf_len;
    uint8_t *ra_buf;

    ip6_hdr_t *ip6_hdr;

    ND_RA_REQUIRED_LEN = (sizeof(nd_ra_t) + sizeof(pio_t) + sizeof(abro_t) + sizeof(sixco_t) + sizeof(sllao_t));


    ip6_hdr = (ip6_hdr_t *)icmp_driver.get_payload(&ra_buf_len,ND_RA_REQUIRED_LEN);
    ra_buf = ((icmp_hdr_t *)(ip6_hdr->payload))->payload;
    uint8_t *temp_ra_buf = ra_buf;

    nd_ra_t *ra = (nd_ra_t *)temp_ra_buf;
    temp_ra_buf = temp_ra_buf + sizeof(nd_ra_t);

    pio_t *pio = (pio_t*)temp_ra_buf;
    temp_ra_buf = temp_ra_buf + sizeof(pio_t);

    abro_t *abro = (abro_t*)temp_ra_buf;
    temp_ra_buf = temp_ra_buf + sizeof(abro_t);


    sixco_t *sixco = (sixco_t*)temp_ra_buf;
    temp_ra_buf = temp_ra_buf + sizeof(sixco_t);

    sllao_t *sllao = (sllao_t*)temp_ra_buf;
    temp_ra_buf = temp_ra_buf + sizeof(sllao_t);



    //info set from nd_init on Root
    //OR already set when receive RA from other router
    //need to check 
    //each valid time have to update by timer? then we need to assign that value from entry table rather than @@_info ???

    ra->cur_hop_limit = nd_ra_info.cur_hop_limit;
    ra->flag = 0;
    ra->flag |= nd_ra_info.M << ND_RA_M_SHIFT;
    ra->flag |= nd_ra_info.O << ND_RA_O_SHIFT;

    //nd_ra_info.router_lifetime = router table's lifetime
    ra->router_lifetime = nd_ra_info.router_lifetime;

    //alway 0?
    ra->reachable_time = nd_ra_info.reachable_time;    
    ra->retrans_timer = nd_ra_info.retrans_timer;

    //pio info
    pio->type = 3;
    pio->length = 4;

    //pio->prefix_length = from route table
    pio->prefix_length = pio_info.prefix_length;
    pio->valid_lifetime = pio_info.valid_lifetime;
    pio->preferred_lifetime = pio_info.preferred_lifetime;
    pio->rsvd2 = 0;
    memcpy(&pio->prefix,&pio_info.prefix,sizeof(ip6_hdr_t));

    pio->flag = 0;
    pio->flag |= pio_info.L << ND_PIO_L_SHIFT;
    pio->flag |= pio_info.A << ND_PIO_A_SHIFT;


    //same value with rpl_info.version
    abro->type = 0x23;
    abro->length = 3;
    abro->version_low = abro_info.version_low;
    abro->version_high = abro_info.version_high;
    abro->valid_lifetime = abro_info.valid_lifetime;
    memcpy(&abro->sixlbr_address,&abro_info.sixlbr_address,sizeof(ip6_hdr_t));
  
    //???????????????
    sixco->type = 0x22;
    sixco->length = 3;
    sixco->context_lenght = sixco_info.context_length;
    sixco->flag = 0;
    sixco->flag |= sixco_info.C << ND_6CO_C_SHIFT;
    sixco->flag |= sixco_info.CID << ND_6CO_CID_SHIFT;
    sixco->rsvd2 = 0;
    sixco->valid_lifetime = sixco_info.valid_lifetime;
    memcpy(&sixco->context_prefix,&sixco_info.context_prefix,sizeof(ip6_hdr_t));

    sllao->type = 1;
    sllao->length = 2;
    link_addr_t *link_addr = net_core_driver.get_linkaddr();
    memset(sllao->link_address,0,sizeof(sllao->link_address));
    memcpy(sllao->link_address,link_addr->addr,link_addr->len);
    

    ND_RA_LOG_LN("=================SEND-ND-RA==============");
    for (int i = 0; i < ra_buf_len; i++)
    {
        if (i%4 == 0)
        {
            ND_RA_LOG_LN("");
        }
        ND_RA_LOG("%02x ",*(ra_buf + i));

    }

    nd_send(dst,ra_buf,icmp_type_router_advertisement,ra_buf_len,NULL);  
}


void nd_parse_ra(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint16_t pkt_size, void *ptr)
{
    uint8_t *ra_ext_buf = pkt;
    nd_ra_t *ra = (nd_ra_t*)ra_ext_buf;
    uint8_t ra_ext_len;

    ra_ext_buf = ra_ext_buf + sizeof(nd_ra_t);
    ra_ext_len = pkt_size - sizeof(nd_ra_t);
    pio_t *pio = (pio_t*)ra_ext_buf;

    ra_ext_buf = ra_ext_buf + sizeof(pio_t);
    ra_ext_len = pkt_size - sizeof(pio_t);
    abro_t *abro = (abro_t*)ra_ext_buf;

    ra_ext_buf = ra_ext_buf + sizeof(abro_t);
    ra_ext_len = pkt_size - sizeof(abro_t);
    sixco_t *sixco = (sixco_t*)ra_ext_buf;

    ra_ext_buf = ra_ext_buf + sizeof(sixco_t);
    ra_ext_len = pkt_size - sizeof(sixco_t);
    sllao_t *sllao = (sllao_t*)ra_ext_buf;

    ra_ext_buf = ra_ext_buf + sizeof(sllao_t);
    ra_ext_len = pkt_size - sizeof(sllao_t);





    ND_RA_LOG_LN("=================RECV-ND-RA==============");
    for (int i = 0; i < pkt_size; i++)
    {
        if (i%4 == 0)
        {
            ND_RA_LOG_LN("");
        }
        ND_RA_LOG("%02x ",*(pkt + i));

    }
    ND_RA_LOG_LN("sixco_flag : %02x",sixco->flag);
    ND_RA_LOG_LN("version low : %02x",abro->version_low);
    ND_RA_LOG_LN("version high : %02x",abro->version_high);
    if((nd_driver.is_root == 0 )
        && ((pio->flag & ND_PIO_L_MASK ) >> ND_PIO_L_SHIFT == 1))
    {
        ND_RA_LOG_LN("ASSIGHN Router option ");
        
        //recv pio_opition
        // pio_info.L = ( pio->flag & ND_PIO_L_MASK ) >> ND_PIO_L_SHIFT;
        pio_info.A = ( pio->flag & ND_PIO_A_MASK ) >> ND_PIO_A_SHIFT;
        pio_info.valid_lifetime = pio->valid_lifetime;
        pio_info.preferred_lifetime = pio->preferred_lifetime;
        memcpy(&pio_info.prefix,&pio->prefix,sizeof(ip6_addr_t));
        pio_info.prefix_length = pio->prefix_length;
        
        //recv abro_opiton
        abro_info.version_low = abro->version_low;
        abro_info.version_high = abro->version_high;
        abro_info.valid_lifetime = abro->valid_lifetime;
        memcpy(&abro_info.sixlbr_address,&abro->sixlbr_address,sizeof(ip6_addr_t));
        
        //recv sixco option
        sixco_info.context_length = sixco->context_lenght;
        sixco_info.C = (sixco->flag & ND_6CO_C_MASK) >> ND_6CO_C_SHIFT;
        sixco_info.CID = (sixco->flag & ND_6CO_CID_MASK) >> ND_6CO_CID_SHIFT;
        sixco_info.valid_lifetime = sixco->valid_lifetime;
        memcpy(&sixco_info.context_prefix,&sixco->context_prefix,sizeof(ip6_addr_t));
        nd_driver.control(&ip6_hdr->src_address,icmp_type_neighbor_solicitation);
    }
    else
    {
        ND_RA_LOG_LN("That router is not on-link");
    }
}

void nd_receive_ra(ip6_hdr_t *ip6_hdr, uint8_t *pkt, uint8_t code, uint16_t pkt_size, void *ptr)
{
    nd_parse_ra(ip6_hdr, pkt, pkt_size, ptr);

    

}

void nd_send_ra_done(ip6_hdr_t *ip6_hdr, uint16_t pkt_id, uint8_t code, uint16_t pkt_size, uint8_t result, uint8_t *pkt, void *ptr)
{
    //TO DO
}