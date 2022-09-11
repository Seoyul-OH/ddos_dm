/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define ETHERTYPE_IPV4 0x0800
#define PROTOCOL_DDOSDM 0xFD

#define MAX_DDoS_SIZE 131072
#define DDoS_threshold 2
#define TOP 8192
#define DROP_PERCENT 30 /* Value of allowed suspect IP adresses percent */


const bit<32> NORMAL = 0;
const bit<32> CLONE = 2; // PKT_INSTANCE_TYPE_EGRESS_CLONE 2
const bit<32> RECIRCULATED = 4; //PKT_INSTANCE_TYPE_INGRESS_RECIRC 4

const bit<8> CLONE_FL_1 = 1;
const bit<8> RECIRC_FL_1 = 3;



typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ddosdm_t {
    bit<32> pkt_num;
    bit<8> alarm;
    bit<8> protocol;
    bit<16> count_ip;
}

header alarm_t {
    ip4Addr_t ip_alarm;
}


struct metadata {
    @field_list(CLONE_FL_1, RECIRC_FL_1)
    bit<1> res1; 
    bit<1> res2; 
    bit<1> res3;
    bit<32> count_min;
    bit<32> packet_number;
    bit<32> current_round;
    bit<32> round_in_cms1;
    bit<32> round_in_cms2;
    bit<32> round_in_cms3;
    bit<32> sl_source;/* IP source address to verify in Suspect List*/
    bit<32> sl_dst;
    bit<32> sl_ind; /* Suspect List index when read*/
    bit<32> sl_read; /* IP address readed from Suspect List*/
    bit<32> il_read; /* IP address readed from Inspection List*/
    bit<32> sl_address; /* Address to include into Suspect List */
    bit<32> sl_index; /* Suspect List index when write*/
    bit<48> timestamp; /* Ingress timestamp to generate hash and filtering malicious traffic */
    bit<48> timestamp_hashed; /* Hash of timestamp for filtering */
    bit<32> hhd_dst_carried; /* Key packet */
    bit<32> hhd_src_carried; /* Key packet */
    bit<32> hhd_count_carried; /* Counter for packet key */
    bit<32> hhd_index; /* Table slot based on hash function */
    bit<32> hhd_src_table; /* IP address in table */
    bit<32> hhd_count_table; /* Counter value in table */
    bit<32> hhd_src_swap; /* Swap key carried and key in table */
    bit<32> hhd_count_swap; /* Swap counter carried and table */
    bit<32> hhd_swapped; /* Indicator if IP was swapped in previous stage */
    bit<32> hhd_index_total; /* Position of Heavy Hitter global register */
    bit<32> hhd_aux_index_total; /* Position of Heavy Hitter global register when alarm detected */
    bit<32> hhd_write_key; /* Key readed from Heavy Hitter global register for write in alarm packet */
    bit<32> vl_ind; 
    bit<32> vl_read; 
    bit<16> parser_count; /* Number of headers to parser */
    bit<16> parser_remaining; /* Number of packet remaining for parser */
    int<32> ip_count; /* Number of ip address into alarm packet */
    bit<8> alarm; /* It is set to 0x01 to indicate the detection of a DDoS attack */
    bit<9> egress_port; /* Recirculated packet egrees port */
    bit<1> recirculated; /* Value to know in egress if packet from ingress is recirculated originally */
    bit<9> ack_port; /* Port wich switch is circulating ack responses, for non register as heavy hitter */
    bit<9> ingress_port; /* Port on which the packet arrived */
    bit<16> sl_position; /* Header stack position to read ip address in alarm packet */
    bit<32> trigsl; /* Trigger when alarm packet with ip addresses is received */
    bit<8> features; /* Indicates switch features */
    bit<8> attack; /* Network device status 0:Only Forwarding, 1:Mechanism running, 2:Mechanism running and k halved */
    bit<1> digest;
    bit<32> victimdstip;
    bit<32> alarm_pktin; /* Alarm packet received */
    bit<32> alarm_pktout; /* Alarm packet generated into switch */
    bit<8> key; /* Key for share alarm packet - session ID */
    bit<8> key_write_ip;
    bit<8> key_write_ip_notif;
    bit<8> mirror_session_id; /* Mirror session */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    ddosdm_t      ddosdm;
    alarm_t[TOP] alarm;
}

parser ParserImpl(packet_in pkt,out headers hdr,inout metadata meta,inout standard_metadata_t standard_metadata) {

    state start {
	    pkt.extract(hdr.ethernet);
	    transition select(hdr.ethernet.ether_type){
            ETHERTYPE_IPV4: parse_ipv4;
	        default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            PROTOCOL_DDOSDM: parse_ddosdm;
            default: accept;
        }
    }

    state parse_ddosdm {
        pkt.extract(hdr.ddosdm);
        meta.parser_remaining = hdr.ddosdm.count_ip;
        transition select(meta.parser_remaining) {
            0: accept;
            default: parse_alarm;
        }
    }

    state parse_alarm {
        pkt.extract(hdr.alarm.next);
        meta.parser_remaining = meta.parser_remaining - 1;
        transition select(meta.parser_remaining) {
            0: accept;
            default: parse_alarm;
        }
    }
}


register<bit<32>>(1024) occSlots1;
register<bit<32>>(1024) occSlots2;
register<bit<32>>(1024) occSlots3;

register<bit<32>>(1024) occSlots1_round;
register<bit<32>>(1024) occSlots2_round;
register<bit<32>>(1024) occSlots3_round;

register<bit<32>>(MAX_DDoS_SIZE) cms1_0;
register<bit<32>>(MAX_DDoS_SIZE) cms1_1;
register<bit<32>>(MAX_DDoS_SIZE) cms1_2;
register<bit<32>>(MAX_DDoS_SIZE) cms1_3;
register<bit<32>>(MAX_DDoS_SIZE) cms1_4;
register<bit<32>>(MAX_DDoS_SIZE) cms1_5;
register<bit<32>>(MAX_DDoS_SIZE) cms1_6;
register<bit<32>>(MAX_DDoS_SIZE) cms1_7;

register<bit<32>>(MAX_DDoS_SIZE) cms2_0;
register<bit<32>>(MAX_DDoS_SIZE) cms2_1;
register<bit<32>>(MAX_DDoS_SIZE) cms2_2;
register<bit<32>>(MAX_DDoS_SIZE) cms2_3;
register<bit<32>>(MAX_DDoS_SIZE) cms2_4;
register<bit<32>>(MAX_DDoS_SIZE) cms2_5;
register<bit<32>>(MAX_DDoS_SIZE) cms2_6;
register<bit<32>>(MAX_DDoS_SIZE) cms2_7;

register<bit<32>>(MAX_DDoS_SIZE) cms3_0;
register<bit<32>>(MAX_DDoS_SIZE) cms3_1;
register<bit<32>>(MAX_DDoS_SIZE) cms3_2;
register<bit<32>>(MAX_DDoS_SIZE) cms3_3;
register<bit<32>>(MAX_DDoS_SIZE) cms3_4;
register<bit<32>>(MAX_DDoS_SIZE) cms3_5;
register<bit<32>>(MAX_DDoS_SIZE) cms3_6;
register<bit<32>>(MAX_DDoS_SIZE) cms3_7;

register<bit<32>>(1) round;
register<bit<32>>(1) pkt_counter;

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    register<bit<8>>(1) device_status;
    register<bit<9>>(1) ack_port;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        size = 1024;
    }
    

    apply {

        ack_port.read(meta.ack_port, 0);
        device_status.read(meta.attack,0);
        meta.ingress_port = standard_metadata.ingress_port;

        meta.timestamp = standard_metadata.ingress_global_timestamp;

        if (hdr.ipv4.isValid()){
            if (standard_metadata.instance_type == NORMAL && hdr.ipv4.protocol == 0xFD){
                // if (meta.attack == 0){
                //     device_status.write(0,1);
                // } else
                if (meta.attack == 0){
                //To adjust entropy threshold when is received alarm packet more than one time
                    //bit<8> new_k;
                    //k_attack.read(new_k,0);
                    //k.write(0,new_k);
                    device_status.write(0,2);
                }

                if (hdr.ddosdm.count_ip != 0) {
                    meta.alarm_pktin = 1;
                }
            }
        }

        if (standard_metadata.instance_type == NORMAL){
            //Initialize trigger observation window
            //meta.trigow = 0;
            if (hdr.ipv4.isValid()) {
                meta.key = 0;

                bit<10> hash_32_1;
                bit<10> hash_32_2;
                bit<10> hash_32_3;

                // Index in Bitmap (Size 1024)
                bit<10> bm_hash;

                // Index in BACON Sketch (Size 1024 * 1024)
                bit<32> index1 = 32w0;
                bit<32> index2 = 32w0;
                bit<32> index3 = 32w0;

                // Number of 1s in BACON Sketch
                bit<32> value_1 = 32w0;
                bit<32> value_2 = 32w0;
                bit<32> value_3 =32w0;

                bit<32> round_1 = 32w0;
                bit<32> round_2 = 32w0;
                bit<32> round_3 =32w0;

                // Difference between values
                bit<32> d12;
                bit<32> d13;
                bit<32> d23;
        
                ipv4_lpm.apply();
        
                hash(hash_32_1, HashAlgorithm.crc32, 1w0, {hdr.ipv4.dstAddr}, 10w1023);
                hash(hash_32_2, HashAlgorithm.crc32_custom, 1w0, {hdr.ipv4.dstAddr}, 10w1023);

                hash(hash_32_3, HashAlgorithm.crc32_custom, 1w0, {hdr.ipv4.dstAddr}, 10w1023);
                hash(bm_hash, HashAlgorithm.crc32, 1w0, {hdr.ipv4.srcAddr}, 10w1023);
        
                index1[9:0] = bm_hash;
                index2[9:0] = bm_hash;
                index3[9:0] = bm_hash;

                index1[16:10] = hash_32_1[6:0];
                index2[16:10] = hash_32_2[6:0];
                index3[16:10] = hash_32_3[6:0];

                //packet count, round count 
                pkt_counter.read(meta.packet_number, 0);
                meta.packet_number = meta.packet_number + 1;
                round.read(meta.current_round,0);

                if (meta.packet_number == 1) {
                    meta.current_round = meta.current_round + 1;
                    round.write(0, meta.current_round);
                    pkt_counter.write(0, meta.packet_number);
                }
                else if(meta.packet_number == 5){//number of packets in one round is 5, reset
                    pkt_counter.write(0,0);
                }
                else { 
                    pkt_counter.write(0, meta.packet_number);
                }

                //hash1
                if(hash_32_1[9:7] == 0){//if round_in_cms is 0, it is automatically different from current_round which starts from 1
                    cms1_0.read(meta.round_in_cms1, index1);
                    if(meta.round_in_cms1 != meta.current_round){ 
                        cms1_0.write(index1, meta.current_round);
                        meta.res1=1;
                    }
                    else{
                        meta.res1=0;
                    }
                }else if(hash_32_1[9:7] == 1){
                    cms1_1.read(meta.round_in_cms1, index1);
                    if(meta.round_in_cms1 != meta.current_round){ 
                        cms1_1.write(index1, meta.current_round);
                        meta.res1=1;
                    }
                    else{
                        meta.res1=0;
                    }
                }else if(hash_32_1[9:7] == 2){
                    cms1_2.read(meta.round_in_cms1, index1);
                    if(meta.round_in_cms1 != meta.current_round){ 
                        cms1_2.write(index1, meta.current_round);
                        meta.res1=1;
                    }
                    else{
                        meta.res1=0;
                    }
                }else if(hash_32_1[9:7] == 3){
                    cms1_3.read(meta.round_in_cms1, index1);
                    if(meta.round_in_cms1 != meta.current_round){ 
                        cms1_3.write(index1, meta.current_round);
                        meta.res1=1;
                    }
                    else{
                        meta.res1=0;
                    }
                }else if(hash_32_1[9:7] == 4){
                    cms1_4.read(meta.round_in_cms1, index1);
                    if(meta.round_in_cms1 != meta.current_round){ 
                        cms1_4.write(index1, meta.current_round);
                        meta.res1=1;
                    }
                    else{
                        meta.res1=0;
                    }    
                }else if(hash_32_1[9:7] == 5){
                    cms1_5.read(meta.round_in_cms1, index1);
                    if(meta.round_in_cms1 != meta.current_round){ 
                        cms1_5.write(index1, meta.current_round);
                        meta.res1=1;
                    }
                    else{
                        meta.res1=0;
                    }
                }else if(hash_32_1[9:7] == 6){
                    cms1_6.read(meta.round_in_cms1, index1);
                    if(meta.round_in_cms1 != meta.current_round){ 
                        cms1_6.write(index1, meta.current_round);
                        meta.res1=1;
                    }
                    else{
                        meta.res1=0;
                    }
                }else if(hash_32_1[9:7] == 7){
                    cms1_7.read(meta.round_in_cms1, index1);
                    if(meta.round_in_cms1 != meta.current_round){ 
                        cms1_7.write(index1, meta.current_round);
                        meta.res1=1;
                    }
                    else{
                        meta.res1=0;
                    }
                }

                //hash2
                if(hash_32_2[9:7] == 0){
                    cms2_0.read(meta.round_in_cms2, index2);
                    if(meta.round_in_cms2 != meta.current_round){ 
                        cms2_0.write(index2, meta.current_round);
                        meta.res2=1;
                    }
                    else{
                        meta.res2=0;
                    }
                }else if(hash_32_2[9:7] == 1){
                    cms2_1.read(meta.round_in_cms2, index2);
                    if(meta.round_in_cms2 != meta.current_round){ 
                        cms2_1.write(index2, meta.current_round);
                        meta.res2=1;
                    }
                    else{
                        meta.res2=0;
                    }
                }else if(hash_32_2[9:7] == 2){
                    cms2_2.read(meta.round_in_cms2, index2);
                    if(meta.round_in_cms2 != meta.current_round){ 
                        cms2_2.write(index2, meta.current_round);
                        meta.res2=1;
                    }
                    else{
                        meta.res2=0;
                    }
                }else if(hash_32_2[9:7] == 3){
                    cms2_3.read(meta.round_in_cms2, index2);
                    if(meta.round_in_cms2 != meta.current_round){ 
                        cms2_3.write(index2, meta.current_round);
                        meta.res2=1;
                    }
                    else{
                        meta.res2=0;
                    }
                }
                else if(hash_32_2[9:7] == 4){
                    cms2_4.read(meta.round_in_cms2, index2);
                    if(meta.round_in_cms2 != meta.current_round){ 
                        cms2_4.write(index2, meta.current_round);
                        meta.res2=1;
                    }
                    else{
                        meta.res2=0;
                    }
                }else if(hash_32_2[9:7] == 5){
                    cms2_5.read(meta.round_in_cms2, index2);
                    if(meta.round_in_cms2 != meta.current_round){ 
                        cms2_5.write(index2, meta.current_round);
                        meta.res2=1;
                    }
                    else{
                        meta.res2=0;
                    }
                }else if(hash_32_2[9:7] == 6){
                    cms2_6.read(meta.round_in_cms2, index2);
                    if(meta.round_in_cms2 != meta.current_round){ 
                        cms2_6.write(index2, meta.current_round);
                        meta.res2=1;
                    }
                    else{
                        meta.res2=0;
                    }
                }else if(hash_32_2[9:7] == 7){
                    cms2_7.read(meta.round_in_cms2, index2);
                    if(meta.round_in_cms2 != meta.current_round){ 
                        cms2_7.write(index2, meta.current_round);
                        meta.res2=1;
                    }
                    else{
                        meta.res2=0;
                    }
                }

                //hash3
                if(hash_32_3[9:7] == 0){
                    cms3_0.read(meta.round_in_cms3, index3);
                    if(meta.round_in_cms3 != meta.current_round){ 
                        cms3_0.write(index3, meta.current_round);
                        meta.res3=1;
                    }
                    else{
                        meta.res3=0;
                    }
                }else if(hash_32_3[9:7] == 1){
                    cms3_1.read(meta.round_in_cms3, index3);
                    if(meta.round_in_cms3 != meta.current_round){ 
                        cms3_1.write(index3, meta.current_round);
                        meta.res3=1;
                    }
                    else{
                        meta.res3=0;
                    }
                }else if(hash_32_3[9:7] == 2){
                    cms3_2.read(meta.round_in_cms3, index3);
                    if(meta.round_in_cms3 != meta.current_round){ 
                        cms3_2.write(index3, meta.current_round);
                        meta.res3=1;
                    }
                    else{
                        meta.res3=0;
                    }
                }else if(hash_32_3[9:7] == 3){
                    cms3_3.read(meta.round_in_cms3, index3);
                    if(meta.round_in_cms3 != meta.current_round){ 
                        cms3_3.write(index3, meta.current_round);
                        meta.res3=1;
                    }
                    else{
                        meta.res3=0;
                    }
                }
                else if(hash_32_3[9:7] == 4){
                    cms3_4.read(meta.round_in_cms3, index3);
                    if(meta.round_in_cms3 != meta.current_round){ 
                        cms3_4.write(index3, meta.current_round);
                        meta.res3=1;
                    }
                    else{
                        meta.res3=0;
                    }
                }else if(hash_32_3[9:7] == 5){
                    cms3_5.read(meta.round_in_cms3, index3);
                    if(meta.round_in_cms3 != meta.current_round){ 
                        cms3_5.write(index3, meta.current_round);
                        meta.res3=1;
                    }
                    else{
                        meta.res3=0;
                    }
                }else if(hash_32_3[9:7] == 6){
                    cms3_6.read(meta.round_in_cms3, index3);
                    if(meta.round_in_cms3 != meta.current_round){ 
                        cms3_6.write(index3, meta.current_round);
                        meta.res3=1;
                    }
                    else{
                        meta.res3=0;
                    }
                }else if(hash_32_3[9:7] == 7){
                    cms3_7.read(meta.round_in_cms3, index3);
                    if(meta.round_in_cms3 != meta.current_round){ 
                        cms3_7.write(index3, meta.current_round);
                        meta.res3=1;
                    }
                    else{
                        meta.res3=0;
                    }
                }

                //count the number of 1s
                occSlots1.read(value_1, (bit<32>)hash_32_1);
                occSlots1_round.read(round_1,(bit<32>)hash_32_1);
                if(meta.res1 == 1 && round_1 == meta.current_round){
                    value_1 = value_1 + 1;
                    occSlots1.write((bit<32>)hash_32_1, value_1);
                }
                else if(meta.res1 == 1 && round_1 != meta.current_round){
                    round_1 = meta.current_round;
                    occSlots1_round.write((bit<32>)hash_32_1, round_1);
                    value_1 = 1;
                    occSlots1.write((bit<32>)hash_32_1, value_1);
                }

                occSlots2.read(value_2, (bit<32>)hash_32_2);
                occSlots2_round.read(round_2,(bit<32>)hash_32_2);
                if(meta.res2 == 1 && round_2 == meta.current_round){
                    value_2 = value_2 + 1;
                    occSlots2.write((bit<32>)hash_32_2, value_2);
                }
                else if(meta.res2 == 1 && round_2 != meta.current_round){
                    round_2 = meta.current_round;
                    occSlots2_round.write((bit<32>)hash_32_2, round_2);
                    value_2 = 1;
                    occSlots2.write((bit<32>)hash_32_2, value_2);
                }

                occSlots3.read(value_3, (bit<32>)hash_32_3);
                occSlots3_round.read(round_3,(bit<32>)hash_32_3);
                if(meta.res3 == 1 && round_3 == meta.current_round){
                    value_3 = value_3 + 1;
                    occSlots3.write((bit<32>)hash_32_3, value_3);
                }
                else if(meta.res3 == 1 && round_3 != meta.current_round){
                    round_3 = meta.current_round;
                    occSlots3_round.write((bit<32>)hash_32_3, round_3);
                    value_3 = 1;
                    occSlots3.write((bit<32>)hash_32_3, value_3);
                }

                //find the minimum of 1-counts
                d12 = value_1 - value_2;
                d13 = value_1 - value_3;
                d23 = value_2 - value_3;
                if (d12 < 0 && d13 < 0){
                    meta.count_min = value_1;
                }else if (d12 > 0 && d23 <0){
                    meta.count_min = value_2;
                }else{
                    meta.count_min = value_3;
                }

                if (meta.count_min == DDoS_threshold + 1){
                    meta.digest = 1;
                    meta.victimdstip = hdr.ipv4.dstAddr;
                    //recirculate packet or something.. 
                }
            }    
        }
        else if (standard_metadata.instance_type == RECIRCULATED && meta.alarm_pktout == 1){
            standard_metadata.egress_spec = meta.egress_port;
            meta.recirculated = 1;
        }
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    register<bit<32>>(1024) suspectlist; // (HHD) Register with IP Address to blocking
    register<bit<32>>(1024) inspectionlist; // HHD Register with IP Address received into Alarm PacketIn
    register<bit<8>>(1) features; //Register indicates features of switch (1: FlowStatistics/Suspect Identificaction)

    register<bit<32>>(1024) src_1;
    register<bit<32>>(1024) count_1;
    register<bit<32>>(1024) src_2;
    register<bit<32>>(1024) count_2;
    register<bit<32>>(1024) src_3;
    register<bit<32>>(1024) count_3;

    register<bit<32>>(8128) key_total;//TOP
    register<bit<32>>(1) index_total;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_session(bit<8> session_id) {
        meta.mirror_session_id = session_id;
    }

    table share_alarm {
        key = {
            meta.key: exact;
        }
        actions = {
            set_session;
        }
        default_action = set_session(0);
    }

    table share_notification {
        key = {
            meta.key: exact;
        }
        actions = {
            set_session;
        }
        default_action = set_session(0);
    }

    action write_mac_addr (macAddr_t srcAddr, macAddr_t dstAddr) {
        hdr.ethernet.srcAddr = srcAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }

    table write_mac {
        key = {
            standard_metadata.egress_port: exact;
        }
        actions = {
            write_mac_addr;
            drop;
        }
        default_action = drop();
    }

    action write_ip_addr (ip4Addr_t srcAddr, ip4Addr_t dstAddr) {
        hdr.ipv4.srcAddr = srcAddr;
        hdr.ipv4.dstAddr = dstAddr;
    }

    table write_ip {
        key = {
            meta.key_write_ip: exact;
        }
        actions = {
            write_ip_addr;
            drop;
        }
        default_action = drop();
    }

    apply {
        //send_frame.apply();
        meta.sl_source = hdr.ipv4.srcAddr;
        hash(meta.sl_ind, HashAlgorithm.crc32, 1w0, {meta.sl_source}, 10w1023);//suspect list sourceIP stored location, for the front switches part 
        suspectlist.read(meta.sl_read,meta.sl_ind);
        inspectionlist.read(meta.il_read,meta.sl_ind);
        features.read(meta.features,0);

        index_total.read(meta.hhd_index_total,0);

        if (meta.alarm == 1){
            meta.key = meta.key + 1;
            if (meta.mirror_session_id > 0) {
                clone_preserving_field_list(CloneType.E2E, (bit<32>) meta.mirror_session_id, CLONE_FL_1);
            }
        }else{
            index_total.write(0,0);
        }

        if(meta.sl_source == meta.sl_read){
            hash(meta.timestamp_hashed, HashAlgorithm.crc16, 32w0, {meta.timestamp}, 32w64); /*This generates a number between 0-100 based on packet timestamp */
            if (meta.timestamp_hashed > DROP_PERCENT){
                drop(); /* Block 70% of packet if IP Address match in IP Suspect List */
            }
        }else if(meta.sl_source == meta.il_read){
            suspectlist.write(meta.sl_ind,meta.sl_source);
            key_total.write(meta.hhd_index_total,meta.sl_source);
            meta.hhd_index_total = meta.hhd_index_total + 1;
            index_total.write(0,meta.hhd_index_total);
        } else {
            if (hdr.ipv4.isValid() && meta.alarm_pktin != 1) {
                write_mac.apply();

                if (meta.alarm == 1){
                    share_alarm.apply();
                    share_notification.apply();
                }

                if (standard_metadata.instance_type == NORMAL && meta.recirculated != 1 && meta.features == 1){//no victim yet, just increment the packet 

                  //######################################################################
                    //######################################################################
                    //         ***** FLOW STATISTICS / SUSPECT IDENTIFICATION ******
                    //######################################################################
                    //######################################################################

                    meta.hhd_dst_carried = hdr.ipv4.dstAddr;
                    meta.hhd_src_carried = hdr.ipv4.srcAddr;
                    meta.hhd_count_carried = 1;

                    hash(meta.hhd_index, HashAlgorithm.crc32, 1w0, {meta.hhd_dst_carried}, 10w1023);

                    // Read key and counter in slot
                    src_1.read(meta.hhd_src_table,meta.hhd_index);
                    count_1.read(meta.hhd_count_table,meta.hhd_index);

                    meta.hhd_swapped = 0;

                    if (meta.hhd_count_table == 0){//empty table 
                        meta.hhd_src_table = meta.hhd_src_carried;
                        meta.hhd_count_table = meta.hhd_count_carried;

                    } else{//not empty table, assume same dstip
                        if (meta.hhd_src_table == meta.hhd_src_carried){//same srcIP in same dstIP index
                            meta.hhd_count_table = meta.hhd_count_table + 1;
                            if (meta.hhd_index_total < TOP && meta.ack_port != meta.ingress_port ){//
                                suspectlist.write(meta.sl_ind,meta.sl_source);
                                key_total.write(meta.hhd_index_total,meta.sl_source);
                                meta.hhd_index_total = meta.hhd_index_total + 1;
                                index_total.write(0,meta.hhd_index_total);
                            }

                        } else {//diff srcIP in same dstIP index
                            meta.hhd_src_swap = meta.hhd_src_table;
                            meta.hhd_count_swap = meta.hhd_count_table;

                            meta.hhd_src_table = meta.hhd_src_carried;
                            meta.hhd_count_table = meta.hhd_count_carried;

                            meta.hhd_src_carried = meta.hhd_src_swap;
                            meta.hhd_count_carried = meta.hhd_count_swap;

                            meta.hhd_swapped = 1;
                        }
                    }

                    src_1.write(meta.hhd_index,meta.hhd_src_table);
                    count_1.write(meta.hhd_index,meta.hhd_count_table);

                    /*Stage 2*/
                    if (meta.hhd_swapped ==1){

                        hash(meta.hhd_index, HashAlgorithm.crc32_custom, 1w0, {meta.hhd_dst_carried}, 10w1023);

                        // Read key and counter in slot
                        src_2.read(meta.hhd_src_table,meta.hhd_index);
                        count_2.read(meta.hhd_count_table,meta.hhd_index);

                        meta.hhd_swapped = 1;

                        if (meta.hhd_count_table == 0){//empty table 
                        meta.hhd_src_table = meta.hhd_src_carried;
                        meta.hhd_count_table = meta.hhd_count_carried;

                        } else{//not empty table, assume same dstip
                            if (meta.hhd_src_table == meta.hhd_src_carried){//same srcIP in same dstIP index
                                meta.hhd_count_table = meta.hhd_count_table + 1;
                                if (meta.hhd_index_total < TOP && meta.ack_port != meta.ingress_port ){//
                                    suspectlist.write(meta.sl_ind,meta.sl_source);
                                    key_total.write(meta.hhd_index_total,meta.sl_source);
                                    meta.hhd_index_total = meta.hhd_index_total + 1;
                                    index_total.write(0,meta.hhd_index_total);
                                }

                            } else {//diff srcIP in same dstIP index
                            meta.hhd_src_swap = meta.hhd_src_table;
                            meta.hhd_count_swap = meta.hhd_count_table;

                            meta.hhd_src_table = meta.hhd_src_carried;
                            meta.hhd_count_table = meta.hhd_count_carried;

                            meta.hhd_src_carried = meta.hhd_src_swap;
                            meta.hhd_count_carried = meta.hhd_count_swap;

                            meta.hhd_swapped = 1;
                            }
                        }

                        src_2.write(meta.hhd_index,meta.hhd_src_table);
                        count_2.write(meta.hhd_index,meta.hhd_count_table);
                    }
                
                    /*Stage 3*/
                    if (meta.hhd_swapped ==1){

                        hash(meta.hhd_index, HashAlgorithm.crc32_custom, 1w0, {meta.hhd_dst_carried}, 10w1023);

                        // Read key and counter in slot
                        src_3.read(meta.hhd_src_table,meta.hhd_index);
                        count_3.read(meta.hhd_count_table,meta.hhd_index);

                        meta.hhd_swapped = 1;

                        if (meta.hhd_count_table == 0){//empty table 
                            meta.hhd_src_table = meta.hhd_src_carried;
                            meta.hhd_count_table = meta.hhd_count_carried;

                        } else{//not empty table, assume same dstip
                            if (meta.hhd_src_table == meta.hhd_src_carried){//same srcIP in same dstIP index
                                meta.hhd_count_table = meta.hhd_count_table + 1;
                                if (meta.hhd_index_total < TOP && meta.ack_port != meta.ingress_port ){//
                                    suspectlist.write(meta.sl_ind,meta.sl_source);
                                    key_total.write(meta.hhd_index_total,meta.sl_source);
                                    meta.hhd_index_total = meta.hhd_index_total + 1;
                                    index_total.write(0,meta.hhd_index_total);
                                }

                            } else {//diff srcIP in same dstIP index
                                meta.hhd_src_swap = meta.hhd_src_table;
                                meta.hhd_count_swap = meta.hhd_count_table;

                                meta.hhd_src_table = meta.hhd_src_carried;
                                meta.hhd_count_table = meta.hhd_count_carried;

                                meta.hhd_src_carried = meta.hhd_src_swap;
                                meta.hhd_count_carried = meta.hhd_count_swap;

                                meta.hhd_swapped = 1;
                            }
                        }
                        src_2.write(meta.hhd_index,meta.hhd_src_table);
                        count_2.write(meta.hhd_index,meta.hhd_count_table);
                    }

                    index_total.write(0,meta.hhd_index_total);

                    //######################################################################
                    //######################################################################
                    //       ***** END FLOW STATISTICS / SUSPECT IDENTIFICATION ******
                    //######################################################################
                    //######################################################################

                } else if (standard_metadata.instance_type == CLONE) {
                    meta.key_write_ip = meta.key - 1;
                    write_ip.apply();
                    if (!hdr.ddosdm.isValid()) {
                        hdr.ddosdm.setValid();
                        hdr.ddosdm.pkt_num = meta.packet_number;
                        hdr.ddosdm.alarm = meta.alarm;
                        hdr.ddosdm.protocol = hdr.ipv4.protocol;
                        hdr.ddosdm.count_ip = 0;
                        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 32;
                        hdr.ipv4.protocol = PROTOCOL_DDOSDM;
                        meta.egress_port = standard_metadata.egress_port;
                        index_total.read(meta.hhd_aux_index_total,0);
                        index_total.write(0,0);
                        meta.alarm_pktout = 1;
                        recirculate_preserving_field_list(RECIRC_FL_1);
                    } else {
                        meta.key = meta.key + 1;
                        if (meta.mirror_session_id > 0) {
                            clone_preserving_field_list(CloneType.E2E, (bit<32>) meta.mirror_session_id, CLONE_FL_1);
                        }
                    }
                } else if (meta.recirculated == 1 && meta.alarm_pktout == 1){
                    if (meta.hhd_aux_index_total > 0){
                        meta.hhd_aux_index_total = meta.hhd_aux_index_total - 1;
                        key_total.read(meta.hhd_write_key,meta.hhd_aux_index_total);
                        if (meta.hhd_write_key != 0){
                            key_total.write(meta.hhd_aux_index_total,0);
                            hdr.ddosdm.count_ip = hdr.ddosdm.count_ip + 1;
                            hdr.alarm.push_front(1);
                            hdr.alarm[0].setValid();
                            hdr.alarm[0].ip_alarm = meta.hhd_write_key;
                            hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
                            meta.egress_port = standard_metadata.egress_port;
                        }
                        recirculate_preserving_field_list(RECIRC_FL_1);
                    } else {
                        meta.key = meta.key + 1;
                        if (meta.mirror_session_id > 0) {
                            clone_preserving_field_list(CloneType.E2E, (bit<32>) meta.mirror_session_id, CLONE_FL_1);
                        }
                    }
                }
            }else if (hdr.ipv4.isValid() && meta.alarm_pktin == 1){
                //Adding IP address received into inspection list
                if (hdr.ddosdm.isValid()){
                    if (hdr.ipv4.protocol == 0xFD && hdr.ddosdm.count_ip != 0){
                        meta.sl_address = hdr.alarm[0].ip_alarm;
                        hash(meta.sl_index, HashAlgorithm.crc32, 32w0, {meta.sl_address}, 32w0xffffffff);
                        inspectionlist.write(meta.sl_index, meta.sl_address);
                        hdr.ddosdm.count_ip = hdr.ddosdm.count_ip - 1;
                        hdr.alarm.pop_front(1);
                        recirculate_preserving_field_list(RECIRC_FL_1);
                    }
                }
            }
        }
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ddosdm);
        packet.emit(hdr.alarm);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

