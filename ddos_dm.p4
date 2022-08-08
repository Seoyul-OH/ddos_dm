#include <core.p4>
#include <v1model.p4>

#define MAX_DDoS_SIZE 131072
#define DDoS_threshold 2
#define DROP_PERCENT 30

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
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
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udplen;
    bit<16> udpchk;
}

struct metadata {
    bit<1> res1; 
    bit<1> res2; 
    bit<1> res3;
    bit<32> count_min;
    
    bit<1> digest;
    bit<32> victimdstip;

    bit<32> pkt_num;
    bit<32> current_round;

    bit<32> round_in_cms1;
    bit<32> round_in_cms2;
    bit<32> round_in_cms3;

    bit<8> key; /* Key for share alarm packet - session ID */
    bit<8> key_write_ip;
    bit<8> key_write_ip_notif;
    bit<8> mirror_session_id; /* Mirror session */

    bit<32> sl_source;/* IP source address to verify in Suspect List*/
    bit<32> sl_dst;
    bit<32> sl_ind; /* Suspect List index when read*/
    bit<32> sl_read; /* IP address readed from Suspect List*/
    bit<32> il_read; /* IP address readed from Inspection List*/
    bit<32> sl_address; /* Address to include into Suspect List */
    bit<32> sl_index; /* Suspect List index when write*/
    bit<1> features; /* Indicates switch features */

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
    //bit<32> hhd_thresh; /* Heavy Hitter Threshold */

    bit<32> hhd_index_total; /* Position of Heavy Hitter global register */
    bit<32> hhd_aux_index_total; /* Position of Heavy Hitter global register when alarm detected */
    bit<32> hhd_write_key; /* Key readed from Heavy Hitter global register for write in alarm packet */

    bit<32> suspectadd_index;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".tcp") 
    tcp_t      tcp;
    @name(".udp") 
    udp_t      udp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w0x6: parse_tcp;
            8w0x11: parse_udp;
            default: accept;
        }
    }
    @name(".parse_tcp") state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    @name(".parse_udp") state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
    @name(".start") state start {
        transition parse_ethernet;
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
    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 8w1;
    }
    action _drop() {
        mark_to_drop(standard_metadata);
    }

    table ipv4_lpm {
        actions = {
            ipv4_forward;
            _drop;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
    }
    apply {
        // Index in Count-min sketch (Size 1024)
        bit<10> hash_32_1;
        bit<10> hash_32_2;
        bit<10> hash_32_3;

        // Index in Bitmap (Size 1024)
        bit<10> bm_hash;

        // Index in BACON Sketch (Size 1024 * 1024)
        bit<32> index1 = 32w0;
        bit<32> index2 = 32w0;
        bit<32> index3 = 32w0;

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
        pkt_counter.read(meta.pkt_num, 0);
        meta.pkt_num = meta.pkt_num + 1;
        round.read(meta.current_round,0);

        if (meta.pkt_num == 1) {
            meta.current_round = meta.current_round + 1;
            round.write(0, meta.current_round);
            pkt_counter.write(0, meta.pkt_num);
        }
        else if(meta.pkt_num == 5){//number of packets in one round is 5, reset
            pkt_counter.write(0,0);
        }
        else { 
            pkt_counter.write(0, meta.pkt_num);
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
        }
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
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

    action rewrite_mac (bit<48> smac){
        hdr.ethernet.srcAddr = smac;
    }

    table send_frame {
        key = {
            standard_metadata.egress_port: exact;
        }
        actions = {
            rewrite_mac;
            drop;
        }
        default_action = drop();
    }

    action write_srcip_addr (bit<32> srcAddr) {
        hdr.ipv4.srcAddr = srcAddr;
    }
    action write_dstip_addr (bit<32> dstAddr) {
        hdr.ipv4.dstAddr = dstAddr;
    }

    table write_ip {
        key = {
            meta.key_write_ip: exact;
        }
        actions = {
            write_srcip_addr;
            write_dstip_addr;
            drop;
        }
        default_action = drop();
    }

    register<bit<32>>(1024) suspectlist; // (HHD) Register with IP Address to blocking
    register<bit<32>>(1024) inspectionlist; // HHD Register with IP Address received into Alarm PacketIn
    register<bit<1>>(1) features; //Register indicates features of switch (1: FlowStatistics/Suspect Identificaction) ?? first, 0

    register<bit<32>>(1024) src_1;
    register<bit<32>>(1024) count_1;
    register<bit<32>>(1024) src_2;
    register<bit<32>>(1024) count_2;
    register<bit<32>>(1024) src_3;
    register<bit<32>>(1024) count_3;

    register<bit<32>>(8128) key_total;//TOP
    register<bit<32>>(1) index_total;

    apply{
        write_ip.apply();
        share_alarm.apply();
        share_notification.apply();


        //start
        meta.sl_source = hdr.ipv4.srcAddr;
        hash(meta.sl_ind, HashAlgorithm.crc32, 1w0, {meta.sl_source}, 10w1023);//source IP location in suspect list, for the front switches. 
        suspectlist.read(meta.sl_read,meta.sl_ind);
        inspectionlist.read(meta.il_read,meta.sl_ind);
        features.read(meta.features,0);

        index_total.read(meta.hhd_index_total,0);

        if(meta.sl_source == meta.sl_read){//incoming packet's src is in suspect list 
            hash(meta.timestamp_hashed, HashAlgorithm.crc16, 32w0, {meta.timestamp}, 32w64); /*This generates a number between 0-100 based on packet timestamp */
            if (meta.timestamp_hashed > DROP_PERCENT){
                drop(); /* Block 70% of packet if IP Address match in IP Suspect List */
            }
        }else if(meta.sl_source == meta.il_read){//???end of this code, make inspection list
            suspectlist.write(meta.sl_ind,meta.sl_source);
            key_total.write(meta.hhd_index_total,meta.sl_source);
            meta.hhd_index_total = meta.hhd_index_total + 1;
            index_total.write(0,meta.hhd_index_total);
        } else {
            if (hdr.ipv4.isValid()) {// ++ alarm packet X 
                send_frame.apply();

                if (meta.features == 0){ 

                  //######################################################################
                    //######################################################################
                    //         ***** FLOW STATISTICS / SUSPECT IDENTIFICATION ******
                    //######################################################################
                    //######################################################################

                    meta.hhd_dst_carried = hdr.ipv4.dstAddr;
                    meta.hhd_src_carried = hdr.ipv4.srcAddr;
                    meta.hhd_count_carried = 1;

                    hash(meta.hhd_index, HashAlgorithm.crc32, 1w0, {meta.hhd_dst_carried}, 10w1023);//destination hash 

                    // Read key and counter in slot
                    src_1.read(meta.hhd_src_table,meta.hhd_index);
                    count_1.read(meta.hhd_count_table,meta.hhd_index);

                    meta.hhd_swapped = 0;

                    if (meta.digest == 0){
                        if (meta.hhd_count_table == 0){//empty table 
                            meta.hhd_src_table = meta.hhd_src_carried;
                            meta.hhd_count_table = meta.hhd_count_carried;
                            //meta.hhd_swapped = 0;

                        } else{//not empty table, assume same dstip
                            if (meta.hhd_src_table == meta.hhd_src_carried){//same srcIP in same dstIP index
                            
                                meta.hhd_count_table = meta.hhd_count_table + 1;
                                //meta.hhd_swapped = 0;

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
                    }
                    else{//meta.digest == 1 
                        meta.hhd_swapped = 1;
                        if(meta.hhd_count_table > 5){//suspect list adding threshold is 5, src_table is not empty 
                            hash(meta.suspectadd_index, HashAlgorithm.crc32, 1w0, {meta.hhd_src_table}, 10w1023);
                            suspectlist.write(meta.suspectadd_index, meta.hhd_src_table);
                        }//else just pass to next stage 
                    }
        

                    /*Stage 2*/
                    if (meta.hhd_swapped ==1){

                        hash(meta.hhd_index, HashAlgorithm.crc32_custom , 1w0, {meta.hhd_dst_carried}, 10w1023);

                        // Read key and counter in slot
                        src_2.read(meta.hhd_src_table,meta.hhd_index);
                        count_2.read(meta.hhd_count_table,meta.hhd_index);

                        if(meta.digest == 0){
                            if (meta.hhd_count_table == 0){//empty table, swapped =0 should be here and below too 
                                meta.hhd_src_table = meta.hhd_src_carried;
                                meta.hhd_count_table = meta.hhd_count_carried;
                                meta.hhd_swapped = 0;

                            } else{//not empty table, assume same dstip
                                if (meta.hhd_src_table == meta.hhd_src_carried){//same srcIP in same dstIP index
                                    meta.hhd_count_table = meta.hhd_count_table + 1;
                                    meta.hhd_swapped = 0;

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
                        else {//meta.digest == 1
                            meta.hhd_swapped = 1;
                            if(meta.hhd_count_table > 5){//suspect list adding threshold is 5
                                hash(meta.suspectadd_index, HashAlgorithm.crc32, 1w0, {meta.hhd_src_table}, 10w1023);
                                suspectlist.write(meta.suspectadd_index,meta.hhd_src_table);
                            }//else just pass to next stage 
                        }
                    }

                    /*Stage 3*/
                    if (meta.hhd_swapped ==1){

                        hash(meta.hhd_index, HashAlgorithm.crc32_custom, 1w0, {meta.hhd_dst_carried}, 10w1023);

                        // Read key and counter in slot
                        src_3.read(meta.hhd_src_table,meta.hhd_index);
                        count_3.read(meta.hhd_count_table,meta.hhd_index);

                        if(meta.digest == 0){
                            if (meta.hhd_count_table == 0){//empty table, swapped =0 should be here and below too 
                                meta.hhd_src_table = meta.hhd_src_carried;
                                meta.hhd_count_table = meta.hhd_count_carried;
                                meta.hhd_swapped = 0;

                            } else{//not empty table, assume same dstip
                                if (meta.hhd_src_table == meta.hhd_src_carried){//same srcIP in same dstIP index
                                    meta.hhd_count_table = meta.hhd_count_table + 1;
                                    meta.hhd_swapped = 0;

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

                            src_3.write(meta.hhd_index,meta.hhd_src_table);
                            count_3.write(meta.hhd_index,meta.hhd_count_table);

                        } 
                        else {//meta.digest == 1
                            meta.hhd_swapped = 1;
                            if(meta.hhd_count_table > 5){//suspect list adding threshold is 5
                                hash(meta.suspectadd_index, HashAlgorithm.crc32, 1w0, {meta.hhd_src_table}, 10w1023);
                                suspectlist.write(meta.suspectadd_index,meta.hhd_src_table);
                            }//else just pass to next stage 
                        }
                    }
                    index_total.write(0,meta.hhd_index_total);
                }//features == 0 end 
            }//not alarm packet end 
            // else if (hdr.ipv4.isValid() && meta.alarm_pktin == 1){ddosd header} alarm packet O 
        }
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
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

