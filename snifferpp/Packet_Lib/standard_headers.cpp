//
//  standard_headers.cpp
//  tcp_demo
//
//  Created by Robert Arnott on 4/19/20.
//  Copyright © 2020 Robert Arnott. All rights reserved.
//

#include "standard_headers.hpp"

using std::unique_ptr;
using std::shared_ptr;
using std::string;
using std::cerr;
using std::cout;
using std::endl;
using std::ostream;



ostream& operator<<(ostream& os, const ether_header& eth) {
    std::ios tmp {NULL};
    tmp.copyfmt(os);
    os << "Ethernet Header" << endl;
    
    os << "\t|-Source Address: ";
    for(int i = 0; i < ETHER_ADDR_LEN; ++i){
        os << std::setfill('0') << std::setw(2) << std::hex << (0xff & eth.ether_shost[i]);
        if(i < ETHER_ADDR_LEN-1){
            os << ":";
        }
    }
    os << endl;
    
    os << "\t|-Destination Address: ";
    for(int i = 0; i < ETHER_ADDR_LEN; ++i){
        os << std::setfill('0') << std::setw(2) << std::hex << (0xff & eth.ether_dhost[i]);
        if(i < ETHER_ADDR_LEN-1){
            os << ":";
        }
    }
    os<<endl;
    
    os << "\t|-Protocol: " << eth.ether_type;
    os.copyfmt(tmp);
    return os;
}

ostream& operator<<(ostream& os, const ip& iph) {
    std::ios tmp {NULL};
    tmp.copyfmt(os);
    os << "IP Header" << endl;
    os << "\t|-Version: " << iph.ip_v << endl;
    os << "\t|-IP Header Length: " << iph.ip_hl << " double-words" << endl;
    os << "\t|-Type of Service: " << +iph.ip_tos << endl;
    os << "\t|-Total Length: " << iph.ip_len << endl;
    os << "\t|-Identification: " << iph.ip_id << endl;
    os << "\t|-Time To Live: " << +iph.ip_ttl << endl;
    os << "\t|-Protocol: " << +iph.ip_p << endl;
    os << "\t|-Header Checksum: " << iph.ip_sum << endl;
    os << "\t|-Source IP: " << inet_ntoa(iph.ip_src) << endl;
    os << "\t|-Destination IP: " << inet_ntoa(iph.ip_dst) << endl;
    os << endl;
    os.copyfmt(tmp);
    return os;
}

ostream& operator<<(ostream& os, const udphdr& udp) {
    std::ios tmp {NULL};
    tmp.copyfmt(os);
    os << "UDP Header" << endl;
    os << "\t|-Source Port: " << udp.uh_sport << endl;
    os << "\t|-Destination Port: " << udp.uh_dport << endl;
    os << "\t|-UDP Length: " << udp.uh_ulen << endl;
    os << "\t|-UDP Checksum: " << udp.uh_sum << endl;
    os << endl;
    os.copyfmt(tmp);
    return os;
}

ostream& operator<<(ostream& os, const tcphdr& tcp) {
    std::ios tmp {NULL};
    tmp.copyfmt(os);
    os << "TCP Header" << endl;
    os << "\t|-Source Port: " << tcp.th_sport << endl;
    os << "\t|-Destination Port: " << tcp.th_dport << endl;
    os << "\t|-Sequence Number: " << tcp.th_seq << endl;
    os << "\t|-Ack Number: " << tcp.th_ack << endl;
    os << "\t|-Header Length (Offset): " << tcp.th_off << " dwords" << endl;
    os << "\t|-Flags: " << endl;
    
    // flag unpacking
    os << "\t\t|-Urgent: " << (tcp.th_flags & TH_URG) << endl;
    os << "\t\t|-Ack: " << (tcp.th_flags & TH_ACK) << endl;
    os << "\t\t|-Push: " << (tcp.th_flags & TH_PUSH) << endl;
    os << "\t\t|-Reset: " << (tcp.th_flags & TH_RST) << endl;
    os << "\t\t|-Sync: " << (tcp.th_flags & TH_SYN) << endl;
    os << "\t\t|-Finish: " << (tcp.th_flags & TH_FIN) << endl;
    os << "\t\t|-ECE: " << (tcp.th_flags & TH_ECE) << endl;
    os << "\t\t|-CWR: " << (tcp.th_flags & TH_CWR) << endl;
    
    os << "\t|-Window Size: " << tcp.th_win << endl;
    os << "\t|-Checksum: " << tcp.th_sum << endl;
    os << "\t|-Urgent Pointer: " << tcp.th_urp << endl;
    os << endl;
    os.copyfmt(tmp);
    return os;
}
