//
//  BPFPacket.cpp
//  tcp_demo
//
//  Created by Robert Arnott on 4/21/20.
//  Copyright © 2020 Robert Arnott. All rights reserved.
//

#include "BPFPacket.hpp"

using std::vector;
using std::ostream;
using std::cout;
using std::endl;

WrappedHeader<bpf_hdr> BPFPacket::get_bpf_header() {
    return bhdr;
}

Packet BPFPacket::get_packet() {
    return p;
}

vector<byte_t> BPFPacket::get_bytes() {
    vector<byte_t> bhdr_b = bhdr.get_bytes();
    vector<byte_t> p_b = p.get_bytes();
    vector<byte_t> res;
    res.reserve(bhdr_b.size() + p_b.size());
    res.insert(res.end(), bhdr_b.begin(), bhdr_b.end());
    res.insert(res.end(), p_b.begin(), p_b.end());
    return res;
}

// BPF Header utils
ostream& operator<<(ostream& os, const bpf_hdr& bhdr) {
    std::ios tmp {NULL};
    tmp.copyfmt(os);
    os << "BPF Header" << endl;
    time_t packet_time {bhdr.bh_tstamp.tv_sec};
    os << "\t|-Timestamp: " << std::put_time(std::localtime(&packet_time), "%c %Z") << " and " << bhdr.bh_tstamp.tv_usec << " usec" << endl;
    os << "\t|-Captured length: " << bhdr.bh_caplen << " Bytes" << endl;
    os << "\t|-Original length: " << bhdr.bh_datalen << " Bytes" << endl;
    os << "\t|-Header length: " << bhdr.bh_hdrlen << " Bytes" << endl;
    os.copyfmt(tmp);
    return os;
}

ostream& operator<<(ostream& os, WrappedHeader<bpf_hdr> bhdr) {
    return os << *bhdr.get_header();
}
    
ostream& operator<<(ostream& os, BPFPacket p){
    os << "BPF Packet" << endl;
    os << p.get_bpf_header() << endl;
    os << p.get_packet() << endl;
    return os;
}
