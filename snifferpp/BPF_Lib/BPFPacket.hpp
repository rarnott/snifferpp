//
//  BPFPacket.hpp
//  tcp_demo
//
//  Created by Robert Arnott on 4/21/20.
//  Copyright © 2020 Robert Arnott. All rights reserved.
//

#ifndef BPFPacket_hpp
#define BPFPacket_hpp

#include <iostream>
#include <iomanip>
#include <ctime>
#include <net/bpf.h>
#include "Packet.hpp"

class BPFPacket {
private:
    WrappedHeader<bpf_hdr> bhdr;
    Packet p;
public:
    BPFPacket(const WrappedHeader<bpf_hdr>& bhdr, const Packet& p) :bhdr{bhdr}, p{p} {};
    BPFPacket(WrappedHeader<bpf_hdr>&& bhdr, Packet&&p) :bhdr{bhdr}, p{p} {};
    
    BPFPacket(const BPFPacket& bp) : bhdr{bp.bhdr}, p{bp.p} {};
    BPFPacket(BPFPacket&& bp) : bhdr{std::move(bp.bhdr)}, p{std::move(bp.p)} {};
    
    WrappedHeader<bpf_hdr> get_bpf_header();
    Packet get_packet();
    
    std::vector<byte_t> get_bytes();
};

std::ostream& operator<<(std::ostream& os, const bpf_hdr& bhdr);
std::ostream& operator<<(std::ostream& os, WrappedHeader<bpf_hdr> bhdr);
std::ostream& operator<<(std::ostream& os, BPFPacket p);

#endif /* BPFPacket_hpp */
