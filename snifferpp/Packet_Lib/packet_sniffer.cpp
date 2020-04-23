//
//  packet_sniffer.cpp
//  tcp_demo
//
//  Created by Robert Arnott on 4/19/20.
//  Copyright © 2020 Robert Arnott. All rights reserved.
//

#include "packet_sniffer.hpp"

using std::unique_ptr;
using std::shared_ptr;
using std::string;
using std::cerr;
using std::cout;
using std::endl;
using std::ostream;

Packet strip_packet(unique_ptr<byte_t> buffer, size_t buff_len) {
    if(buff_len < sizeof(ether_header) + sizeof(ip)){
        throw InvalidInput {"In parsing ethernet and IP headers"};
    }
    size_t data_offset = 0;
    
    // Strip Ethernet Header
    WrappedHeader<ether_header> eth {strip_header<ether_header>(buffer.get()+data_offset)};
    data_offset += sizeof(ether_header);
    
    // Strip IP Header
    
    WrappedHeader<ip> iph {strip_header<ip>(buffer.get()+data_offset)};
    data_offset += 4*(iph.get_header()->ip_hl);
    
    // Strip TCP or UDP depending on packet type
    TransportHeader tph;
    switch (iph.get_header()->ip_p) {
        case IPPROTO_TCP: {
            if(buff_len < data_offset+sizeof(tcphdr)){
                throw InvalidInput {"In parsing TCP header"};
            }
            WrappedHeader<tcphdr> tcp {strip_header<tcphdr>(buffer.get()+data_offset)};
            tph = TransportHeader {tcp}; // works
            data_offset += tph.get_tcp_header().get_header()->th_off;
            break;
        }
        case IPPROTO_UDP: {
            if(buff_len < data_offset+sizeof(udphdr)){
                throw InvalidInput {"In parsing UDP header"};
            }
            WrappedHeader<udphdr> udp {strip_header<udphdr>(buffer.get()+data_offset)};
            tph = TransportHeader {udp};
            data_offset += sizeof(udphdr);
            break;
        }
        default: {
            cerr << "Unsupported Transport Protocol" << endl;
            throw UnsupportedProtocol{"In parsing transport protocol: "};
        }
    }
    
    // Can now pack the header
    PacketHeader phdr {std::move(eth), std::move(iph), std::move(tph), iph.get_header()->ip_p};
    
    // The rest is assumed to be data
    std::vector<byte_t> data {buffer.get()+data_offset, buffer.get()+buff_len};
    
    return Packet {std::move(phdr), std::move(data)};
}
