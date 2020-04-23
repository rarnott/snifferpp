//
//  PacketHeader.cpp
//  tcp_demo
//
//  Created by Robert Arnott on 4/20/20.
//  Copyright © 2020 Robert Arnott. All rights reserved.
//

#include "PacketHeader.hpp"

using std::unique_ptr;
using std::shared_ptr;
using std::ostream;
using std::cout;
using std::cerr;
using std::endl;
using std::vector;

std::ostream& operator<<(std::ostream& os, TransportKind k){
    switch (k) {
        case TransportKind::TCP:
            os << "TCP";
            break;
        case TransportKind::UDP:
            os << "UDP";
            break;
        default:
            os << "Invalid";
    }
    return os;
}

// TransportHeader
WrappedHeader<udphdr> TransportHeader::get_udp_header() {
    if (kind != TransportKind::UDP) {
        throw WrongTransportProtocol {};
    }
    return udp;
}

WrappedHeader<tcphdr> TransportHeader::get_tcp_header() {
    if (kind != TransportKind::TCP) {
        throw WrongTransportProtocol {};
    }
    return tcp;
}

TransportKind TransportHeader::get_kind() { return kind; }

vector<byte_t> TransportHeader::get_bytes(void) {
    size_t size;
    byte_t* bytes;
    switch (kind) {
        case TransportKind::TCP:
            size = sizeof(tcphdr);
            bytes = new byte_t[size];
            memcpy(bytes, tcp.get_header().get(), size);
            break;
        case TransportKind::UDP:
            size = sizeof(udphdr);
            bytes = new byte_t[size];
            memcpy(bytes, udp.get_header().get(), size);
            break;
        default:
            std::cerr << "Attempted to get bytes of empty transport header" << endl;
            return vector<byte_t> {};
    }
    return vector<byte_t> {bytes,bytes+size};
}

//Packet Header
WrappedHeader<ether_header> PacketHeader::get_ether_header() { return eth; }

WrappedHeader<ip> PacketHeader::get_ip_header() { return iph; }

TransportHeader PacketHeader::get_transport_header() { return tph; }

TransportKind PacketHeader::get_transport_kind() { return tph.get_kind(); }

vector<byte_t> PacketHeader::get_bytes(void) {
    vector<byte_t> eth_bytes = eth.get_bytes();
    vector<byte_t> ip_bytes = iph.get_bytes();
    vector<byte_t> transp_bytes = tph.get_bytes();
    
    vector<byte_t> res;
    res.reserve(eth_bytes.size() + ip_bytes.size() + transp_bytes.size());
    res.insert(res.end(), eth_bytes.begin(), eth_bytes.end());
    res.insert(res.end(), ip_bytes.begin(), ip_bytes.end());
    res.insert(res.end(), transp_bytes.begin(), transp_bytes.end());
    
    return res;
}

            
// Output helpers
ostream& operator<<(ostream& os, WrappedHeader<ether_header> whdr) {
    return os << *whdr.get_header();
}
    
ostream& operator<<(ostream& os, WrappedHeader<ip> whdr) {
    return os << *whdr.get_header();
}
    
ostream& operator<<(ostream& os, WrappedHeader<udphdr> whdr) {
    return os << *whdr.get_header();
}
    
ostream& operator<<(ostream& os, WrappedHeader<tcphdr> whdr) {
    return os << *whdr.get_header();
}

ostream& operator<<(ostream& os, TransportHeader tph) {
    switch (tph.get_kind()) {
        case TransportKind::TCP:
            return os << tph.get_tcp_header();
        case TransportKind::UDP:
            return os << tph.get_udp_header();
        default:
            cerr << "Tried to print invalid header" << endl;
    return os;
    }
}
    
ostream& operator<<(ostream& os, PacketHeader phdr) {
    os << phdr.get_ether_header() << endl;
    os << phdr.get_ip_header() << endl;
    os << phdr.get_transport_header() << endl;
    return os;
}
