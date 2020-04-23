//
//  Packet.cpp
//  tcp_demo
//
//  Created by Robert Arnott on 4/19/20.
//  Copyright © 2020 Robert Arnott. All rights reserved.
//

#include "Packet.hpp"

using std::vector;
using std::endl;

PacketHeader Packet::get_header() {
    return phdr;
}

vector<byte_t> Packet::get_data() {
    return data;
}

vector<byte_t> Packet::get_bytes() {
    vector<byte_t> ph_b = phdr.get_bytes();
    vector<byte_t> res;
    res.reserve(ph_b.size()+data.size());
    res.insert(res.end(), ph_b.begin(), ph_b.end());
    res.insert(res.end(), data.begin(), data.end());
    return res;
}

std::ostream& operator<<(std::ostream& os, Packet p){
    std::ios tmp {NULL};
    tmp.copyfmt(os);
    os << "Packet" << endl;
    os << p.get_header() << endl;
    os << "Raw Packet Data" << endl;
    for(auto b : p.get_data()) {
        os << std::setfill('0') << std::setw(2) << std::hex << +b << " ";
    } // TODO: this is a jank way of doing this, unclear if right
    os << endl;
    os.copyfmt(tmp);
    
    os << "ASCII-encoded Packet Data" << endl;
    for(auto b : p.get_data()) {
        os << b;
    } // TODO: this is a jank way of doing this, unclear if right
    os.copyfmt(tmp);
    return os;
}
