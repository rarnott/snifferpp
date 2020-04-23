//
//  Packet.hpp
//  tcp_demo
//
//  Created by Robert Arnott on 4/19/20.
//  Copyright © 2020 Robert Arnott. All rights reserved.
//

#ifndef Packet_hpp
#define Packet_hpp

#include "PacketHeader.hpp"

/*
 Represents a complete packet (from the ethernet header to the data)
 */
class Packet {
private:
    PacketHeader phdr;
    std::vector<byte_t> data;
    
public:
    Packet(const PacketHeader& phdr, std::vector<byte_t> d) :phdr{phdr}, data{d} {};
    Packet(PacketHeader&& phdr, std::vector<byte_t> d) :phdr{phdr}, data{d} {};
    
    Packet(const Packet& pack) :phdr{pack.phdr}, data{pack.data} {};
    Packet(Packet&& pack) :phdr{std::move(pack.phdr)}, data{std::move(pack.data)} {};
    
    Packet& operator=(const Packet& pack) {
        Packet{pack};
        return *this;
    }
    
    Packet& operator=(Packet&& pack) {
        Packet{pack};
        return *this;
    }
    
    PacketHeader get_header(void);
    std::vector<byte_t> get_data(void);
    
    /*
     Stitches together the bytes of the underlying types
     */
    std::vector<byte_t> get_bytes(void);
};

std::ostream& operator<<(std::ostream& os, Packet p);

#endif /* Packet_hpp */
