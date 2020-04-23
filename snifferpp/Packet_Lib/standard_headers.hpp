//
//  standard_headers.hpp
//  tcp_demo
//
//  Created by Robert Arnott on 4/19/20.
//  Copyright © 2020 Robert Arnott. All rights reserved.
//

#ifndef standard_headers_hpp
#define standard_headers_hpp

#include <iostream>
#include <string>
#include <exception>
#include <cstdlib>
#include <iomanip>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

using byte_t = char; // Used by the entire library to represent packet data

// Overload output functions for headers
std::ostream& operator<<(std::ostream& os, const ether_header& eth);

std::ostream& operator<<(std::ostream& os, const ip& iph);

std::ostream& operator<<(std::ostream& os, const udphdr& udp);

std::ostream& operator<<(std::ostream& os, const tcphdr& tcp);

/*
 Strip Packet Headers from the start of the buffer -- caller responsibility for passing a pointer to the correct starting point
 
 One of the few functions in the library the operates with naked pointer -- responsibility for freeing the underlying resource is with the caller
 */
template <typename Header>
std::unique_ptr<Header> strip_header(byte_t* buffer) {
    size_t hdr_len = sizeof(Header);
    std::unique_ptr<Header> h {new Header{}};
    memcpy(h.get(),buffer,hdr_len);
    return h;
}

#endif /* standard_headers_hpp */
