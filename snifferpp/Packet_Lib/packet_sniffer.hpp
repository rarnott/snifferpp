//
//  packet_sniffer.hpp
//  tcp_demo
//
//  Created by Robert Arnott on 4/19/20.
//  Copyright © 2020 Robert Arnott. All rights reserved.
//

#ifndef packet_sniffer_hpp
#define packet_sniffer_hpp

#include <iostream>
#include <exception>
#include <string>
#include "standard_headers.hpp"
#include "Packet.hpp"

/*
 For Flagging that the sniffer has encountered a transport protocol it does not support
 */
class UnsupportedProtocol : public std::exception {
private:
    std::string message;
    
public:
    UnsupportedProtocol() {};
    UnsupportedProtocol(std::string message) :message{message} {};
    
    const char* what(void) {
        message += "Attempted to parse packet of unsupported protocol";
        return message.c_str();
    }
};

/*
 For Flagging that the sniffer was given a buffer length not long enough to
    feasibly represent the packet
*/
class InvalidInput : public std::exception {
private:
    std::string message;
    
public:
    InvalidInput() {};
    InvalidInput(std::string message) :message{message} {};
    
    const char* what(void) {
        message += "Buffer not long enough to feasibly contain packet";
        return message.c_str();
    }
};

/*
 Attempts to strip a TCP or UDP packet from the buffer
    If the IP header suggests an alternate packet, throws UnsupportedProtocolPacket
 
 Inputs:    buffer: unique_ptr to byte_t buffer containing the packet.
            buff_len: size of the data on the buffer (to be used to check whether
                        we can strip out various components and where to stop)
 
 Return:    Packet (as declared in Packet.hpp)
*/
Packet strip_packet(std::unique_ptr<byte_t> buffer, size_t buffer_len);

#endif /* packet_sniffer_hpp */
