//
//  PacketHeader.hpp
//  tcp_demo
//
//  Created by Robert Arnott on 4/20/20.
//  Copyright © 2020 Robert Arnott. All rights reserved.
//

#ifndef PacketHeader_hpp
#define PacketHeader_hpp

#include <iostream>
#include <cstddef>
#include <vector>
#include <exception>
#include "standard_headers.hpp"

/*
 For representing a "Standard" network header as an object (rather than a struct or pointer to struct)
 
 Currently support (provide overriden print operators) for ether_header, ip, tcphdr, udphdr, and bpf_hdr (though the latter is defined in BPF_Lib).
 
 Guaranteed to destroy headers at the end of its lifetime and when being reassigned
 
 *** We currently DO NOT do any validating of the headers to check if they are valid ***
 */
template <typename StandardHeader>
class WrappedHeader {
private:
    std::unique_ptr<StandardHeader> sth;
    
public:
    WrappedHeader() {};
    WrappedHeader(std::unique_ptr<StandardHeader> sth) :sth{sth.release()} {};
    
    WrappedHeader(const WrappedHeader<StandardHeader>& other) {
        sth.reset(new StandardHeader{});
        memcpy(sth.get(), other.sth.get(), sizeof(StandardHeader));
    }
    WrappedHeader(WrappedHeader<StandardHeader>&& other) : sth{other.sth.release()} {};
    
    WrappedHeader<StandardHeader>& operator=(const WrappedHeader<StandardHeader>& other) {
        clear();
        sth.reset(new StandardHeader{});
        memcpy(sth.get(), other.sth.get(), sizeof(StandardHeader));
        return *this;
    }
    
    WrappedHeader<StandardHeader>& operator=(WrappedHeader<StandardHeader>&& other) {
        clear();
        sth.reset(other.sth.release());
        return *this;
    }
    
    void clear(void) {
        sth.reset();
    }
    
    ~WrappedHeader() { clear();}
    
    // TODO: do we want to return pointers to copies of the stored values or to the actual objects
    std::unique_ptr<StandardHeader> get_header() {
        std::unique_ptr<StandardHeader> out {new StandardHeader {}};
        memcpy(out.get(),sth.get(), sizeof(StandardHeader));
        return out;
    }
    
    std::vector<byte_t> get_bytes(void) {
        byte_t* bytes = new byte_t[sizeof(StandardHeader)];
        memcpy(bytes, sth.get(), sizeof(StandardHeader));
        return std::vector<byte_t> {bytes,bytes+sizeof(StandardHeader)};
    }
};
    
/*
 Utilities for the transport protocol:
 Since we can have a multitude of transport protocols, We define an extra layer of abstraction for the transport protocol header, with a class that can hold to any one of the headers for the protocols we support
 */

/*
 For checking that accesses to TransportHeader headers are for the correct header.
 */
class WrongTransportProtocol : public std::exception {
private:
    std::string message;
public:
    WrongTransportProtocol() :message{} {};
    WrongTransportProtocol(std::string m) :message{m} {};
    
    const char * what(void) {
        message += "Attempted to access header for incorrect transport protocol";
        return message.c_str();
    }
};

/*
 Represents the distinct transport protocols in a strongly-typed manner (versus the macro definitions)
 */
enum class TransportKind {TCP, UDP};
    
std::ostream& operator<<(std::ostream& os, TransportKind k);
    
/*
 Represents the transport header, can hold any supported protocol at a given time, but is guanteed to only hold one at a time, of the type given by get_kind()
 */
class TransportHeader {
private:
    WrappedHeader<udphdr> udp;
    WrappedHeader<tcphdr> tcp;
    TransportKind kind;
    
    void clear() {
        udp.clear();
        tcp.clear();
    }
    
public:
    // We provide a default constructor but it will throw exceptions whenever the returned object is used
    TransportHeader() {};
    
    TransportHeader(WrappedHeader<tcphdr> tcph) :tcp{tcph}, kind{TransportKind::TCP} {};
    TransportHeader(WrappedHeader<udphdr> udph) :udp{udph}, kind{TransportKind::UDP} {};
    
    TransportHeader(const TransportHeader& tph) :kind{tph.kind} {
        switch (kind) {
            case TransportKind::TCP:
                tcp = tph.tcp;
                break;
            case TransportKind::UDP:
                udp = tph.udp;
                break;
            default:
                std::cerr << "Copying invalid TransportHeader" << std::endl;
        }
    }
    
    TransportHeader(TransportHeader&& tph) :kind{tph.kind} {
        switch (kind) {
            case TransportKind::TCP:
                tcp = std::move(tph.tcp);
                break;
            case TransportKind::UDP:
                udp = std::move(tph.udp);
                break;
            default:
                std::cerr << "Moving invalid TransportHeader" << std::endl;
        }
    };
    
    TransportHeader& operator=(const TransportHeader& tph) {
        clear();
        kind = tph.kind;
        switch (kind) {
            case TransportKind::TCP:
                tcp = tph.tcp;
                break;
            case TransportKind::UDP:
                udp = tph.udp;
                break;
            default:
                std::cerr << "Copying invalid TransportHeader" << std::endl;
        }
        return *this;
    };
    
    TransportHeader& operator=(TransportHeader&& tph) {
        clear();
        kind = tph.kind;
        switch (kind) {
            case TransportKind::TCP:
                tcp = std::move(tph.tcp);
                break;
            case TransportKind::UDP:
                udp = std::move(tph.udp);
                break;
            default:
                std::cerr << "Moving invalid TransportHeader" << std::endl;
        }
        return *this;
    };
    
    WrappedHeader<udphdr> get_udp_header(void);
    WrappedHeader<tcphdr> get_tcp_header(void);
    TransportKind get_kind(void);
    
    /*
     Returns vector of bytes representing the stored transport protocol
     If the protocol is undefined (ex. for a default-initialized instances), we return an empty vector.
     */
    std::vector<byte_t> get_bytes(void);
};

/*
 For representing a complete packet header. Restricted by the transport protocols we support.
 Facillitates decoding a packet via the get_bytes function (which will stitch together the packet bytes
 */
class PacketHeader {
private:
    WrappedHeader<ether_header> eth;
    WrappedHeader<ip> iph;
    TransportHeader tph;
    int transport_protocol;
    
public:
    PacketHeader(WrappedHeader<ether_header>& ethh, WrappedHeader<ip>& iphh, TransportHeader& tphh, int p) :eth{ethh}, iph{iphh}, tph{tphh}, transport_protocol{p} {};
    PacketHeader(WrappedHeader<ether_header>&& ethh, WrappedHeader<ip>&& iphh, TransportHeader&& tphh, int p) :eth{std::move(ethh)}, iph{std::move(iphh)}, tph{std::move(tphh)}, transport_protocol{p} {};
    
    PacketHeader(const PacketHeader& phdr) :eth{phdr.eth}, iph{phdr.iph}, tph{phdr.tph}, transport_protocol{phdr.transport_protocol} {};
    PacketHeader(PacketHeader&& phdr) :eth{std::move(phdr.eth)}, iph{std::move(phdr.iph)}, tph{std::move(phdr.tph)}, transport_protocol{std::move(phdr.transport_protocol)} {};
    
    PacketHeader& operator=(const PacketHeader& phdr) {
        PacketHeader {phdr};
        return *this;
    }
    PacketHeader& operator=(PacketHeader&& phdr) {
        PacketHeader {phdr};
        return *this;
    }
    
    // Getters -- currently return copies as defined by the underlying classes
    WrappedHeader<ether_header> get_ether_header(void);
    WrappedHeader<ip> get_ip_header(void);
    TransportHeader get_transport_header(void);
    TransportKind get_transport_kind(void);
    int get_protocol(void);
    
    std::vector<byte_t> get_bytes(void);
};

std::ostream& operator<<(std::ostream& os, WrappedHeader<ether_header> phdr);
std::ostream& operator<<(std::ostream& os, WrappedHeader<ip> phdr);
std::ostream& operator<<(std::ostream& os, WrappedHeader<udphdr> phdr);
std::ostream& operator<<(std::ostream& os, WrappedHeader<tcphdr> phdr);

/*
 Currently we will just print to error if the TransportHeader is not defined when we try to print.
 */
std::ostream& operator<<(std::ostream& os, TransportHeader phdr);

std::ostream& operator<<(std::ostream& os, PacketHeader phdr);

#endif /* PacketHeader_hpp */
