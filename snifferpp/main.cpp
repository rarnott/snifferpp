//
//  main.cpp
//  tcp_demo
//
//  Created by Robert Arnott on 4/18/20.
//  Copyright © 2020 Robert Arnott. All rights reserved.
//

#include <iostream>
#include <iomanip>
#include <map>
#include <unordered_map>
#include "packet_sniffer.hpp"
#include "BPF_util.hpp"

using std::unordered_map;
using std::string;
using std::vector;
using std::unique_ptr;
using std::pair;
using std::cout;
using std::cerr;
using std::endl;

// Generic code for parsing commandline arguments into a map
// Assume --key value pairs.
unordered_map<string, string> get_arg_dict(int argc, const char * argv[]) {
    unordered_map<string, string> arg_dict;
    
    if (argc == 1 || !(argc % 2)) { // Expect an odd number > 1
        return arg_dict;
    }
    
    for (int i = 1; i < argc; i+=2) {
        arg_dict[string {argv[i]}] = string {argv[i+1]};
    }
    return arg_dict;
}

void print_bytes(vector<byte_t> bytes) {
    for(auto b : bytes) {
        std::cout << std::setfill('0') << std::setw(2) << std::hex << (0xff & (unsigned char) b) << " ";
    }
    std::cout << std::endl;
 }


int main(int argc, const char * argv[]) {
    unordered_map<string, string> arg_dict = get_arg_dict(argc, argv);
    
    int buffer_len = 4096;
    unique_ptr<BPFDevice> dev = open_new_device("en0", buffer_len);
    pair<unique_ptr<byte_t>,size_t> out;
    bool found_packet = false;
    do {
        try {
            // Read
            out = dev->readRaw();
            
            // Strip bpf header
            unique_ptr<bpf_hdr> bhdr = strip_header<bpf_hdr>(out.first.get());
            cout << *bhdr << endl;
            
            // Copy remaining packet from buffer
            size_t data_len = out.second-(bhdr->bh_hdrlen);
            unique_ptr<byte_t> pack {new byte_t[data_len]};
            memcpy(pack.get(),out.first.get()+bhdr->bh_hdrlen,data_len);
            
            // Strip underlying packet
            Packet p = strip_packet(std::move(pack), data_len);
            found_packet=true;
            cout << p << endl;
        } catch(CouldNotRead e) {
            cerr << e.what() << endl;
        } catch(UnsupportedProtocol e) {
            cerr << e.what() << endl;
        }
    } while (!found_packet && dev->get_curr_bytes_consumed() < dev->get_last_read_len());
    
    return 0;
}
