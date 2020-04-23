//
//  BPFDevice.cpp
//  tcp_demo
//
//  Created by Robert Arnott on 4/21/20.
//  Copyright © 2020 Robert Arnott. All rights reserved.
//

#include "BPFDevice.hpp"

using std::string;
using std::unique_ptr;
using std::shared_ptr;
using std::cout;
using std::cerr;
using std::endl;

ssize_t BPFDevice::get_max_buffer_len() {
    return max_buffer_len;
}

size_t BPFDevice::get_last_read_len() {
    return last_read_len;
}

size_t BPFDevice::get_curr_bytes_consumed() {
    return curr_bytes_consumed;
}

void BPFDevice::set_buffer_len(ssize_t new_len) {
    if(ioctl(fd, BIOCSBLEN, &max_buffer_len) == -1) {
        std::cout << "Could not set buffer len: " << strerror(errno) << std::endl;
    }
}

string BPFDevice::get_device_name() {
    return device;
}

std::pair<unique_ptr<byte_t>,size_t> BPFDevice::readPacket() {
    if(curr_bytes_consumed >= last_read_len) {
        cout << "Refilling buffer ..." << endl;
        clear_buffer();
        refill_buffer();
    }
    unique_ptr<bpf_hdr> bhdr = strip_header<bpf_hdr>(buffer.get()+curr_bytes_consumed);
    
    if (bhdr->bh_caplen != bhdr->bh_datalen) {
        cerr << "Packet truncated" << endl;
    }
    
    // Copy data from buffer (just the underlying packet)
    size_t data_size = (bhdr->bh_caplen);
    unique_ptr<byte_t> out {new byte_t[data_size]};
    memcpy(out.get(), buffer.get()+curr_bytes_consumed+(bhdr->bh_hdrlen), data_size);
    
    // Update the bytes consumed
    curr_bytes_consumed += BPF_WORDALIGN(bhdr->bh_caplen + bhdr->bh_hdrlen);
    
    return {std::move(out), data_size};
}

std::pair<unique_ptr<byte_t>,size_t> BPFDevice::readRaw() {
    if(curr_bytes_consumed >= last_read_len) {
        cout << "Refilling buffer ..." << endl;
        clear_buffer();
        refill_buffer();
    }
    unique_ptr<bpf_hdr> bhdr = strip_header<bpf_hdr>(buffer.get()+curr_bytes_consumed);
    cout << "Captured " << std::dec << bhdr->bh_caplen << " bytes from original length of " << bhdr->bh_datalen << endl;
    if (bhdr->bh_caplen != bhdr->bh_datalen) {
        cerr << "Packet truncated" << endl;
    }
    
    // Copy data (entire wrapped packet)
    size_t data_size = bhdr->bh_caplen + bhdr->bh_hdrlen;
    unique_ptr<byte_t> out {new byte_t[data_size]};
    memcpy(out.get(), buffer.get()+curr_bytes_consumed, data_size);
    
    // Update bytes consumed
    curr_bytes_consumed += BPF_WORDALIGN(data_size);
    
    return {std::move(out), data_size};
}
