//
//  BPF_util.hpp
//  tcp_demo
//
//  Created by Robert Arnott on 4/21/20.
//  Copyright © 2020 Robert Arnott. All rights reserved.
//

#ifndef BPF_util_hpp
#define BPF_util_hpp

#include <net/bpf.h>
#include "BPFDevice.hpp"
#include "BPFPacket.hpp"
#include "PacketHeader.hpp"


int pickDevice();
std::unique_ptr<BPFDevice> open_new_device(std::string physicalDevice, ssize_t buffer_len);

#endif /* BPF_util_hpp */
