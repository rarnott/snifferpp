//
//  BPF_util.cpp
//  tcp_demo
//
//  Created by Robert Arnott on 4/21/20.
//  Copyright © 2020 Robert Arnott. All rights reserved.
//

#include "BPF_util.hpp"

using std::unique_ptr;
using std::string;
using std::ostream;
using std::cout;
using std::cerr;
using std::endl;

int pick_device() {
    string bpfDeviceName = "";
    int max_device = 5;
    int fd;
    for (int i = 0; i < max_device; ++i) {
        bpfDeviceName = "/dev/bpf" + std::to_string(i);
        cout << "Trying " << bpfDeviceName << endl;
        if((fd = open(bpfDeviceName.c_str(), O_RDWR)) != -1) {
            cout << "Chose " << bpfDeviceName << endl;
           return fd;
        }
    }
    throw BPFDeviceNotOpened {};
}

unique_ptr<BPFDevice> open_new_device(string physicalDevice, ssize_t buffer_len) {
    int fd = pick_device();
    cout << "Chose File Descriptor " << fd << endl;
    
    if(ioctl(fd, BIOCSBLEN, &buffer_len) == -1) {
        cout << "Could set buffer len: " << strerror(errno) << endl;
    }
    
    ifreq if_req;
    strcpy(if_req.ifr_name, physicalDevice.c_str());
    if(ioctl(fd, BIOCSETIF, &if_req) == -1) {
        cout << "Could not set interface: " << strerror(errno) << endl;
    }
    
    if(ioctl(fd, BIOCPROMISC, nullptr) == -1) {
        cout << "Could not set promiscuous mode: " << strerror(errno) << endl;
    }
    
    unique_ptr<BPFDevice> res;
    try {
        res.reset(new BPFDevice {fd, physicalDevice, buffer_len});
    } catch(BPFDeviceNotOpened e) {
        cerr << e.what() << endl;
        throw;
    }
    return res;
}
