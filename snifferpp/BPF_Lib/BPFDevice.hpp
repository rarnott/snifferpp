//
//  BPFDevice.hpp
//  tcp_demo
//
//  Created by Robert Arnott on 4/21/20.
//  Copyright © 2020 Robert Arnott. All rights reserved.
//

#ifndef BPFDevice_hpp
#define BPFDevice_hpp

#include <iostream>
#include <string>
#include <exception>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include "Packet.hpp"
#include "BPFPacket.hpp"

/*
Used to signal that a BPF device could not be opened
*/
class BPFDeviceNotOpened : public std::exception {
private:
    std::string message;
public:
    BPFDeviceNotOpened() {};
    BPFDeviceNotOpened(std::string m) :message{m} {};
    
    const char * what() {
        message += "BPF Device not opened";
        return message.c_str();
    }
};

/*
 Used by BPFDevice to signal that it could not read from the BPF
 */
class CouldNotRead : public std::exception {
private:
    std::string message;
public:
    CouldNotRead() {};
    CouldNotRead(std::string m) :message{m} {};
    
    const char * what() {
        message += "Could not read from BPF";
        return message.c_str();
    }
};

/*
 Interface to a BPF, which manages the file descriptor and holds a buffer
 
 Supports reading packets (as defined in Packet.hpp -- Packet_Lib at a time as well as reading raw data
 */
class BPFDevice {
private:
    int fd;
    std::string device;
    ssize_t max_buffer_len; // Buffer params
    size_t last_read_len, curr_bytes_consumed; // Where we are in buffer
    std::unique_ptr<byte_t> buffer;
    
    void close(void) {
        if (fd != -1) {
            ::close(fd);
        }
        buffer.reset(); // Free the underlying buffer -- for closing
    }
    
    // Clearing buffer for refilling (not for closing)
    void clear_buffer(void) {
        memset(buffer.get(), 0, max_buffer_len);
    }
    
    void refill_buffer(void) {
        size_t len;
        if((len = read(fd, buffer.get(),max_buffer_len)) == -1) {
            std::string m {"Refilling buffer: "};
            m += strerror(errno);
            m += "\n";
            throw CouldNotRead {m};
        }
        last_read_len = len;
        curr_bytes_consumed = 0;
        std::cout << "Read " << len << " bytes" << std::endl;
    }
    
public:
    
    BPFDevice() :fd{-1}, max_buffer_len{0}, curr_bytes_consumed{0}, last_read_len{0} {};
    
    BPFDevice(int fd, std::string dev) :fd{fd}, device{dev}, max_buffer_len{0}, curr_bytes_consumed{0}, last_read_len{0} {
        if (fd < 0) {
            throw BPFDeviceNotOpened {"Device Constructor: "};
        }
        ioctl(fd, BIOCGBLEN, &max_buffer_len); // Fill in buffer length
        buffer.reset(new byte_t[max_buffer_len]);
        memset(buffer.get(), 0, max_buffer_len);
    }
    
    BPFDevice(int fd, std::string dev, ssize_t len) :fd{fd}, device{dev}, max_buffer_len{len}, curr_bytes_consumed{0}, last_read_len{0} {
        if (fd < 0) {
            throw BPFDeviceNotOpened {"Device Constructor: "};
        }
        ssize_t tmp;
        ioctl(fd, BIOCGBLEN, &tmp); // Fill in buffer length
        if (tmp != max_buffer_len) {
            throw BPFDeviceNotOpened {"Device Constructor: buffer length not equal to provided length: "};
        }
        buffer.reset(new byte_t[max_buffer_len]);
        memset(buffer.get(), 0, max_buffer_len);
    }
    
    
    BPFDevice(const BPFDevice& other)= delete;
    BPFDevice operator=(const BPFDevice& other)=delete;
    
    BPFDevice(BPFDevice&& other) : fd{other.fd}, device{std::move(other.device)}, max_buffer_len{std::move(other.max_buffer_len)}, last_read_len{std::move(other.last_read_len)}, curr_bytes_consumed{std::move(other.curr_bytes_consumed)}, buffer{std::move(other.buffer)} {};
    
    BPFDevice& operator=(BPFDevice&& other){
        close();
        BPFDevice{std::move(other)};
        return *this;
    }
    
    ~BPFDevice() {
        std::cout << "Closing " << fd << std::endl;
        close();
    };
    
    ssize_t get_max_buffer_len(void);
    size_t get_last_read_len(void);
    size_t get_curr_bytes_consumed(void);
    std::string get_device_name(void);
    
    void set_buffer_len(ssize_t new_len);
    
    /*
     Does not return BPF header
     */
    std::pair<std::unique_ptr<byte_t>,size_t> readPacket(void);
    
    /*
     Includes BPF Header
     */
    std::pair<std::unique_ptr<byte_t>,size_t> readRaw(void);
};

#endif /* BPFDevice_hpp */
