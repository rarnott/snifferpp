# snifferpp
Packet Sniffer I wrote while trying to replicate TCP in C++. I was developing on MacOS, so it uses Berklee Packet Filters (BPF).

Part of the goal here was to try to C++-ify a more traditionally C workflow, so you will see lots of classes here acting as resource handles (for example BPFDevice, which essentially manages the file descriptor for the BPF and helps buffer reads). 
