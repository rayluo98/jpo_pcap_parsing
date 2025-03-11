#include <iostream>
#include "flag_structures.h"
#include <pcap.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

// Function prototype for jpExchangeDecoder
std::vector<Data> jpExchangeDecoder(const std::vector<uint8_t>& line);
#define ETHERTYPE_IP 0x0800
struct ether_header {
    u_char  ether_dhost[6];   // Destination MAC address
    u_char  ether_shost[6];   // Source MAC address
    u_short ether_type;       // Protocol type (e.g., IPv4, ARP)
};

struct ip {
    u_char ip_src[6];
    u_char ip_dst[6];
};

// Function to process the PCAP file
void process_pcap(const std::string& in_file, const std::string& out_file) {
    // Open the output file
    std::ofstream out(out_file);

    if (!out.is_open()) {
        std::cerr << "Error opening output file!" << std::endl;
        return;
    }

    // Open the PCAP file
    pcap_t* handle = pcap_open_offline(in_file.c_str(), nullptr);
    if (handle == nullptr) {
        std::cerr << "Error opening pcap file: " << pcap_geterr(handle) << std::endl;
        return;
    }

    struct pcap_pkthdr header;
    const u_char* pkt_data;
    int count = 0;
    uint64_t first_timestamp = 0;
    std::vector<std::vector<Data>> line_list;

    // Loop through all the packets in the PCAP
    while ((pkt_data = pcap_next(handle, &header)) != nullptr) {
        ether_header* eth_hdr = (struct ether_header*)pkt_data;

        // Check for IPv4
        if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
            ip* ip_pkt = (ip*)(pkt_data + sizeof(ether_header));

            // Get the source and destination IP addresses
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_pkt->ip_src, src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ip_pkt->ip_dst, dst_ip, INET_ADDRSTRLEN);

            // Extract payload data (equivalent to Ether[Raw].load[27:])
            std::vector<uint8_t> payload(pkt_data + sizeof(ether_header) + sizeof(ip),
                pkt_data + header.caplen);

            // Decode the payload using jpExchangeDecoder function
            line_list.push_back(jpExchangeDecoder(payload));
        }

        count++;
    }

    // Optionally write output (you can also print line_list or handle output more as needed)
    out.close();

    // Close the pcap handle
    pcap_close(handle);
}

// Function to decode big-endian data based on the format string
template<typename T>
T decode_big_endian(const std::vector<uint8_t>& data, size_t& index) {
    T result;
    std::memcpy(&result, &data[index], sizeof(T));
    // // Assuming the system might be little-endian and we need to convert to big-endian
    index += sizeof(T); // Move the index after reading the data
    return result;
}

// Function to handle the decoding process (like `jpExchangeDecoder`)
std::vector<Data> jpExchangeDecoder(const std::vector<uint8_t>& line) {
    size_t start = 0;
    size_t end = line.size();
    //std::vector<std::vector<uint8_t>> res;
    std::vector<Data> res;
    std::vector<std::vector<uint8_t>> unhandled;

    while (start < end) {
        char tag = line[start]; // Get the tag
        start += 1; // Move past the tag itself

        if (TAG_LENGTH.find(tag) == TAG_LENGTH.end()) {
            std::cerr << "Unknown tag encountered!" << std::endl;
            return {}; // Return empty vector if tag is not found
        }

        int buffer_length = TAG_LENGTH[tag];

        // Get the corresponding format string for decoding
        std::string format_string = TAG_CONVERSION[tag];

        std::vector<uint8_t> buffer(line.begin() + start, line.begin() + start + buffer_length);

        // Decode based on the format string
        // For simplicity, let's assume that we have just one type per tag and we're reading them as integers or floats
        switch (tag) {
        case 'T':
            // Example: decoding 'T' as an integer (L)
            res.push_back(unpackDataT(buffer));
            //size_t idx = 0;
            //int decoded_value = decode_big_endian<int>(buffer, idx);
            //std::cout << "Decoded T: " << decoded_value << std::endl;
            break;
        case 'O':
            res.push_back(unpackDataO(buffer));
            break;
        case 'L':
            res.push_back(unpackDataL(buffer));
            break;
        case 'K':
            res.push_back(unpackDataK(buffer));
            break;
        case 'E':
            res.push_back(unpackDataE(buffer));
            break;
        case 'C':
            res.push_back(unpackDataC(buffer));
            break;
        case 'D':
            res.push_back(unpackDataD(buffer));
            break;
        default:
            unhandled.push_back(buffer);
            break;
        }
        // Add more tag-decoding logic based on `TAG_CONVERSION`

        // Move start index to the next tag
        start += buffer_length;
    }

    return res;
}

int main() {
    // Example payload (in bytes)
    std::vector<uint8_t> line = { 0x4f, 0x00, 0x00, 0xba, 0xd7, 0x0b, 0x20, 0x20, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x19, 0x5f, 0x40}; // Example data
    std::vector<Data> result = jpExchangeDecoder(line);

    // Output the result (for debugging)
    //for (const auto& res : result) {
    //    for (uint8_t byte : res) {
    //        std::cout << std::hex << static_cast<int>(byte) << " ";
    //    }
    //    std::cout << std::endl;
    //}

    //process_pcap();

    return 0;
}