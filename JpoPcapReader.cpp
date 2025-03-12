#include <iostream>
#include "flag_structures.h"
#include <pcap.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <WinSock2.h>

// Function prototype for jpExchangeDecoder
std::vector<Data> jpExchangeDecoder(const std::vector<uint8_t>& line, std::ofstream& out_file);
#define ETHERTYPE_IP 0x0800
struct ether_header { //14
    u_char  ether_dhost[6];   // Destination MAC address
    u_char  ether_shost[6];   // Source MAC address
    u_short ether_type;       // Protocol type (e.g., IPv4, ARP)
};

struct ip { //20
    u_char version;
    u_char diff_field;
    u_short length;
    u_short id;
    u_char flags[4];
    uint16_t checksum;
    uint32_t ip_src[4];
    uint32_t ip_dst[4];
};

struct udp { //8
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};
// 1444 = 1490 - 1444 = 46
//66
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
        struct ether_header* eth_hdr = (struct ether_header*)pkt_data;

        // Check for IPv4
        if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
            struct ip* ip_pkt = (ip*)(pkt_data + sizeof(struct ether_header));

            // Get the source and destination IP addresses
            //char src_ip[INET_ADDRSTRLEN];
            //char dst_ip[INET_ADDRSTRLEN];
            //inet_ntop(AF_INET, &ip_pkt->ip_src, src_ip, INET_ADDRSTRLEN);
            //inet_ntop(AF_INET, &ip_pkt->ip_dst, dst_ip, INET_ADDRSTRLEN);

            // Calculate the starting position of the payload (data after UDP header)
            struct udp* udp_header = (struct udp*)(pkt_data + sizeof(struct ether_header) + sizeof(struct ip));

            // Calculate the starting position of the payload (data after UDP header)

            // Extract payload data (equivalent to Ether[Raw].load[27:])
            std::vector<uint8_t> payload(pkt_data + 42 + 27, //sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udp),
                pkt_data + header.caplen);

            // Decode the payload using jpExchangeDecoder function
            std::vector<Data> temp = jpExchangeDecoder(payload, out);
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
std::vector<Data> jpExchangeDecoder(const std::vector<uint8_t>& line, std::ofstream& out) {
    size_t start = 0;
    // the last 4 bytes are not part of the payload
    size_t end = line.size() - 4;
    //std::vector<std::vector<uint8_t>> res;
    std::vector<Data> res;
    std::vector<std::vector<uint8_t>> unhandled;

    while (start < end) {
        char tag = line[start]; // Get the tag
        start += 1; // Move past the tag itself

        if (TAG_LENGTH.find(tag) == TAG_LENGTH.end()) {
            continue;
        }

        int buffer_length = TAG_LENGTH[tag];

        // Get the corresponding format string for decoding
        std::string format_string = TAG_CONVERSION[tag];

        if (line.size() < buffer_length + start) {// something went wrong
            out << "UNHANDLED BUFFER" << '\n';
        };

        std::vector<uint8_t> buffer(line.begin() + start, line.begin() + start + buffer_length);

        // Decode based on the format string
        // For simplicity, let's assume that we have just one type per tag and we're reading them as integers or floats
        out << tag << ",";
        switch (tag) {
            case 'T':
                out << unpackDataT(buffer) << '\n';
                break;
            case 'O':
                out << unpackDataO(buffer) << '\n';
                break;
            case 'L':
                out << unpackDataL(buffer) << '\n';
                break;
            case 'K':
                out << unpackDataK(buffer) << '\n';
                break;
            case 'E':
                out << unpackDataE(buffer) << '\n';
                break;
            case 'C':
                out << unpackDataC(buffer) << '\n';
                break;
            case 'D':
                out << unpackDataD(buffer) << '\n';
                break;
            case 'A':
                out << unpackDataA(buffer) << '\n';
                break;
            case 'R':
                out << unpackDataR(buffer) << '\n';
                break;
                /*
            case 'B': // checks for BP -- this might not be correct
                if (line[start + 1] == 'P') {
                    out << unpackDataBP(buffer) << '\n';
                }
                else {
                    out << "UNHANDLED TAG " + tag << '\n';
                }
                break;
            case 'I': // checks for II -- this might not be correct
                if (line[start + 1] == 'I') {
                    out << unpackDataII(buffer) << '\n';
                }
                else {
                    out << "UNHANDLED TAG " + tag << '\n';
                }
                break;
            case 'M': // checks for MG -- this might not be correct
                if (line[start + 1] == 'G') {
                    out << unpackDataMG(buffer) << '\n';
                }
                else {
                    out << "UNHANDLED TAG " + tag << '\n';
                }
                break;
                */
            default:
                out << "UNHANDLED TAG " + tag << '\n';
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

    auto out_file = "C:\\Users\\raymo\\Documents\\test.txt";
    auto in_file = "C:\\Users\\raymo\\OneDrive\\Desktop\\20250205_2_057.pcap\\20250205_2_057.pcap";

    // Open the output file
    //std::ofstream out(out_file);

    //if (!out.is_open()) {
    //    std::cerr << "Error opening output file!" << std::endl;
    //    return 0;
    //}

    //std::vector<Data> result = jpExchangeDecoder(line, out);

    // Output the result (for debugging)
    //for (const auto& res : result) {
    //    for (uint8_t byte : res) {
    //        std::cout << std::hex << static_cast<int>(byte) << " ";
    //    }
    //    std::cout << std::endl;
    //}

    process_pcap(in_file, out_file);
    //out.close();

    return 0;
}