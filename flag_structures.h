#pragma once
#include <unordered_map>
//#include <winsock2.h>  // For handling endian conversions (ntohl, htonl)
#include <vector>
#include <cstring>
#include <string>
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
//#include <netinet/in.h>
#pragma comment(lib, "ws2_32.lib")
//#include <netinet/ip.h>
//#include <netinet/ether.h>
//#include <arpa/inet.h>

std::unordered_map<char, int> TAG_LENGTH = {
    {'A', 25}, {'T', 4}, {'O', 17}, {'K', 45}, {'E', 19}, {'C', 28},
    {'D', 10}, {'R', 1}, {'L', 2}, {'|', 124}, {'B', 67}, {'M', 15}
};

std::unordered_map<char, std::string> TAG_CONVERSION = {
    {'T', "L"}, {'O', "LB2sBBq"}, {'L', "BB"}, {'K', "LcL2xL2xQLQQ"},
    {'A', "LLcL2xQBB"}, {'E', "LLcL2xL"}, {'C', "LLcL2xLQB"},
    {'D', "LLcB"}, {'R', "B"}, {'|', ""}, {'B', ""}, {'M', ""}
};

uint32_t to_big_endian32(uint32_t value) {
    return htonl(value);
}

uint16_t to_big_endian16(uint16_t value) {
    return htons(value);
}

uint64_t to_big_endian64(uint64_t value) {
    uint32_t high_part = htonl(value >> 32);
    uint32_t low_part = htonl(value & 0xFFFFFFFF);
    return ((uint64_t)low_part << 32) | high_part;
}

uint8_t uint8_from_binary(std::vector<uint8_t>& data, u_int idx) {
    return (unsigned char)data[idx] << 0;
}

uint32_t uint32_from_binary(std::vector<uint8_t>& data, u_int idx) {
    char str[4];
    for (auto i : data) {
        sprintf_s(str, "%x", i);
        printf("The uint8_t as a hexadecimal string: %s\n", str);
    }
    return (unsigned long)data[idx] << 24 |
        (unsigned long)data[idx + 1] << 16 |
        (unsigned long)data[idx + 2] << 8 |
        (unsigned long)data[idx + 3] << 0;
}

uint64_t uint64_from_binary(std::vector<uint8_t>& data, u_int idx) {
    for (auto i : data) {
        std::cout << i << std::endl;
    }
    return (unsigned long long)data[idx] << 56 |
        (unsigned long long)data[idx + 1] << 48 |
        (unsigned long long)data[idx + 2] << 40 |
        (unsigned long long)data[idx + 3] << 32 |
        (unsigned long long)data[idx + 4] << 24 |
        (unsigned long long)data[idx + 5] << 16 |
        (unsigned long long)data[idx + 6] << 8 |
        (unsigned long long)data[idx + 7] << 0;
}

struct Data {};

struct DataT :Data {
    unsigned long time;
};

DataT unpackDataT(std::vector<uint8_t>& data) {
    DataT payload;
    std::memcpy(&payload.time, &data[0], sizeof(payload.time));
    return payload;
};


struct DataO :Data {
    unsigned long time;
    unsigned char mkt_status;
    char status_flag1;
    char status_flag2;
    unsigned char short_selling_status;
    unsigned char px_method;
    unsigned long long px;
};

DataO unpackDataO(std::vector<uint8_t>& data) {
    DataO payload;
    std::memcpy(&payload.time, &data[0], sizeof(payload.time));
    payload.time = uint32_from_binary(data, 0);
    std::memcpy(&payload.mkt_status, &data[4], sizeof(payload.mkt_status));
    payload.mkt_status = uint8_from_binary(data, 4);
    std::memcpy(&payload.status_flag1, &data[5], sizeof(payload.status_flag1));
    std::memcpy(&payload.status_flag2, &data[6], sizeof(payload.status_flag2));
    std::memcpy(&payload.short_selling_status, &data[7], sizeof(payload.short_selling_status));
    std::memcpy(&payload.px_method, &data[8], sizeof(payload.px_method));
    std::memcpy(&payload.px, &data[9], sizeof(payload.px));
    payload.px = to_big_endian64(payload.px);
    return payload;
};

struct DataL :Data {
    unsigned char test_mode_flag;
    unsigned char start_end_flag;
};

DataL unpackDataL(std::vector<uint8_t>& data) {
    DataL payload;
    std::memcpy(&payload.test_mode_flag, &data[0], sizeof(payload.test_mode_flag));
    std::memcpy(&payload.start_end_flag, &data[1], sizeof(payload.start_end_flag));
    return payload;
};


struct DataK :Data {
    unsigned long time;
    char trigger_side;
    unsigned long total_volume;
    byte buffer;
    byte buffer2;
    unsigned long total_invalidation_1;
    byte buffer3;
    byte buffer4;
    unsigned long long last_px;
    unsigned long match_id;
    unsigned long long best_offer;
    unsigned long long best_bid;
};

DataK unpackDataK(std::vector<uint8_t>& data) {
    DataK payload;
    std::memcpy(&payload.time, &data[0], sizeof(payload.time));
    std::memcpy(&payload.trigger_side, &data[4], sizeof(payload.trigger_side));
    std::memcpy(&payload.total_volume, &data[5], sizeof(payload.total_volume));
    std::memcpy(&payload.buffer, &data[9], sizeof(payload.buffer));
    std::memcpy(&payload.buffer2, &data[10], sizeof(payload.buffer2));
    std::memcpy(&payload.total_invalidation_1, &data[11], sizeof(payload.total_invalidation_1));
    std::memcpy(&payload.buffer3, &data[15], sizeof(payload.buffer3));
    std::memcpy(&payload.buffer4, &data[16], sizeof(payload.buffer4)); 
    std::memcpy(&payload.last_px, &data[17], sizeof(payload.last_px));
    std::memcpy(&payload.match_id, &data[25], sizeof(payload.match_id));
    std::memcpy(&payload.best_offer, &data[29], sizeof(payload.best_offer));
    std::memcpy(&payload.best_bid, &data[37], sizeof(payload.best_bid));
    return payload;
};

struct DataA :Data {
    unsigned long time;
    unsigned long order_id;
    char side;
    unsigned long qty;
    byte buffer;
    byte buffer2;
    unsigned long long px;
    char order_condition;
    char mod_flag;
};

DataA unpackDataA(std::vector<uint8_t>& data) {
    DataA payload;
    std::memcpy(&payload.time, &data[0], sizeof(payload.time));
    std::memcpy(&payload.order_id, &data[4], sizeof(payload.order_id));
    std::memcpy(&payload.side, &data[8], sizeof(payload.side));
    std::memcpy(&payload.qty, &data[9], sizeof(payload.qty));
    std::memcpy(&payload.buffer, &data[13], sizeof(payload.buffer));
    std::memcpy(&payload.buffer2, &data[14], sizeof(payload.buffer2));
    std::memcpy(&payload.px, &data[15], sizeof(payload.px));
    std::memcpy(&payload.order_condition, &data[23], sizeof(payload.order_condition));
    std::memcpy(&payload.mod_flag, &data[24], sizeof(payload.mod_flag));
    return payload;
};

struct DataE :Data {
    unsigned long time;
    unsigned long order_id;
    char side;
    unsigned long volume;
    byte buffer;
    byte buffer2;
    unsigned long match_id;
};

DataE unpackDataE(std::vector<uint8_t>& data) {
    DataE payload;
    std::memcpy(&payload.time, &data[0], sizeof(payload.time));
    std::memcpy(&payload.order_id, &data[4], sizeof(payload.order_id));
    std::memcpy(&payload.side, &data[8], sizeof(payload.side));
    std::memcpy(&payload.volume, &data[9], sizeof(payload.volume));
    std::memcpy(&payload.buffer, &data[13], sizeof(payload.buffer));
    std::memcpy(&payload.buffer2, &data[14], sizeof(payload.buffer2));
    std::memcpy(&payload.match_id, &data[15], sizeof(payload.match_id));
    return payload;
};

struct DataC :Data {
    unsigned long time;
    unsigned long order_id;
    char side;
    unsigned long volume;
    byte buffer;
    byte buffer2;
    unsigned long match_id;
    unsigned long long execution_px;
    char px_method;
};


DataC unpackDataC(std::vector<uint8_t>& data) {
    DataC payload;
    std::memcpy(&payload.time, &data[0], sizeof(payload.time));
    std::memcpy(&payload.order_id, &data[4], sizeof(payload.order_id));
    std::memcpy(&payload.side, &data[8], sizeof(payload.side));
    std::memcpy(&payload.volume, &data[9], sizeof(payload.volume));
    std::memcpy(&payload.buffer, &data[13], sizeof(payload.buffer));
    std::memcpy(&payload.buffer2, &data[14], sizeof(payload.buffer2));
    std::memcpy(&payload.match_id, &data[15], sizeof(payload.match_id));
    std::memcpy(&payload.execution_px, &data[19], sizeof(payload.execution_px));
    std::memcpy(&payload.px_method, &data[27], sizeof(payload.px_method));
    return payload;
};

struct DataD :Data {
    unsigned long time;
    unsigned long order_id;
    char side;
    char mod_flag;
};

DataD unpackDataD(std::vector<uint8_t>& data) {
    DataD payload;
    std::memcpy(&payload.time, &data[0], sizeof(payload.time));
    std::memcpy(&payload.order_id, &data[4], sizeof(payload.order_id));
    std::memcpy(&payload.side, &data[8], sizeof(payload.side));    
    std::memcpy(&payload.mod_flag, &data[9], sizeof(payload.mod_flag));
    return payload;
};

struct DataR :Data {
    char start_end_flag;
};

DataR unpackDataR(std::vector<uint8_t>& data) {
    DataR payload;
    std::memcpy(&payload.start_end_flag, &data[0], sizeof(payload.start_end_flag));
    return payload;
};