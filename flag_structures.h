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
    {'D', 10}, {'R', 1}, {'L', 2} , {'BP', 67}, {'MG', 15},{'II', 124}
};

std::unordered_map<char, std::string> TAG_CONVERSION = {
    {'T', "L"}, {'O', "LB2sBBq"}, {'L', "BB"}, {'K', "LcL2xL2xQLQQ"},
    {'A', "LLcL2xQBB"}, {'E', "LLcL2xL"}, {'C', "LLcL2xLQB"},
    {'D', "LLcB"}, {'R', "B"},{'BP', ""}, {'MG', ""}, {'II', ""}//, <<-- NOT HANDLED
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

template <typename T>
T uint8_from_binary(std::vector<uint8_t>& data, u_int idx) {
    auto var = (T)((unsigned char) data[idx] << 0);
    return var;
}

uint32_t uint32_from_binary(std::vector<uint8_t>& data, u_int idx) {
    //char str[4];
    //for (auto i : data) {
    //    sprintf_s(str, "%x", i);
    //    printf("The uint8_t as a hexadecimal string: %s\n", str);
    //}

    auto var = (unsigned long)data[idx] << 24 |
        (unsigned long)data[idx + 1] << 16 |
        (unsigned long)data[idx + 2] << 8 |
        (unsigned long)data[idx + 3] << 0;

    //std::cout << var << std::endl;

    return var;
}

uint64_t uint64_from_binary(std::vector<uint8_t>& data, u_int idx) {
    auto var = (unsigned long long)data[idx] << 56 |
        (unsigned long long)data[idx + 1] << 48 |
        (unsigned long long)data[idx + 2] << 40 |
        (unsigned long long)data[idx + 3] << 32 |
        (unsigned long long)data[idx + 4] << 24 |
        (unsigned long long)data[idx + 5] << 16 |
        (unsigned long long)data[idx + 6] << 8 |
        (unsigned long long)data[idx + 7] << 0;
    return var;
}

struct Data {};

struct DataT :Data {
    unsigned long time;
};

std::ostream& operator<<(std::ostream& os, const DataT& p) {
    os << p.time;
    return os;
}

DataT unpackDataT(std::vector<uint8_t>& data) {
    DataT payload;
    std::memcpy(&payload.time, &data[0], sizeof(payload.time));
    return payload;
};


struct DataO :Data {
    unsigned long time;
    int mkt_status;
    char status_flag1;
    char status_flag2;
    int short_selling_status;
    int px_method;
    unsigned long long px;
};

std::ostream& operator<<(std::ostream& os, const DataO& p) {
    os << p.time << "," << p.mkt_status << "," << p.status_flag1 << "," << p.status_flag2 << "," << p.short_selling_status << "," << p.px_method << "," << p.px;
    return os;
}

DataO unpackDataO(std::vector<uint8_t>& data) {
    DataO payload;
    /// memcpy was not consistent due to Big Endian Encoding ... also VS suck at seeing intermediate debugger views for this
    //std::memcpy(&payload.time, &data[0], sizeof(payload.time));
    payload.time = uint32_from_binary(data, 0);
    //std::memcpy(&payload.mkt_status, &data[4], sizeof(payload.mkt_status));
    payload.mkt_status = uint8_from_binary<int>(data, 4);
    //std::memcpy(&payload.status_flag1, &data[5], sizeof(payload.status_flag1));
    payload.status_flag1 = uint8_from_binary<char>(data, 5);
    //std::memcpy(&payload.status_flag2, &data[6], sizeof(payload.status_flag2));
    payload.status_flag2 = uint8_from_binary<char>(data, 5);
    //std::memcpy(&payload.short_selling_status, &data[7], sizeof(payload.short_selling_status));
    payload.short_selling_status = uint8_from_binary<int>(data, 7);
    //std::memcpy(&payload.px_method, &data[8], sizeof(payload.px_method));
    payload.px_method = uint8_from_binary<int>(data, 8);
    //std::memcpy(&payload.px, &data[9], sizeof(payload.px));
    payload.px = uint64_from_binary(data, 9);
    return payload;
};

struct DataL :Data {
    int test_mode_flag;
    int start_end_flag;
};


std::ostream& operator<<(std::ostream& os, const DataL& p) {
    os << p.test_mode_flag << "," << p.start_end_flag;
    return os;
}

DataL unpackDataL(std::vector<uint8_t>& data) {
    DataL payload;
    payload.test_mode_flag = uint8_from_binary<int>(data, 0);
    payload.start_end_flag = uint8_from_binary<int>(data, 1);
    //std::memcpy(&payload.test_mode_flag, &data[0], sizeof(payload.test_mode_flag));
    //std::memcpy(&payload.start_end_flag, &data[1], sizeof(payload.start_end_flag));
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

std::ostream& operator<<(std::ostream& os, const DataK& p) {
    os << p.time << "," << p.trigger_side << "," << p.total_volume << "," << p.total_invalidation_1 << "," << p.last_px << "," << p.match_id << "," << p.best_offer << "," << p.best_bid;
    return os;
}

DataK unpackDataK(std::vector<uint8_t>& data) {
    DataK payload;
    payload.time = uint32_from_binary(data, 0);
    //std::memcpy(&payload.time, &data[0], sizeof(payload.time));
    payload.trigger_side = uint8_from_binary<char>(data, 4);
    //std::memcpy(&payload.trigger_side, &data[4], sizeof(payload.trigger_side));
    payload.total_volume = uint32_from_binary(data, 5);
    //std::memcpy(&payload.total_volume, &data[5], sizeof(payload.total_volume));
    //std::memcpy(&payload.buffer, &data[9], sizeof(payload.buffer));
    //std::memcpy(&payload.buffer2, &data[10], sizeof(payload.buffer2));
    payload.total_invalidation_1 = uint32_from_binary(data, 11);
    //std::memcpy(&payload.total_invalidation_1, &data[11], sizeof(payload.total_invalidation_1));
    //std::memcpy(&payload.buffer3, &data[15], sizeof(payload.buffer3));
    //std::memcpy(&payload.buffer4, &data[16], sizeof(payload.buffer4)); 
    payload.last_px = uint64_from_binary(data, 17);
    //std::memcpy(&payload.last_px, &data[17], sizeof(payload.last_px));
    payload.match_id = uint32_from_binary(data, 25);
    //std::memcpy(&payload.match_id, &data[25], sizeof(payload.match_id));
    payload.best_offer = uint64_from_binary(data, 29);
    //std::memcpy(&payload.best_offer, &data[29], sizeof(payload.best_offer));
    payload.best_bid = uint64_from_binary(data, 37);
    //std::memcpy(&payload.best_bid, &data[37], sizeof(payload.best_bid));
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

std::ostream& operator<<(std::ostream& os, const DataA& p) {
    os << std::to_string(p.time) << "," << std::to_string(p.order_id)
        << "," << std::to_string(p.side) << "," << std::to_string(p.qty) 
        << "," << std::to_string(p.px) << "," << std::to_string(p.order_condition)
        << "," << std::to_string(p.mod_flag);
    return os;
}

DataA unpackDataA(std::vector<uint8_t>& data) {
    DataA payload;
    payload.time = uint32_from_binary(data, 0);
    //std::memcpy(&payload.time, &data[0], sizeof(payload.time));
    payload.order_id = uint32_from_binary(data, 4);
    //std::memcpy(&payload.order_id, &data[4], sizeof(payload.order_id));
    payload.time = uint8_from_binary<char>(data, 8);
    //std::memcpy(&payload.side, &data[8], sizeof(payload.side));
    payload.qty = uint32_from_binary(data, 9);
    //std::memcpy(&payload.qty, &data[9], sizeof(payload.qty));
    //std::memcpy(&payload.buffer, &data[13], sizeof(payload.buffer));
    //std::memcpy(&payload.buffer2, &data[14], sizeof(payload.buffer2));
    payload.qty = uint32_from_binary(data, 15);
    //std::memcpy(&payload.px, &data[15], sizeof(payload.px));
    payload.order_condition = uint8_from_binary<char>(data, 23);
    //std::memcpy(&payload.order_condition, &data[23], sizeof(payload.order_condition));
    payload.mod_flag = uint8_from_binary<char>(data, 24);
    //std::memcpy(&payload.mod_flag, &data[24], sizeof(payload.mod_flag));
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

std::ostream& operator<<(std::ostream& os, const DataE& p) {
    os << p.time << "," << p.order_id << "," << p.side << "," << p.volume << "," << p.match_id;
    return os;
}

DataE unpackDataE(std::vector<uint8_t>& data) {
    DataE payload;
    payload.time = uint32_from_binary(data, 0);
    //std::memcpy(&payload.time, &data[0], sizeof(payload.time));
    payload.order_id = uint32_from_binary(data, 4);
    //std::memcpy(&payload.order_id, &data[4], sizeof(payload.order_id));
    payload.side = uint8_from_binary<char>(data, 8);
    //std::memcpy(&payload.side, &data[8], sizeof(payload.side));
    payload.volume = uint32_from_binary(data, 9);
    //std::memcpy(&payload.volume, &data[9], sizeof(payload.volume));
    //std::memcpy(&payload.buffer, &data[13], sizeof(payload.buffer));
    //std::memcpy(&payload.buffer2, &data[14], sizeof(payload.buffer2));
    payload.match_id = uint32_from_binary(data, 15);
    //std::memcpy(&payload.match_id, &data[15], sizeof(payload.match_id));
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

std::ostream& operator<<(std::ostream& os, const DataC& p) {
    os << p.time << "," << p.order_id << "," << p.volume << "," << p.match_id << "," << p.execution_px;
    return os;
}


DataC unpackDataC(std::vector<uint8_t>& data) {
    DataC payload;
    payload.time = uint32_from_binary(data, 0);
    //std::memcpy(&payload.time, &data[0], sizeof(payload.time));
    payload.order_id = uint32_from_binary(data, 4); 
    //std::memcpy(&payload.order_id, &data[4], sizeof(payload.order_id));
    payload.side = uint8_from_binary<char>(data, 8); 
    //std::memcpy(&payload.side, &data[8], sizeof(payload.side));
    payload.volume = uint32_from_binary(data, 9);
    //std::memcpy(&payload.volume, &data[9], sizeof(payload.volume));
    //std::memcpy(&payload.buffer, &data[13], sizeof(payload.buffer));
    //std::memcpy(&payload.buffer2, &data[14], sizeof(payload.buffer2));
    payload.match_id = uint32_from_binary(data, 15); 
    //std::memcpy(&payload.match_id, &data[15], sizeof(payload.match_id));
    payload.execution_px = uint64_from_binary(data, 19); 
    //std::memcpy(&payload.execution_px, &data[19], sizeof(payload.execution_px));
    payload.px_method = uint8_from_binary<char>(data, 27); 
    //std::memcpy(&payload.px_method, &data[27], sizeof(payload.px_method));
    return payload;
};

struct DataD :Data {
    unsigned long time;
    unsigned long order_id;
    char side;
    char mod_flag;
};

std::ostream& operator<<(std::ostream& os, const DataD& p) {
    os << p.time << "," << p.order_id << "," << p.side << "," << p.mod_flag;
    return os;
}

DataD unpackDataD(std::vector<uint8_t>& data) {
    DataD payload;
    payload.time = uint32_from_binary(data, 0);
    //std::memcpy(&payload.time, &data[0], sizeof(payload.time));
    payload.order_id = uint32_from_binary(data, 4);
    //std::memcpy(&payload.order_id, &data[4], sizeof(payload.order_id));
    payload.side = uint8_from_binary<char>(data, 8);
    //std::memcpy(&payload.side, &data[8], sizeof(payload.side));    
    payload.mod_flag = uint8_from_binary<char>(data, 9);
    //std::memcpy(&payload.mod_flag, &data[9], sizeof(payload.mod_flag));
    return payload;
};

struct DataR :Data {
    char start_end_flag;
};


std::ostream& operator<<(std::ostream& os, const DataR& p) {
    os << p.start_end_flag;
    return os;
}

DataR unpackDataR(std::vector<uint8_t>& data) {
    DataR payload;
    payload.start_end_flag = uint8_from_binary<char>(data, 0);
    //std::memcpy(&payload.start_end_flag, &data[0], sizeof(payload.start_end_flag));
    return payload;
};

struct Price {
    u_char unitFlag;
    u_char price[14]; // this is weird
    u_char sign;
};

std::ostream& operator<<(std::ostream& os, const Price& p) {
    os << p.unitFlag << "," << p.price << "," << p.sign ;
    return os;
}

struct DataBP :Data {
    byte buffer;
    byte buffer2;
    u_char businessDay[8];
    Price BasePrice;
    Price MaxPrice;
    Price MinPrice;
    u_char bpFlag;
    u_char tickSize[2];
    byte buffe3;
    byte buffer4[4];
};

DataBP unpackDataBP(std::vector<uint8_t>& data) {
    DataBP payload;
    return payload;
};

std::ostream& operator<<(std::ostream& os, const DataBP& p) {
    os << p.businessDay << "," << p.BasePrice 
        << "," << p.MaxPrice << "," << p.MinPrice 
        << "," << p.bpFlag << "," << p.tickSize;
    return os;
}

struct DataMG :Data {
    byte buffer;
    byte buffer2;
    u_char businessDay[8];
    u_char grpNo[3];
    byte buffer3;
};

DataMG unpackDataMG(std::vector<uint8_t>& data) {
    DataMG payload;
    return payload;
};

struct DataII :Data {
};

DataII unpackDataII(std::vector<uint8_t>& data) {
    DataII payload;
    return payload;
};