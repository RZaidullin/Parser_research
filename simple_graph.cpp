#include <stdio.h>
#include <ctime>
#include <stdint.h>
#include <string.h>
#include <iostream>
#include "packet.cpp"

class Parser {
    int size;
    std::vector<std::mutex> mutex_vector;

    // std::vector<uint8_t* > interconnect;

public:

    std::vector<packet_ctx> ic; // interconnector

    Parser (int x) {
        this->size = x;
        size_t count = x;

        std::vector<std::mutex> list(count);
        this->mutex_vector.swap(list);

        std::vector<packet_ctx> lst(count);
        this->ic.swap(lst);
    }

    void ethernet_parse (int x, struct mac_header * res) {
        ic[x+1].counter = 0;
        memcpy(res->mac_src, ic[x].packet, 6);
        ic[x+1].counter += 6;
        memcpy(res->mac_src, ic[x].packet + ic[x+1].counter, 6);
        ic[x+1].counter += 6;
        res->ethtype = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;
        // this -> ic[x+1].packet = ic[x].packet;
    }

    void vlan_parse (int x, struct vlan_header * res) {
        // ic[x+1].first_vlan_header.tpid = 0x8100;
        ic[x+1].counter = ic[x].counter;
        res->vlan_tag = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;
        res->tpid = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;
    }

    void mpls_parse (int x, struct mpls_header * res) {
        ic[x+1].counter = ic[x].counter;
        memcpy(res->mpls_tag_tc_s, ic[x].packet + ic[x+1].counter, 3);
        ic[x+1].counter += 3;
        res->mpls_ttl = ic[x].packet[ic[x+1].counter];
        ic[x+1].counter++;
    }

    void ip4_parse (int x, struct ipv4_header * res) {
        ic[x+1].counter = ic[x].counter;
        res->version_ihl = ic[x].packet[ic[x+1].counter];
        ic[x+1].counter++;
        res->dcsp_ecn = ic[x].packet[ic[x+1].counter];
        ic[x+1].counter++;
        res->length = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;
        res->identification = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;
        res->flags_offset = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;
        res->ip_ttl = ic[x].packet[ic[x+1].counter];
        ic[x+1].counter++;
        res->protocol = ic[x].packet[ic[x+1].counter];
        ic[x+1].counter++;
        res->crc = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;

        memcpy(res->ip_src, ic[x].packet + ic[x+1].counter, 4);
        ic[x+1].counter += 4;

        memcpy(res->ip_dst, ic[x].packet + ic[x+1].counter, 4);
        ic[x+1].counter += 4;
        // this -> ic[x+1].packet = ic[x].packet;
    }

    void tcp_parse (int x) {
        ic[x+1].counter = ic[x].counter;
    }

    void udp_parse (int x, struct udp_header * res) {
        ic[x+1].counter = ic[x].counter;
        res->src_port = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;
        res->dst_port = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;
        res->length = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;
        res->checksum = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;
        // this -> ic[x+1].packet = ic[x].packet;
    }
};

// void main_loop_parse(){

// }

int main() {
    int size = 4;
    struct packet_ctx tmp1;
    // struct mac_header mac;
    // struct ipv4_header ip;
    // struct udp_header udp;
    tmp1.packet = test_frame;
    Parser parser(4);

    parser.ic[0] = tmp1;

    int x = 100000;

    int s1[x], s2[x+1], s3[x+2];

    s2[0] = 0;
    s3[0] = 0;
    s3[1] = 0;

    unsigned int t1 = 0, t2 = 0, t3 = 0, simple_time = 0, conv_time = 0, tmp = 0;
    unsigned int end_time, start_time =  clock();

    for (int j = 0; j < x; ++j) {
        
        end_time = clock();
        parser.ethernet_parse(0, & parser.ic[1].mac_header);
        s1[j] = clock() - end_time;

        end_time = clock();
        parser.ip4_parse(0, & parser.ic[1].ipv4_header);
        s2[j+1] = clock() - end_time;

        end_time = clock();
        parser.udp_parse(0, & parser.ic[1].udp_header);
        s3[j+2] = clock() - end_time;
    }

    for (int i = 0; i < x; ++i){
        simple_time = simple_time + s1[i] + s2[i+1] + s3[i+2];
        t1 += s1[i];
        t2 += s2[i];
        t3 += s3[i];
        if (s1[i] >= s2[i] && s1[i] >= s3[i]) {
            tmp = s1[i];
        }
        else if (s2[i] >= s3[i]) {
            tmp = s2[i];
        }
        else {
            tmp = s3[i];
        }
        conv_time += tmp;
    }
    
    std::cout << "first " << t1 << " " << t1/double(x) << std::endl;
    std::cout << "second " << t2 << " " << t2/double(x) << std::endl;
    std::cout << "third " << t3 << " " << t3/double(x) << std::endl;
    std::cout << "simple " << simple_time << std::endl;
    std::cout << "module " << simple_time / 2 << std::endl;
    std::cout << "conv " << conv_time << std::endl;

    int m1 = 0, m2 = 0, m3 = 0;


    return 0;
}