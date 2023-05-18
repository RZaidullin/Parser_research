#include <stdio.h>
#include <ctime>
#include <stdint.h>
#include <string.h>
#include <iostream>
#include <algorithm>
#include "packet.cpp"

using std::max;

int conv_times[10];
int simple_times[10];
int module_times[10];

double conv_single[10];
double simple_single[10];
double module_single[10];

int vect_cnt = 0;

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
        // ic[x+1].counter = 0;
        memcpy(res->mac_src, ic[x].packet, 6);
        ic[x+1].counter += 6;
        memcpy(res->mac_src, ic[x].packet + ic[x+1].counter, 6);
        ic[x+1].counter += 6;
        res->ethtype = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        // printf("ethtype is %x \n", res->ethtype);
        ic[x+1].counter += 2;
        // this -> ic[x+1].packet = ic[x].packet;
    }

    void vlan_parse (int x, struct vlan_header * res) {
        // ic[x+1].first_vlan_header.tpid = 0x8100;
        // ic[x+1].counter = ic[x].counter;
        res->vlan_tag = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;
        res->tpid = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;
        // printf("\n  tpid is %x \n", res->tpid);
    }

    void mpls_parse (int x, struct mpls_header * res) {
        // ic[x+1].counter = ic[x].counter;
        memcpy(res->mpls_tag_tc_s, ic[x].packet + ic[x+1].counter, 3);
        ic[x+1].counter += 3;
        res->mpls_ttl = ic[x].packet[ic[x+1].counter];
        ic[x+1].counter++;
    }

    void ip4_parse (int x, struct ipv4_header * res) {
        // ic[x+1].counter = ic[x].counter;
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

    void ip6_parse (int x, struct ipv6_header * res){
        // ic[x+1].counter = ic[x].counter;
        memcpy(res->version_tc_fl, ic[x].packet + ic[x+1].counter, 4);
        ic[x+1].counter += 4;
        res->payload_length = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;
        res->next_header = ic[x].packet[ic[x+1].counter];
        ic[x+1].counter++;
        res->hop_limit = ic[x].packet[ic[x+1].counter];
        ic[x+1].counter++;

        memcpy(res->ip_src, ic[x].packet + ic[x+1].counter, 4);
        ic[x+1].counter += 4;

        memcpy(res->ip_dst, ic[x].packet + ic[x+1].counter, 4);
        ic[x+1].counter += 4;
    }

    void tcp_parse (int x, struct tcp_header * res) {
        // ic[x+1].counter = ic[x].counter;
        res->src_port = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;
        res->dst_port = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;

        memcpy(res->sequence_number, ic[x].packet + ic[x+1].counter, 4);
        ic[x+1].counter += 4;

        memcpy(res->ack_number, ic[x].packet + ic[x+1].counter, 4);
        ic[x+1].counter += 4;

        res->data_offset_reserved = ic[x].packet[ic[x+1].counter];
        ic[x+1].counter++;
        res->flags = ic[x].packet[ic[x+1].counter];
        ic[x+1].counter++;
        res->window_size = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;
        res->checksum = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;
        res->urg_pointer = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;
    }

    void udp_parse (int x, struct udp_header * res) {
        // ic[x+1].counter = ic[x].counter;
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

    void icmp_parse (int x, struct icmp_header * res) {
        // ic[x+1].counter = ic[x].counter;
        res->type = ic[x].packet[ic[x+1].counter];
        ic[x+1].counter++;
        res->code = ic[x].packet[ic[x+1].counter];
        ic[x+1].counter++;
        res->checksum = ((uint16_t)ic[x].packet[ic[x+1].counter] << 8) | ic[x].packet[ic[x+1].counter + 1];
        ic[x+1].counter += 2;
        memcpy(res->rest, ic[x].packet + ic[x+1].counter, 4);
        ic[x+1].counter += 4;
    }
};

// void main_loop_parse(){

// }

void count_time (long int x, struct packet_ctx tmp1) {
    Parser parser(4);

    parser.ic[0] = tmp1;

    // int x = 40000;

    int s1[x], s2[x+1], s3[x+2], s4[x+3], s5[x+4];
    int s6[x+5], s7[x+6], s8[x+7], s9[x+8], s10[x+9];
    int conv_length = 10;

    s2[0] = 0;
    s3[0] = 0;
    s3[1] = 0;
    s4[0] = 0;
    s4[1] = 0;
    s4[2] = 0;
    s5[0] = 0;
    s5[1] = 0;
    s5[2] = 0;
    s5[3] = 0;
    for (int i = 0; i < 5; i++) { s6[i] = 0; }
    for (int i = 0; i < 6; i++) { s7[i] = 0; }
    for (int i = 0; i < 7; i++) { s8[i] = 0; }
    for (int i = 0; i < 8; i++) { s9[i] = 0; }
    for (int i = 0; i < 9; i++) { s10[i] = 0; }


    unsigned int t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0, t8 = 0, t9 = 0, t10 = 0;
    unsigned int simple_time = 0, conv_time = 0, tmp = 0;
    unsigned int end_time, start_time =  clock();
    uint16_t eth1;
    uint8_t next;

    for (int j = 0; j < x; ++j) {
        
        parser.ic[1].counter = 0;
        end_time = clock();
        parser.ethernet_parse(0, & parser.ic[1].mac_header);
        tmp = clock() - end_time;
        s1[j] = tmp > 0 ? tmp : 1;

        eth1 = parser.ic[1].mac_header.ethtype;
        // std::cout << "\n"<< 0x800 << "  d after ether parse  " << eth1 << std::endl;
        // printf("eth1 is %x \n", eth1);

        s2[j+1] = 0;
        s3[j+2] = 0;
        s4[j+3] = 0;
        s5[j+4] = 0;
        s6[j+5] = 0;
        s7[j+6] = 0;
        s8[j+7] = 0;

        if (eth1 == 0x8100) {
            end_time = clock();
            parser.vlan_parse(0, & parser.ic[1].first_vlan_header);
            tmp = clock() - end_time;
            s2[j+1] = tmp > 0 ? tmp : 1;
            eth1 = parser.ic[1].first_vlan_header.tpid;
            // std::cout << 0x800 << "  d  " << eth1 << std::endl;
            // printf("eth1 is %x \n", eth1);
            if (eth1 == 0x8100) {
                end_time = clock();
                parser.vlan_parse(0, & parser.ic[1].second_vlan_header);
                tmp = clock() - end_time;
                s3[j+2] = tmp > 0 ? tmp : 1;
                eth1 = parser.ic[1].second_vlan_header.tpid;
                // std::cout << 0x800 << "  d  " << eth1 << std::endl;
                // printf("eth1 is %x \n", eth1);
            }
        }

        if (eth1 == 0x8848) {
            end_time = clock();
            parser.mpls_parse(0, & parser.ic[1].first_mpls_header);
            tmp = clock() - end_time;
            s4[j+3] = tmp > 0 ? tmp : 1;
            // eth1 = parser.ic[1].first_vlan_header.tpid;
            next = parser.ic[1].first_mpls_header.mpls_tag_tc_s[2] & 1;
            // std::cout << 0x800 << "  d  " << eth1 << std::endl;
            // printf("eth1 is %x \n", next);
            if (next == 0x00) {
                end_time = clock();
                parser.mpls_parse(0, & parser.ic[1].second_mpls_header);
                tmp = clock() - end_time;
                s5[j+4] = tmp > 0 ? tmp : 1;
                next = parser.ic[1].second_mpls_header.mpls_tag_tc_s[2] & 1;
                if (next == 0x00) {
                    end_time = clock();
                    parser.mpls_parse(0, & parser.ic[1].third_mpls_header);
                    tmp = clock() - end_time;
                    s6[j+5] = tmp > 0 ? tmp : 1;
                    next = parser.ic[1].third_mpls_header.mpls_tag_tc_s[2] & 1;
                    if (next == 0x00) {
                        end_time = clock();
                        parser.mpls_parse(0, & parser.ic[1].fourth_mpls_header);
                        tmp = clock() - end_time;
                        s7[j+6] = tmp > 0 ? tmp : 1;
                        next = parser.ic[1].fourth_mpls_header.mpls_tag_tc_s[2] & 1;
                        if (next == 0x00) {
                            end_time = clock();
                            parser.mpls_parse(0, & parser.ic[1].fifth_mpls_header);
                            tmp = clock() - end_time;
                            s8[j+7] = tmp > 0 ? tmp : 1;
                            // next = parser.ic[1].fifth_mpls_header.mpls_tag_tc_s[2] & 1;
                        }
                    }
                }
            }
        }

        next = parser.ic[0].packet[parser.ic[1].counter] >> 4;

        // std::cout << 0x800 << "  d before ip  " << eth1 << std::endl;

        if (eth1 == 0x0800 || next == 0x04) {
            end_time = clock();
            parser.ip4_parse(0, & parser.ic[1].ipv4_header);
            tmp = clock() - end_time;
            s9[j+8] = tmp > 0 ? tmp : 1;
            next = parser.ic[1].ipv4_header.protocol;
        }
        else if (eth1 == 0x86DD || next == 0x06) {
            end_time = clock();
            parser.ip6_parse(0, & parser.ic[1].ipv6_header);
            tmp = clock() - end_time;
            s9[j+8] = tmp > 0 ? tmp : 1;
            next = parser.ic[1].ipv6_header.next_header;
        }

        if (next == 0x01) {
            end_time = clock();
            parser.icmp_parse(0, & parser.ic[1].icmp_header);
            tmp = clock() - end_time;
            s10[j+9] = tmp > 0 ? tmp : 1;
        }
        else if (next == 0x06) {
            end_time = clock();
            parser.tcp_parse(0, & parser.ic[1].tcp_header);
            tmp = clock() - end_time;
            s10[j+9] = tmp > 0 ? tmp : 1;
        }
        else if (next == 0x11) {
            end_time = clock();
            parser.udp_parse(0, & parser.ic[1].udp_header);
            tmp = clock() - end_time;
            s10[j+9] = tmp > 0 ? tmp : 1;
        }

    }

    for (int i = 0; i < x; ++i){
        simple_time = simple_time + s1[i] + s2[i+1] + s3[i+2] + s4[i+3] + s5[i+4] + s6[i+5] + s7[i+6] + s8[i+7] + s9[i+8] + s10[i+9];
        t1 += s1[i];
        t2 += s2[i];
        t3 += s3[i];
        t4 += s4[i];
        t5 += s5[i];
        t6 += s6[i];
        t7 += s7[i];
        t8 += s8[i];
        t9 += s9[i];
        t10 += s10[i];
        if (s1[i] >= s2[i] && s1[i] >= s3[i] && s1[i] >= s4[i] && s1[i] >= s5[i] && s1[i] >= s6[i] && s1[i] >= s7[i] && s1[i] >= s8[i] && s1[i] >= s9[i] && s1[i] >= s10[i]) {
            tmp = s1[i];
        }
        else if (s2[i] >= s3[i] && s2[i] >= s4[i] && s2[i] >= s5[i] && s2[i] >= s5[i] && s2[i] >= s6[i] && s2[i] >= s8[i] && s2[i] >= s9[i] && s2[i] >= s10[i]) {
            tmp = s2[i];
        }
        else if (s3[i] >= s4[i] && s3[i] >= s5[i] && s3[i] >= s6[i] && s3[i] >= s7[i] && s3[i] >= s8[i] && s3[i] >= s9[i] && s3[i] >= s10[i]) {
            tmp = s3[i];
        }
        else if (s4[i] >= s5[i] && s4[i] >= s6[i] && s4[i] >= s7[i] && s4[i] >= s8[i] && s4[i] >= s9[i] && s4[i] >= s10[i]) {
            tmp = s4[i];
        }
        else if (s5[i] >= s6[i] && s5[i] >= s7[i] && s5[i] >= s8[i] && s5[i] >= s9[i] && s5[i] >= s10[i]) {
            tmp = s5[i];
        }
        else if (s6[i] >= s7[i] && s6[i] >= s8[i] && s6[i] >= s9[i] && s6[i] >= s10[i]) {
            tmp = s6[i];
        }
        else if (s7[i] >= s8[i] && s7[i] >= s9[i] && s7[i] >= s10[i]){
            tmp = s7[i];
        }
        else if (s8[i] >= s9[i] && s8[i] >= s10[i]){
            tmp = s8[i];
        }
        else if (s9[i] >= s10[i]){
            tmp = s9[i];
        }
        else {
            tmp += s10[i];
        }
        conv_time += tmp;
    }
    
    // std::cout << "\n\nfirst " << t1 << " " << t1/double(x) << std::endl;
    // std::cout << "second " << t2 << " " << t2/double(x) << std::endl;
    // std::cout << "third " << t3 << " " << t3/double(x) << std::endl;
    // std::cout << "third " << t4 << " " << t4/double(x) << std::endl;
    // std::cout << "third " << t5 << " " << t5/double(x) << std::endl;
    // std::cout << "third " << t6 << " " << t6/double(x) << std::endl;
    // std::cout << "third " << t7 << " " << t7/double(x) << std::endl;
    // std::cout << "third " << t8 << " " << t8/double(x) << std::endl;
    // std::cout << "third " << t9 << " " << t9/double(x) << std::endl;
    // std::cout << "third " << t10 << " " << t10/double(x) << std::endl;
    // std::cout << "simple " << simple_time << std::endl;
    // std::cout << "module " << simple_time / 2 << std::endl;
    // std::cout << "conv " << conv_time << std::endl;

    // std::cout << "simple " << simple_time << std::endl;
    simple_times[vect_cnt] = simple_time;
    // std::cout << "module " << simple_time / 2 << std::endl;
    module_times[vect_cnt] = simple_time / 2;
    // std::cout << "conv " << conv_time << std::endl;
    conv_times[vect_cnt] = conv_time;

    // vect_cnt++;

    simple_single[vect_cnt] =  simple_time / double(x);
    module_single[vect_cnt] =  simple_time / double(x) / 2;
    conv_single[vect_cnt] =  10 * max(t10/double(x), max(t9/double(x), max(t8/double(x), max(t7/double(x), max(t6/double(x), max(t1/double(x), max(t2/double(x), max(t3/double(x), max(t4/double(x), t5/double(x))))))))));

    vect_cnt++;

    // int m1 = 0, m2 = 0, m3 = 0;

    // for (int i = 0; i < x; ++i) {
    //     // m1 = s1[i] > m1 ? s1[i] : m1;
    //     // m2 = s2[i+1] > m2 ? s2[i+1] : m2;
    //     // m3 = s3[i+2] > m3 ? s3[i+2] : m3;
    //     std::cout << s1[i] << " " << s2[i+1] << " " << s3[i+2] << " " << s4[i+3] << " " << s5[i+4] << " " << s6[i+5] << " " << s7[i+6] << " " << s8[i+7] << " " << s9[i+8] << " " << s10[i+9] << std::endl;
    // }

    // std::cout << "\nfirst " << m1 << std::endl;
    // std::cout << "second " << m2 << std::endl;
    // std::cout << "third " << m3 << std::endl;

    // end_time = clock();

    // unsigned int search_time = end_time - start_time;

    // std::cout << "runtime = " << search_time << std::endl;
    // std::cout << "runtime = " << search_time / 1000.0 << std::endl;

    // std::cout << t1 << " " << t2 << " " << t3 << std::endl;
} 

int main() {
    int size = 4;
    struct packet_ctx tmp1;
    // struct mac_header mac;
    // struct ipv4_header ip;
    // struct udp_header udp;
    // tmp1.packet = service_frame1;
    tmp1.packet = test_frame1;
    // tmp1.packet = test_frame;
    long int x = 50000;

    tmp1.packet = test_frame;
    count_time(x, tmp1);
    
    // tmp1.packet = service_frame1;
    // count_time(x, tmp1);
    tmp1.packet = service_frame2;
    count_time(x, tmp1);
    tmp1.packet = service_frame3;
    count_time(x, tmp1);
    tmp1.packet = service_frame4;
    count_time(x, tmp1);
    tmp1.packet = service_frame5;
    count_time(x, tmp1);
    tmp1.packet = service_frame6;
    count_time(x, tmp1);

    tmp1.packet = test_frame5;
    count_time(x, tmp1);
    tmp1.packet = test_frame1;
    count_time(x, tmp1);

    std::cout << " Simple times: " << std::endl;
    for (int i = 0; i < 8; ++i) {
        std::cout << simple_times[i] << ", ";
    }
    std::cout << "\n Module times: " << std::endl;
    for (int i = 0; i < 8; ++i) {
        std::cout << module_times[i] << ", ";
    }
    std::cout << "\n Conv times: " << std::endl;
    for (int i = 0; i < 8; ++i) {
        std::cout << conv_times[i] << ", ";
    }

    std::cout << "\n Simple single: " << std::endl;
    for (int i = 0; i < 8; ++i) {
        std::cout << simple_single[i] << ", ";
    }
    std::cout << "\n Module single: " << std::endl;
    for (int i = 0; i < 8; ++i) {
        std::cout << module_single[i] << ", ";
    }
    std::cout << "\n Conv single: " << std::endl;
    for (int i = 0; i < 8; ++i) {
        std::cout << conv_single[i] << ", ";
    }

    return 0;
}
