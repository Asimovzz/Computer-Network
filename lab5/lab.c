#include "common.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>
#include <fcntl.h>

#define LOG



static ccb_table_t conn_table = {0};

int init_connection(const char* local_ip, uint16_t local_port,
                   const char* remote_ip, uint16_t remote_port) {
    if (conn_table.count >= CCB_TABLE_SIZE) {
        return -1;
    }

    ccb_t* ccb = &conn_table.entries[conn_table.count];
    memset(ccb, 0, sizeof(ccb_t));

    // 设置连接信息
    strncpy(ccb->local_ip, local_ip, sizeof(ccb->local_ip)-1);
    ccb->local_ip[sizeof(ccb->local_ip)-1] = '\0';
    ccb->local_port = local_port;
    strncpy(ccb->remote_ip, remote_ip, sizeof(ccb->remote_ip)-1);
    ccb->remote_ip[sizeof(ccb->remote_ip)-1] = '\0';
    ccb->remote_port = remote_port;

    // 初始化窗口参数
    ccb->window_base = 0;
    ccb->window_size = 1;
    ccb->rtt_estimated = 0.2; // 200ms
    ccb->rtt_variation = 0;
    ccb->recv_progress = 0;
    memset(&ccb->recv_complete_time, 0, sizeof(struct timeval));


    /***********************
     * start of your code
     **********************/

    // 创建UDP socket
    ccb->udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ccb->udp_sock < 0) {
        return -1;
    }

    // 绑定本地地址
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = inet_addr(local_ip);
    local_addr.sin_port = htons(local_port);
    if (bind(ccb->udp_sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        return -1;
    }

    // 设置远端地址
    memset(&ccb->remote_addr, 0, sizeof(ccb->remote_addr));
    ccb->remote_addr.sin_family = AF_INET;
    ccb->remote_addr.sin_addr.s_addr = inet_addr(remote_ip);
    ccb->remote_addr.sin_port = htons(remote_port);

     /***********************
     * end of your code
     **********************/
    

    
    return conn_table.count++;
}

void close_connection(int conn_id) {
    if (conn_id < 0 || conn_id >= conn_table.count) {
        return;
    }

    ccb_t* ccb = &conn_table.entries[conn_id];
    if (ccb->udp_sock >= 0) {
        close(ccb->udp_sock);
    }
    memset(ccb, 0, sizeof(ccb_t));
}

// 更新RTT估计
static void update_rtt(ccb_t* ccb, double rtt_sample) {
    /***********************
     * start of your code
     **********************/

    // 本次RTT偏差
    double diff = rtt_sample - ccb->rtt_estimated;
    if (diff < 0) diff = -diff; 
    
    // 更新 RTTs 0.875 * RTTs + 0.125 * RTT_sample
    ccb->rtt_estimated = 0.875 * ccb->rtt_estimated + 0.125 * rtt_sample;
    
    // 更新 RTTv 0.75 * RTTv + 0.25 * RTTv_sample
    ccb->rtt_variation = 0.75 * ccb->rtt_variation + 0.25 * diff;

    /***********************
     * end of your code
     **********************/
}

// 拥塞控制
static void congestion_control(ccb_t* ccb, int is_timeout) {
    struct timeval now;
    gettimeofday(&now, NULL);
    
    /***********************
     * start of your code
     **********************/
    double timeout_interval = ccb->rtt_estimated + 4 * ccb->rtt_variation;

    if (is_timeout) {
        // 检查是否在保护期内
        double time_since_last = (now.tv_sec - ccb->last_congestion.tv_sec) + 
                                 (now.tv_usec - ccb->last_congestion.tv_usec) / 1000000.0;
        if (time_since_last > timeout_interval) {
            // 超时,窗口减半,不小于1
            ccb->window_size = ccb->window_size / 2.0;
            if (ccb->window_size < 1.0) {
                ccb->window_size = 1.0;
            }
            // 拥塞避免
            ccb->congestion_state = 1; 
            // 保护期开始
            ccb->last_congestion = now;
        }
    } else {
        // ACK处理
        if (ccb->congestion_state == 0) {
            // 慢启动,每个ACK窗口+1
            ccb->window_size += 1.0;
        } else {
            // 每个ACK窗口+1/window_size
            ccb->window_size += 1.0 / (int)(ccb->window_size);
        }
    }

    /***********************
     * end of your code
     **********************/

}

int m_send(int conn_id, const void* buf, size_t len) {
    if (conn_id < 0 || conn_id >= conn_table.count) {
        return -1;
    }

    ccb_t* ccb = &conn_table.entries[conn_id];
    
    // 检查缓冲区长度
    if (len > MTP_MAX_MSG_LEN) {
        fprintf(stderr, "Message too large\n");
        return -1;
    }

    // 初始化数组
    memset(ccb->timestamps, 0, sizeof(struct timeval) * MTP_MAX_SEGMENTS);
    memset(ccb->acks_received, 0, sizeof(uint8_t) * MTP_MAX_SEGMENTS);
    memset(ccb->retrans_records, 0, sizeof(uint32_t) * MTP_MAX_SEGMENTS);

    // 计算最大序列号
    uint32_t max_seq = (len + MTP_PAYLOAD_LEN - 1) / MTP_PAYLOAD_LEN;
    ccb->max_seq = max_seq;

    // 设置非阻塞模式
    int flags = fcntl(ccb->udp_sock, F_GETFL, 0);
    fcntl(ccb->udp_sock, F_SETFL, flags | O_NONBLOCK);


    // 发送循环
    while (1) {

        /***********************
         * start of your code
         **********************/
        // 处理接收分组
        mtp_header_t ack_hdr;
        struct sockaddr_in src_addr;
        socklen_t addr_len = sizeof(src_addr);
        
        while (recvfrom(ccb->udp_sock, &ack_hdr, sizeof(ack_hdr), 0, 
                        (struct sockaddr*)&src_addr, &addr_len) > 0) {
            uint32_t ack_seq = ack_hdr.seq_num;
            if (ack_seq < ccb->max_seq && !ccb->acks_received[ack_seq]) {
                ccb->acks_received[ack_seq] = 1; // 记录收到ACK
                
                // 仅对非重传分组更新RTT
                if (!ccb->retrans_records[ack_seq]) {
                    struct timeval now;
                    gettimeofday(&now, NULL);
                    double rtt_sample = (now.tv_sec - ccb->timestamps[ack_seq].tv_sec) + 
                                        (now.tv_usec - ccb->timestamps[ack_seq].tv_usec) / 1000000.0;
                    update_rtt(ccb, rtt_sample);
                }
                // 拥塞控制
                congestion_control(ccb, 0);
            }
        }

        // 滑动窗口
        while (ccb->window_base < ccb->max_seq && ccb->acks_received[ccb->window_base]) {
            ccb->window_base++;
        }

        // 发送分组
        struct timeval now;
        gettimeofday(&now, NULL);
        double timeout_val = ccb->rtt_estimated + 4 * ccb->rtt_variation;
        
        for (uint32_t i = ccb->window_base; i < ccb->max_seq && i < ccb->window_base + (int)ccb->window_size; i++) {
            // 已经收到ACK，跳过
            if (ccb->acks_received[i]) continue;

            double elapsed = (now.tv_sec - ccb->timestamps[i].tv_sec) + 
                             (now.tv_usec - ccb->timestamps[i].tv_usec) / 1000000.0;
            
            int is_first_send = (ccb->timestamps[i].tv_sec == 0);
            int is_timeout_pkt = (!is_first_send && elapsed > timeout_val);

            if (is_timeout_pkt) {
                // 超时处理
                congestion_control(ccb, 1);
                ccb->retrans_records[i] = 1; // 记录重传
            }

            if (is_first_send || is_timeout_pkt) {
                // 构造分组
                char packet[sizeof(mtp_header_t) + MTP_PAYLOAD_LEN];
                mtp_header_t* hdr = (mtp_header_t*)packet;
                hdr->seq_num = i;
                hdr->ack_flag = 0;
                
                size_t offset = i * MTP_PAYLOAD_LEN;
                size_t payload_len = (offset + MTP_PAYLOAD_LEN > len) ? (len - offset) : MTP_PAYLOAD_LEN;
                hdr->payload_len = payload_len;
                
                // 复制数据载荷
                memcpy(packet + sizeof(mtp_header_t), (char*)buf + offset, payload_len);
                
                // 发送数据
                sendto(ccb->udp_sock, packet, sizeof(mtp_header_t) + payload_len, 0, 
                       (struct sockaddr*)&ccb->remote_addr, sizeof(ccb->remote_addr));
                       
                // 记录发送时间
                gettimeofday(&ccb->timestamps[i], NULL);
            }
        }

        // 检查完成度
        if (ccb->window_base >= ccb->max_seq) {
            break;
        }
        
        /***********************
         * end of your code
         **********************/
    }

    return 0;
}

// 构造ACK分组
static void build_ack_packet(mtp_header_t* header, uint32_t seq_num) {
    header->seq_num = seq_num;
    header->ack_flag = 1;
    header->payload_len = 0;
}

int m_recv(int conn_id, void* buf, size_t len) {
    if (conn_id < 0 || conn_id >= conn_table.count) {
        return -1;
    }

    ccb_t* ccb = &conn_table.entries[conn_id];
    
    // 检查缓冲区长度
    if (len > MTP_MAX_MSG_LEN) {
        fprintf(stderr, "Buffer too small for message\n");
        return -1;
    }

    // 初始化数组
    memset(ccb->recv_records, 0, sizeof(uint8_t) * MTP_MAX_SEGMENTS);
    ccb->recv_progress = 0;
    memset(&ccb->recv_complete_time, 0, sizeof(struct timeval));

    /***********************
     * start of your code
     **********************/

    // 最大序列号
    uint32_t max_seq = (len + MTP_PAYLOAD_LEN - 1) / MTP_PAYLOAD_LEN;
    
    // 设置非阻塞模式
    int flags = fcntl(ccb->udp_sock, F_GETFL, 0);
    fcntl(ccb->udp_sock, F_SETFL, flags | O_NONBLOCK);
    
    /***********************
     * end of your code
     **********************/


    
    // 接收循环
    while (1) {
        /***********************
         * start of your code
         **********************/
        char packet[sizeof(mtp_header_t) + MTP_PAYLOAD_LEN];
        struct sockaddr_in src_addr;
        socklen_t addr_len = sizeof(src_addr);
        
        // 处理接收分组
        ssize_t recv_len = recvfrom(ccb->udp_sock, packet, sizeof(packet), 0, 
                                    (struct sockaddr*)&src_addr, &addr_len);
        
        if (recv_len > 0) {
            mtp_header_t* hdr = (mtp_header_t*)packet;
            uint32_t seq = hdr->seq_num;
            
            if (seq < max_seq) {
                // 新分组，写入接收缓冲区
                if (!ccb->recv_records[seq]) {
                    size_t offset = seq * MTP_PAYLOAD_LEN;
                    memcpy((char*)buf + offset, packet + sizeof(mtp_header_t), hdr->payload_len);
                    // 更新接收记录和进度
                    ccb->recv_records[seq] = 1;
                    ccb->recv_progress++;
                }
                
                // 发送ACK
                mtp_header_t ack_hdr;
                build_ack_packet(&ack_hdr, seq);
                sendto(ccb->udp_sock, &ack_hdr, sizeof(ack_hdr), 0, 
                       (struct sockaddr*)&src_addr, addr_len);
            }
        }

        // 完成度检查
        if (ccb->recv_progress >= max_seq) {
            struct timeval now;
            gettimeofday(&now, NULL);
            
            // 首次完成
            if (ccb->recv_complete_time.tv_sec == 0) {
                ccb->recv_complete_time = now;
            } else {
                // 是否超过0.5秒
                double elapsed = (now.tv_sec - ccb->recv_complete_time.tv_sec) + 
                                 (now.tv_usec - ccb->recv_complete_time.tv_usec) / 1000000.0;
                if (elapsed >= 0.5) {
                    break;
                }
            }
        }
        /***********************
         * end of your code
         **********************/
    }

    size_t received_len = ccb->recv_progress * MTP_PAYLOAD_LEN;
    if (ccb->recv_progress == max_seq) {
        received_len = received_len - (MTP_PAYLOAD_LEN - (received_len % MTP_PAYLOAD_LEN));
    }

    // 确保接收数据不超过缓冲区长度
    if (received_len > len) {
        return -1;
    }

    return received_len;
}