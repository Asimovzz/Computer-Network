#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

/*======================================================================
 *  实验六：在网计算  —— 学生模板
 *
 *  本文件实现 libpcap 收发、MTP 可靠传输、环形集合通信、路由转发与
 *  AllReduce 在网聚合逻辑。
 *
 *    辅助/IO（已给）：
 *      now_us()                                  取当前时间(微秒)
 *      build_frame(...)                          组装一帧 MTP 报文
 *      conn_send(cn, seq, ack_flag, op, buf, n)  在某连接上发一个分组
 *      conn_pop(cn, &msg)                        从某连接接收缓冲区取一个分组(非阻塞)
 *      router_forward(frame, len, dst_ip)        路由器按目的 IP 转发一帧
 *      dev_pop(&pk)                              路由器从共享缓冲区取一帧(非阻塞)
 *      broadcast_slot(seq)                       路由器把某聚合完成的 slot 广播给所有连接
 *
 *====================================================================*/

/*======================================================================
 *  通用工具（已给）
 *====================================================================*/

uint64_t now_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

/* 标准 Internet 校验和（16 位反码求和） */
static uint16_t ip_checksum(const void *data, int len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;
    int i;
    for (i = 0; i + 1 < len; i += 2)
        sum += (uint16_t)((p[i] << 8) | p[i + 1]);
    if (len & 1)
        sum += (uint16_t)(p[len - 1] << 8);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum & 0xffff);
}

/* 组装一帧 MTP 报文到 buf，返回总长度。已给。 */
static int build_frame(uint8_t *buf,
                       uint32_t src_ip, uint32_t dst_ip,
                       uint16_t conn_id, uint32_t seq,
                       uint8_t ack_flag, uint8_t op,
                       const void *payload, uint16_t plen) {
    eth_header_t *eth = (eth_header_t *)buf;
    memset(eth->dst_mac, 0xff, 6);
    memset(eth->src_mac, 0x00, 6);
    eth->ether_type = htons(ETH_TYPE_IP);

    ip_header_t *ip = (ip_header_t *)(buf + sizeof(eth_header_t));
    ip->version_ihl = 0x45;
    ip->tos = 0;
    ip->total_len = htons(sizeof(ip_header_t) + sizeof(mtp_header_t) + plen);
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IP_PROTO_MTP;
    ip->checksum = 0;
    ip->src_ip = src_ip;
    ip->dst_ip = dst_ip;
    ip->checksum = htons(ip_checksum(ip, sizeof(ip_header_t)));

    mtp_header_t *mtp = (mtp_header_t *)(buf + sizeof(eth_header_t) + sizeof(ip_header_t));
    mtp->conn_id = htons(conn_id);
    mtp->seq_num = htonl(seq);
    mtp->ack_flag = ack_flag;
    mtp->op = op;

    if (plen > 0 && payload)
        memcpy(buf + HDR_LEN, payload, plen);

    return (int)(HDR_LEN + plen);
}

/*======================================================================
 *  主机端
 *====================================================================*/

static config_entry_t g_cfg[MAX_GROUP_SIZE];
static int            g_n = 0;
static int            g_rank = -1;
static uint32_t       g_my_ip = 0;

static pcap_t        *g_host_handle = NULL;
static pthread_mutex_t g_tx_lock = PTHREAD_MUTEX_INITIALIZER;

static conn_t         g_conns[MAX_CONNS];
static int            g_conn_count = 0;

/* 经 pcap 发送一帧（多线程发送加锁）。已给。 */
static void host_inject(uint8_t *frame, int len) {
    pthread_mutex_lock(&g_tx_lock);
    pcap_inject(g_host_handle, frame, len);
    pthread_mutex_unlock(&g_tx_lock);
}

/* 在某条连接上发送一个 MTP 分组。已给。 */
static void conn_send(conn_t *cn, uint32_t seq, uint8_t ack_flag, uint8_t op,
                      const void *payload, uint16_t plen) {
    uint8_t frame[HDR_LEN + PAYLOAD_LEN];
    int len = build_frame(frame, cn->local_ip, cn->remote_ip,
                          cn->conn_id, seq, ack_flag, op, payload, plen);
    host_inject(frame, len);
}

/* 后台接收线程：抓本机网卡进入的帧，按 conn_id 分发到对应连接的接收缓冲区。已给。 */
static void *host_rx_thread(void *arg) {
    (void)arg;
    struct pcap_pkthdr *hdr;
    const u_char *pkt;
    int rc;

    while ((rc = pcap_next_ex(g_host_handle, &hdr, &pkt)) >= 0) {
        if (rc == 0) continue;
        if (hdr->caplen < HDR_LEN) continue;

        const eth_header_t *eth = (const eth_header_t *)pkt;
        if (ntohs(eth->ether_type) != ETH_TYPE_IP) continue;

        const ip_header_t *ip = (const ip_header_t *)(pkt + sizeof(eth_header_t));
        if (ip->protocol != IP_PROTO_MTP) continue;
        if (ip->src_ip == g_my_ip) continue;

        int ip_ihl = (ip->version_ihl & 0x0f) * 4;
        const mtp_header_t *mtp =
            (const mtp_header_t *)(pkt + sizeof(eth_header_t) + ip_ihl);
        int plen = ntohs(ip->total_len) - ip_ihl - (int)sizeof(mtp_header_t);
        if (plen < 0) plen = 0;
        if (plen > PAYLOAD_LEN) plen = PAYLOAD_LEN;

        uint16_t conn_id = ntohs(mtp->conn_id);
        conn_t *cn = NULL;
        for (int i = 0; i < g_conn_count; i++)
            if (g_conns[i].in_use && g_conns[i].conn_id == conn_id) { cn = &g_conns[i]; break; }
        if (!cn) continue;

        pthread_mutex_lock(&cn->lock);
        int nh = (cn->head + 1) % RXQ_SIZE;
        if (nh != cn->tail) {
            rx_msg_t *m = &cn->queue[cn->head];
            m->op = mtp->op;
            m->ack_flag = mtp->ack_flag;
            m->seq_num = ntohl(mtp->seq_num);
            /* 只拷贝实际存在的载荷字节（数据分组为 PAYLOAD_LEN，ACK 为 0） */
            if (plen > 0)
                memcpy(m->payload, pkt + sizeof(eth_header_t) + ip_ihl + sizeof(mtp_header_t), plen);
            cn->head = nh;
        }
        pthread_mutex_unlock(&cn->lock);
    }
    return NULL;
}

/* 从连接缓冲区取一个分组（非阻塞）；返回 1 成功，0 空。已给。 */
static int conn_pop(conn_t *cn, rx_msg_t *out) {
    int ok = 0;
    pthread_mutex_lock(&cn->lock);
    if (cn->tail != cn->head) {
        *out = cn->queue[cn->tail];
        cn->tail = (cn->tail + 1) % RXQ_SIZE;
        ok = 1;
    }
    pthread_mutex_unlock(&cn->lock);
    return ok;
}

/* 已给。 */
void init_host(config_entry_t *cfgs, int n, const char *host_name) {
    g_n = n;
    memcpy(g_cfg, cfgs, sizeof(config_entry_t) * n);

    for (int i = 0; i < n; i++)
        if (strcmp(cfgs[i].host_name, host_name) == 0) {
            g_rank = cfgs[i].rank;
            g_my_ip = cfgs[i].host_ip;
            break;
        }
    if (g_rank < 0) {
        fprintf(stderr, "init_host: host %s not found in config\n", host_name);
        exit(1);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    const char *iface = NULL;
    for (int i = 0; i < n; i++)
        if (cfgs[i].rank == g_rank) iface = cfgs[i].host_iface;

    g_host_handle = pcap_open_live(iface, DEV_BUF_SIZE, 1, 1, errbuf);
    if (!g_host_handle) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", iface, errbuf);
        exit(1);
    }
    pcap_setdirection(g_host_handle, PCAP_D_IN);

    pthread_t tid;
    pthread_create(&tid, NULL, host_rx_thread, NULL);
    printf("[host] %s rank=%d iface=%s ready\n", host_name, g_rank, iface);
    fflush(stdout);
}

/* 已给。 */
int init_conn(uint16_t conn_id, uint32_t local_ip, uint32_t remote_ip) {
    if (g_conn_count >= MAX_CONNS) return -1;
    conn_t *cn = &g_conns[g_conn_count];
    memset(cn, 0, sizeof(conn_t));
    cn->in_use = 1;
    cn->conn_id = conn_id;
    cn->local_ip = local_ip;
    cn->remote_ip = remote_ip;
    cn->head = cn->tail = 0;
    pthread_mutex_init(&cn->lock, NULL);
    return g_conn_count++;
}

/*------------- 可靠传输：发送端 -------------
 * 固定窗口 + 超时重传 + 独立 ACK（选择重传），初始序列号为 0。
 * 假设 size 是 PAYLOAD_LEN 的整数倍，故每个分组都是满载荷 PAYLOAD_LEN。 */
int m_send(int conn, const void *buf, uint32_t size, uint8_t op) {
    if (conn < 0 || conn >= g_conn_count) return -1;
    conn_t *cn = &g_conns[conn];

    uint32_t npkts = size / PAYLOAD_LEN;
    if (npkts == 0) return 0;

    uint8_t *acked = calloc(npkts, sizeof(uint8_t));
    uint64_t *sent_at = calloc(npkts, sizeof(uint64_t));
    if (!acked || !sent_at) {
        free(acked);
        free(sent_at);
        return -1;
    }

    uint32_t base = 0;
    const uint8_t *bytes = (const uint8_t *)buf;

    while (base < npkts) {
        rx_msg_t msg;
        while (conn_pop(cn, &msg)) {
            if (msg.ack_flag && msg.seq_num < npkts)
                acked[msg.seq_num] = 1;
        }

        while (base < npkts && acked[base])
            base++;

        uint64_t now = now_us();
        uint32_t end = base + WINDOW;
        if (end > npkts)
            end = npkts;
        for (uint32_t s = base; s < end; s++) {
            if (!acked[s] && (sent_at[s] == 0 || now - sent_at[s] >= RTO_US)) {
                conn_send(cn, s, 0, op, bytes + s * PAYLOAD_LEN, PAYLOAD_LEN);
                sent_at[s] = now;
            }
        }
        usleep(200);
    }

    free(acked);
    free(sent_at);
    return (int)size;
}

/*------------- 可靠传输：接收端 -------------
 * 假设 size 是 PAYLOAD_LEN 的整数倍，故每个数据分组都是满载荷 PAYLOAD_LEN。 */
int m_recv(int conn, void *buf, uint32_t size, uint8_t op) {
    if (conn < 0 || conn >= g_conn_count) return -1;
    conn_t *cn = &g_conns[conn];

    uint32_t npkts = size / PAYLOAD_LEN;
    if (npkts == 0) return 0;

    uint8_t *recvd = calloc(npkts, sizeof(uint8_t));
    if (!recvd)
        return -1;

    uint32_t got = 0;
    uint64_t complete_at = 0;
    uint8_t *bytes = (uint8_t *)buf;

    while (1) {
        int progressed = 0;
        rx_msg_t msg;
        while (conn_pop(cn, &msg)) {
            progressed = 1;
            if (!msg.ack_flag && msg.seq_num < npkts) {
                if (!recvd[msg.seq_num]) {
                    memcpy(bytes + msg.seq_num * PAYLOAD_LEN, msg.payload, PAYLOAD_LEN);
                    recvd[msg.seq_num] = 1;
                    got++;
                }
                conn_send(cn, msg.seq_num, 1, op, NULL, 0);
            }
        }

        uint64_t now = now_us();
        if (got >= npkts) {
            if (complete_at == 0)
                complete_at = now;
            else if (now - complete_at > 500000)
                break;
        }

        if (!progressed)
            usleep(200);
    }

    free(recvd);
    return (int)size;
}

/*------------- 环形集合通信 ------------- */
typedef struct {
    int      conn;
    char    *buf;
    uint32_t size;
    uint8_t  op;
} recv_args_t;

/* 接收线程入口（已给） */
static void *recv_worker(void *a) {
    recv_args_t *ra = (recv_args_t *)a;
    m_recv(ra->conn, ra->buf, ra->size, ra->op);
    return NULL;
}

/* 环形集合通信：向后继发 src，从前驱收到 dst。 */
static int ring_collective(char *src, char *dst, uint32_t size, uint8_t op) {
    int N = g_n, j = g_rank;
    uint32_t succ_ip = g_cfg[(j + 1) % N].host_ip;
    uint32_t pred_ip = g_cfg[(j - 1 + N) % N].host_ip;

    int succ_conn = init_conn((uint16_t)j, g_my_ip, succ_ip);
    int pred_conn = init_conn((uint16_t)((j - 1 + N) % N), g_my_ip, pred_ip);
    if (succ_conn < 0 || pred_conn < 0)
        return -1;

    recv_args_t ra;
    ra.conn = pred_conn;
    ra.buf = dst;
    ra.size = size;
    ra.op = op;

    pthread_t tid;
    if (pthread_create(&tid, NULL, recv_worker, &ra) != 0)
        return -1;

    int ret = m_send(succ_conn, src, size, op);
    pthread_join(tid, NULL);
    if (ret < 0)
        return ret;
    return 0;
}

int shift(int group_id, char *src_addr, char *dst_addr, uint32_t size) {
    (void)group_id;
    return ring_collective(src_addr, dst_addr, size, OP_TRANSMISSION);
}

int allreduce(int group_id, char *src_addr, char *dst_addr, uint32_t size) {
    (void)group_id;
    return ring_collective(src_addr, dst_addr, size, OP_ALLREDUCE);
}

/*======================================================================
 *  路由器端
 *====================================================================*/

static net_device_t  g_devs[MAX_GROUP_SIZE];
static int           g_dev_count = 0;
static dev_buffer_t  g_dev_buf;

static route_entry_t g_route[MAX_GROUP_SIZE];
static int           g_route_count = 0;

static conn_ctx_t    g_conn_ctx[MAX_GROUP_SIZE];
static int           g_group_n = 0;
static agtr_t       *g_agtr = NULL;

/* 路由器某端口抓包线程（已给） */
static void *dev_capture_thread(void *arg) {
    net_device_t *dev = (net_device_t *)arg;
    struct pcap_pkthdr *hdr;
    const u_char *pkt;
    int rc;
    while ((rc = pcap_next_ex(dev->handle, &hdr, &pkt)) >= 0) {
        if (rc == 0) continue;
        pthread_mutex_lock(&g_dev_buf.lock);
        int nh = (g_dev_buf.head + 1) % DEV_RING_SIZE;
        if (nh != g_dev_buf.tail) {
            dev_pkt_t *e = &g_dev_buf.packets[g_dev_buf.head];
            e->device = dev;
            e->len = hdr->caplen > DEV_BUF_SIZE ? DEV_BUF_SIZE : hdr->caplen;
            memcpy(e->data, pkt, e->len);
            g_dev_buf.head = nh;
        } else {
            fprintf(stderr, "[router] packet buffer full, drop\n");
        }
        pthread_mutex_unlock(&g_dev_buf.lock);
    }
    return NULL;
}

/* 按目的 IP 查转发表，从对应端口注入该帧。已给。 */
static void router_forward(const uint8_t *frame, int len, uint32_t dst_ip) {
    const char *out_port = NULL;
    for (int i = 0; i < g_route_count; i++)
        if (g_route[i].dst_ip == dst_ip) { out_port = g_route[i].out_port; break; }
    if (!out_port) return;
    for (int i = 0; i < g_dev_count; i++)
        if (strcmp(g_devs[i].name, out_port) == 0) {
            pcap_inject(g_devs[i].handle, frame, len);
            return;
        }
}

/* 已给。 */
void init_router(config_entry_t *cfgs, int n) {
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(&g_dev_buf, 0, sizeof(g_dev_buf));
    pthread_mutex_init(&g_dev_buf.lock, NULL);

    for (int i = 0; i < n && g_dev_count < MAX_GROUP_SIZE; i++) {
        const char *port = cfgs[i].router_iface;
        int dup = 0;
        for (int k = 0; k < g_dev_count; k++)
            if (strcmp(g_devs[k].name, port) == 0) dup = 1;
        if (dup) continue;

        net_device_t *dev = &g_devs[g_dev_count];
        strncpy(dev->name, port, sizeof(dev->name) - 1);
        dev->index = g_dev_count;
        dev->handle = pcap_open_live(port, DEV_BUF_SIZE, 1, 1, errbuf);
        if (!dev->handle) {
            fprintf(stderr, "pcap_open_live(%s) failed: %s\n", port, errbuf);
            continue;
        }
        pcap_setdirection(dev->handle, PCAP_D_IN);
        pthread_create(&dev->thread_id, NULL, dev_capture_thread, dev);
        g_dev_count++;
    }

    for (int i = 0; i < n; i++) {
        g_route[g_route_count].dst_ip = cfgs[i].host_ip;
        strncpy(g_route[g_route_count].out_port, cfgs[i].router_iface,
                sizeof(g_route[g_route_count].out_port) - 1);
        g_route_count++;
    }

    g_group_n = n;
    for (int k = 0; k < n; k++) {
        g_conn_ctx[k].conn_id = (uint16_t)k;
        g_conn_ctx[k].src_ip  = cfgs[k].host_ip;
        g_conn_ctx[k].dst_ip  = cfgs[(k + 1) % n].host_ip;
        g_conn_ctx[k].rank    = k;
    }

    g_agtr = calloc(AGTR_ARRAY_SIZE, sizeof(agtr_t));   /* calloc 清零，初始各 slot 即干净 */
    if (!g_agtr) { fprintf(stderr, "agtr alloc failed\n"); exit(1); }
    printf("[router] opened %d ports, group_n=%d, agtr_slots=%d, window=%d\n",
           g_dev_count, g_group_n, AGTR_ARRAY_SIZE, WINDOW);
    fflush(stdout);
}

/* 从共享缓冲区取一帧（非阻塞）。已给。 */
static int dev_pop(dev_pkt_t *out) {
    int ok = 0;
    pthread_mutex_lock(&g_dev_buf.lock);
    if (g_dev_buf.tail != g_dev_buf.head) {
        *out = g_dev_buf.packets[g_dev_buf.tail];
        g_dev_buf.tail = (g_dev_buf.tail + 1) % DEV_RING_SIZE;
        ok = 1;
    }
    pthread_mutex_unlock(&g_dev_buf.lock);
    return ok;
}

/* 把某个已聚合完成的 slot 广播给所有连接（取模寻址）。已给。 */
static void broadcast_slot(uint32_t seq) {
    agtr_t *a = &g_agtr[seq % AGTR_ARRAY_SIZE];
    uint8_t frame[HDR_LEN + PAYLOAD_LEN];
    for (int k = 0; k < g_group_n; k++) {
        conn_ctx_t *cc = &g_conn_ctx[k];
        int len = build_frame(frame, cc->src_ip, cc->dst_ip,
                              (uint16_t)k, seq, 0, OP_ALLREDUCE,
                              a->payload, PAYLOAD_LEN);
        router_forward(frame, len, cc->dst_ip);
    }
}

/* 聚合器复用：清空“一个窗口外”的 slot（gen 仅用于定位物理 slot）。已给。 */
static void clear_slot(uint32_t gen) {
    agtr_t *a = &g_agtr[gen % AGTR_ARRAY_SIZE];
    a->bitmap = 0;
    memset(a->payload, 0, sizeof(a->payload));
}

/*------------- 普通路由器：只按目的 IP 转发 ------------- */
void Router(void) {
    printf("[router] running as ROUTER (forward only)\n");
    fflush(stdout);
    while (1) {
        dev_pkt_t pk;
        if (!dev_pop(&pk)) { usleep(200); continue; }

        if (pk.len < HDR_LEN)
            continue;

        eth_header_t *eth = (eth_header_t *)pk.data;
        if (ntohs(eth->ether_type) != ETH_TYPE_IP)
            continue;

        ip_header_t *ip = (ip_header_t *)(pk.data + sizeof(eth_header_t));
        if (ip->protocol != IP_PROTO_MTP)
            continue;

        router_forward(pk.data, pk.len, ip->dst_ip);
    }
}

/*------------- 在网计算路由器：转发 + 聚合 ------------- */
void INC(void) {
    printf("[router] running as INC (forward + aggregate)\n");
    fflush(stdout);
    uint32_t full_mask = (g_group_n >= 32) ? 0xffffffffu : ((1u << g_group_n) - 1);

    while (1) {
        dev_pkt_t pk;
        if (!dev_pop(&pk)) { usleep(200); continue; }

        /* 解析（已给） */
        eth_header_t *eth = (eth_header_t *)pk.data;
        if (ntohs(eth->ether_type) != ETH_TYPE_IP) continue;
        ip_header_t *ip = (ip_header_t *)(pk.data + sizeof(eth_header_t));
        if (ip->protocol != IP_PROTO_MTP) continue;

        int ip_ihl = (ip->version_ihl & 0x0f) * 4;
        mtp_header_t *mtp = (mtp_header_t *)(pk.data + sizeof(eth_header_t) + ip_ihl);
        /* 载荷指针（数据分组载荷恒为 PAYLOAD_LEN）： */
        int32_t *payload = (int32_t *)(pk.data + sizeof(eth_header_t) + ip_ihl + sizeof(mtp_header_t));

        if (mtp->ack_flag || mtp->op != OP_ALLREDUCE) {
            router_forward(pk.data, pk.len, ip->dst_ip);
            continue;
        }

        uint16_t k = ntohs(mtp->conn_id);
        uint32_t seq = ntohl(mtp->seq_num);
        if (k >= (uint16_t)g_group_n)
            continue;

        agtr_t *a = &g_agtr[seq % AGTR_ARRAY_SIZE];
        uint32_t bit = 1u << k;

        if ((a->bitmap & bit) == 0) {
            for (uint32_t i = 0; i < PAYLOAD_LEN / sizeof(int32_t); i++)
                a->payload[i] += payload[i];
            a->bitmap |= bit;
        }

        if (a->bitmap == full_mask) {
            clear_slot(seq + WINDOW);
            broadcast_slot(seq);
        }
    }
}
