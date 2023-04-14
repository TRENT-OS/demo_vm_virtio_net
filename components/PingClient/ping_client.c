/*
 * Copyright 2023, Hensoldt Cyber
 * Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <autoconf.h>
#include <camkes.h>
#include <stdio.h>
#include <virtqueue.h>
#include <camkes/virtqueue.h>
#include <utils/util.h>
#include <string.h>

#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define ICMP_MSG_SIZE (64 - sizeof(struct icmphdr))
#define IPV4_LENGTH 4

typedef struct {
    bool init_ok;
    virtqueue_device_t recv_virtqueue;
    virtqueue_driver_t send_virtqueue;
} ctx_t;

static ctx_t the_ctx;


static ctx_t *get_ctx(void)
{
    return &the_ctx;
}


static unsigned short one_comp_checksum(
    char *data,
    size_t length
) {
    unsigned int sum = 0;
    int i = 0;

    for (int i = 0; i < length - 1; i += 2) {
        unsigned short data_word = *((unsigned short *)&data[i]);
        sum += data_word;
    }
    /* Odd size */
    if (0 != length % 2) {
        unsigned short data_word = (unsigned char)data[length - 1];
        sum += data_word;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}


static int send_outgoing_packet(
    ctx_t *ctx,
    char *outgoing_data,
    size_t outgoing_data_size
) {
    int err;
    virtqueue_driver_t *vq = &(ctx->send_virtqueue);

    void *buf = NULL;
    err = camkes_virtqueue_buffer_alloc(vq, &buf, outgoing_data_size);
    if (err) {
        ZF_LOGE("Failed to allocate queue buffer (%d)", err);
        return -1;
    }

    memcpy(buf, outgoing_data, outgoing_data_size);

    err = camkes_virtqueue_driver_send_buffer(vq, buf, outgoing_data_size);
    if (err) {
        ZF_LOGE("Failed to send queue buffer (%d)", err);
        camkes_virtqueue_buffer_free(vq, buf);
        return -1;
    }

    vq->notify();

    return 0;
}


static void print_ip_packet(
    char *ip_buf,
    size_t ip_length
) {
    struct iphdr *ip = (struct iphdr *)ip_buf;
    struct icmphdr *icmp = (struct icmphdr *)&ip_buf[sizeof(struct iphdr)];

    printf("Packet Contents:");

    for (int i = 0; i < ip_length; i++) {
        if (i % 15 == 0) {
            printf("\n%d:\t", i);
        }
        printf("%x ", ip_buf[i]);
    }
    printf("\n");

    struct in_addr saddr = {ip->saddr};
    struct in_addr daddr = {ip->daddr};
    printf("IP Header - Version: IPv%d protocol: %d | src address: %s",
           ip->version, ip->protocol, inet_ntoa(saddr));
    printf(" | dest address: %s\n", inet_ntoa(daddr));
    printf("ICMP Header - Type: %d | id: %d | seq: %d\n",
           icmp->type, icmp->un.echo.id, icmp->un.echo.sequence);
    printf("\n");
}


static int create_arp_req_reply(
    ctx_t *ctx,
    char *recv_data,
    size_t recv_data_size
) {
    char reply_buffer[ETH_FRAME_LEN];

    //---------------------------------
    //| ethhdr | ether_arp            |
    //---------------------------------
    struct ether_arp *arp_req = (struct ether_arp *)&recv_data[sizeof(struct ethhdr)];

    struct ethhdr *send_reply = (struct ethhdr *)reply_buffer;
    struct ether_arp *arp_reply = (struct ether_arp *)&reply_buffer[sizeof(struct ethhdr)];

    memcpy(send_reply->h_dest, arp_req->arp_sha, ETH_ALEN);
    send_reply->h_proto = htons(ETH_P_ARP);

    /* MAC Address */
    memcpy(arp_reply->arp_tha, arp_req->arp_sha, ETH_ALEN);
    memcpy(arp_reply->arp_sha, arp_req->arp_sha, ETH_ALEN);
    /* This is an ARP request from the VM in preparation for the ping. The VM
     * just has our IP address, but it needs the MAC address also. There is no
     * MAC configured in this simple example, we simply pretend our MAC is the
     * sender's MAC "+ 2". This is fine, as we and the VM are the only devices
     * in our little virtual network.  We don't even have to remember this MAC,
     * because the VM will use this MAC in the dest field of the ping packet, so
     * we can simply copy dest to src in the response.
     */
    arp_reply->arp_sha[5] = arp_reply->arp_sha[5] + 2;

    memcpy(send_reply->h_source, arp_reply->arp_sha, ETH_ALEN);
    /* IP Addresss */
    for (int i = 0; i < IPV4_LENGTH; i++) {
        arp_reply->arp_spa[i] = arp_req->arp_tpa[i];
    }
    for (int i = 0; i < IPV4_LENGTH; i++) {
        arp_reply->arp_tpa[i] = arp_req->arp_spa[i];
    }
    /* ARP header fields */
    arp_reply->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_reply->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp_reply->ea_hdr.ar_op = htons(ARPOP_REPLY);
    arp_reply->ea_hdr.ar_hln = ETH_ALEN;
    arp_reply->ea_hdr.ar_pln = IPV4_LENGTH;

    return send_outgoing_packet(ctx, reply_buffer, sizeof(struct ethhdr) + sizeof(struct ether_arp));
}


static int create_icmp_req_reply(
    ctx_t *ctx,
    char *recv_data,
    size_t recv_data_size
) {
    struct ethhdr *eth_req = (struct ethhdr *)recv_data;
    struct iphdr *ip_req = (struct iphdr *)&recv_data[sizeof(struct ethhdr)];
    struct icmphdr *icmp_req = (struct icmphdr *)&recv_data[sizeof(struct ethhdr) + sizeof(struct iphdr)];

    char reply_buffer[ETH_FRAME_LEN];
    struct ethhdr *eth_reply = (struct ethhdr *)reply_buffer;
    struct iphdr *ip_reply = (struct iphdr *)&reply_buffer[sizeof(struct ethhdr)];
    struct icmphdr *icmp_reply = (struct icmphdr *)&reply_buffer[sizeof(struct ethhdr) + sizeof(struct iphdr)];
    char *icmp_msg = (char *)(icmp_reply + 1);

    memcpy(eth_reply->h_dest, eth_req->h_source, ETH_ALEN);
    memcpy(eth_reply->h_source, eth_req->h_dest, ETH_ALEN);
    eth_reply->h_proto = htons(ETH_P_IP);

    memcpy(ip_reply, ip_req, sizeof(struct iphdr));
    in_addr_t saddr = ip_reply->saddr;
    ip_reply->saddr = ip_reply->daddr;
    ip_reply->daddr = saddr;

    memset(icmp_msg, 0, ICMP_MSG_SIZE);
    icmp_reply->un.echo.sequence =  icmp_req->un.echo.sequence;
    icmp_reply->un.echo.id = icmp_req->un.echo.id;
    icmp_reply->type = ICMP_ECHOREPLY;
    icmp_reply->checksum = one_comp_checksum((char *)icmp_reply, sizeof(struct icmphdr) + ICMP_MSG_SIZE);

    /* Need to set checksum to 0 before calculating checksum of the header */
    ip_reply->check = 0;
    ip_reply->check = one_comp_checksum((char *)ip_reply, sizeof(struct iphdr));

    return send_outgoing_packet(ctx, reply_buffer,
                                sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + ICMP_MSG_SIZE);
}


static void handle_recv_data(
    ctx_t *ctx,
    char *recv_data,
    size_t recv_data_size
) {
    struct ethhdr *rcv_req = (struct ethhdr *)recv_data;
    /* Actually, we should check the MAC address here to see whether this packet
     * is for us or not. Since our little network only has the VM an us, we just
     * assume anything the VM sends is for us. This example does not even have
     * a dedicated MAC address configured, it makes up one on demand.
     */
    if (ntohs(rcv_req->h_proto) == ETH_P_ARP) {
        create_arp_req_reply(ctx, recv_data, recv_data_size);
    } else if (ntohs(rcv_req->h_proto) == ETH_P_IP) {
        char ip_packet[ETH_FRAME_LEN];
        memcpy(ip_packet, &recv_data[sizeof(struct ethhdr)], recv_data_size - sizeof(struct ethhdr));
        print_ip_packet(ip_packet, recv_data_size - sizeof(struct ethhdr));
        create_icmp_req_reply(ctx, recv_data, recv_data_size);
    }
}


static void handle_recv_callback(
    ctx_t *ctx
) {
    virtqueue_device_t *vq = &(ctx->recv_virtqueue);
    void *buf = NULL;
    size_t buf_size = 0;
    vq_flags_t flag;
    virtqueue_ring_object_t handle;
    if (!virtqueue_get_available_buf(vq, &handle)) {
        ZF_LOGE("Client virtqueue dequeue failed");
        return;
    }

    while (camkes_virtqueue_device_gather_buffer(vq, &handle, &buf, (unsigned int *)&buf_size, &flag) >= 0) {
        handle_recv_data(ctx, (char *)buf, buf_size);
    }

    if (!virtqueue_add_used_buf(vq, &handle, 0)) {
        ZF_LOGE("Unable to enqueue used recv buffer");
        return;
    }

    vq->notify();
}


static void handle_send_callback(
    ctx_t *ctx
) {
    virtqueue_driver_t *vq = &(ctx->send_virtqueue);
    void *buf = NULL;
    unsigned int buf_size = 0;
    uint32_t wr_len = 0;
    vq_flags_t flag;
    virtqueue_ring_object_t handle;
    if (!virtqueue_get_used_buf(vq, &handle, &wr_len)) {
        ZF_LOGE("Client virtqueue dequeue failed");
        return;
    }

    while (camkes_virtqueue_driver_gather_buffer(vq, &handle, &buf, (unsigned int *)&buf_size, &flag) >= 0) {
        /* Clean up and free the buffer we allocated */
        camkes_virtqueue_buffer_free(vq, buf);
    }
}


void ping_wait_callback(void)
{
    /* ToDo: Does the callback have a context or can we get the origin? */
    ctx_t *ctx = get_ctx();

    if (!ctx->init_ok) {
        ZF_LOGE("Callback disabled due to startup failure");
        return;
    }

    if (VQ_DEV_POLL(&(ctx->recv_virtqueue))) {
        handle_recv_callback(ctx);
    }

    if (VQ_DRV_POLL(&(ctx->send_virtqueue))) {
        handle_send_callback(ctx);
    }
}


void post_init(void)
{
    ctx_t *ctx = get_ctx();

    ZF_LOGI("Starting ping echo component");

    /* Initialise recv virtqueue */
    int err = camkes_virtqueue_device_init(&(ctx->recv_virtqueue), 0);
    if (err) {
        ZF_LOGE("Unable to initialise recv virtqueue");
        return;
    }

    /* Initialise send virtqueue */
    err = camkes_virtqueue_driver_init(&(ctx->send_virtqueue), 1);
    if (err) {
        ZF_LOGE("Unable to initialise send virtqueue");
        return;
    }

    ctx->init_ok = true;
}
