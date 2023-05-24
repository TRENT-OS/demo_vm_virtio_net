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

#define PTR_OFFS(p, o)  ((typeof(p))(((uintptr_t)(p)) + (o)))

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


static uint16_t one_comp_checksum(
    char const *data,
    size_t length
) {
    uint32_t sum = 0;

    for (int i = 0; i < length - 1; i += 2) {
        uint16_t data_word = *((uint16_t const *)&data[i]);
        sum += data_word;
    }
    /* Odd size */
    if (0 != length % 2) {
        uint16_t data_word = (uint16_t)data[length - 1];
        sum += data_word;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}


static int send_outgoing_packet(
    ctx_t *ctx,
    char const *outgoing_data,
    size_t outgoing_data_size
) {
    virtqueue_driver_t *vq = &(ctx->send_virtqueue);

    /* Must cast the const qualifier of 'outgoing_data' away. */
    int err = camkes_virtqueue_driver_scatter_send_buffer(vq, (void *)outgoing_data,
                                                          outgoing_data_size);
    if (err) {
        ZF_LOGE("Failed to send data through virtqueue (%d)", err);
        return -1;
    }

    vq->notify();

    return 0;
}


static void print_ip_packet(
    char const *ip_buf,
    size_t ip_length
) {
    printf("Packet Contents:");

    for (int i = 0; i < ip_length; i++) {
        if (i % 15 == 0) {
            printf("\n%d:\t", i);
        }
        printf("%x ", ip_buf[i]);
    }
    printf("\n");

    struct iphdr const *ip = (struct iphdr const *)ip_buf;

    char sz_saddr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), sz_saddr, sizeof(sz_saddr));
    char sz_daddr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->daddr), sz_daddr, sizeof(sz_daddr));

    printf("IP Header - Version: IPv%d protocol: %d | src address: %s",
           ip->version, ip->protocol, sz_saddr);
    printf(" | dest address: %s\n", sz_daddr);

    switch (ip->protocol) {
        case IPPROTO_ICMP: {
            struct icmphdr const *icmp = (struct icmphdr const *)&ip_buf[sizeof(struct iphdr)];
            printf("ICMP Header - Type: %d | id: %d | seq: %d\n",
                   icmp->type, icmp->un.echo.id, icmp->un.echo.sequence);
            break;
        }
        default:
            /* content dumping not supported for IPPROTO_TCP, IPPROTO_UDP ... */
            break;
    }
    printf("\n");
}


static void handle_packet_eth_arp(
    ctx_t *ctx,
    void const *recv_data,
    size_t recv_data_size
) {
    char reply_buffer[ETH_FRAME_LEN];

    //---------------------------------
    //| ethhdr | ether_arp            |
    //---------------------------------
    struct ether_arp const *arp_req = PTR_OFFS(recv_data, sizeof(struct ethhdr));

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

    int err = send_outgoing_packet(ctx, reply_buffer,
                                   sizeof(struct ethhdr) + sizeof(struct ether_arp));
    if (err) {
        ZF_LOGE("failed to send ARP reply (%d)", err);
    }
}


static void handle_packet_eth_ip(
    ctx_t *ctx,
    void const *recv_data,
    size_t recv_data_size
) {
    print_ip_packet(PTR_OFFS(recv_data, sizeof(struct ethhdr)),
                    recv_data_size - sizeof(struct ethhdr));

    struct ethhdr const *eth_req = recv_data;
    struct iphdr const *ip_req = PTR_OFFS(recv_data, sizeof(struct ethhdr));

    if (4 != ip_req->version) { /* don't need a endian conversion for uint8 */
        /* ignore packets with unsupported IP version */
        return;
    }

    switch (ip_req->protocol) { /* don't need a endian conversion for uint8 */
        case IPPROTO_ICMP:
            /* continue below */
            break;
        default:
            /* ignore anything else (IPPROTO_TCP, IPPROTO_UDP ...) */
            return;
    }

    struct icmphdr const *icmp_req = PTR_OFFS(recv_data, sizeof(struct ethhdr) + sizeof(struct iphdr));

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

    int err = send_outgoing_packet(ctx, reply_buffer,
                                   sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + ICMP_MSG_SIZE);
    if (err) {
        ZF_LOGE("failed to send ICMP reply (%d)", err);
    }
}


static void handle_recv_data(
    ctx_t *ctx,
    void const *recv_data,
    size_t recv_data_size
) {
    /* We are expecting the packets to be ethernet frames, so there must be a
     * ethernet header.
     */
    if (recv_data_size < sizeof(struct ethhdr)) {
        ZF_LOGE("Ignore invalid ethernet packet with length %zu", recv_data_size);
        return;
    }
    /* Actually, we should check the MAC address here to see whether this packet
     * is for us or not. Since our little network only has the VM an us, we just
     * assume anything the VM sends is for us. This example does not even have
     * a dedicated MAC address configured, it makes up one on demand.
     */

    struct ethhdr const *rcv_req = recv_data;
    uint16_t protocol = ntohs(rcv_req->h_proto);
    switch (protocol) {
        case ETH_P_ARP:
            handle_packet_eth_arp(ctx, recv_data, recv_data_size);
            break;
        case ETH_P_IP:
            handle_packet_eth_ip(ctx, recv_data, recv_data_size);
            break;
        case ETH_P_IPV6:
            /* Seems the VM also sends IPv6 packets in parallel to IPv4. We
             * don't support IPv6, so we ignore this.
             */
            ZF_LOGI("ignore IPv6 packet");
            break;
        default:
            /* Ignore any other protocols. */
            ZF_LOGI("ignore packet with ethernet protocol 0x%x", protocol);
            break;
    }
}


static void handle_recv_callback(
    ctx_t *ctx
) {
    virtqueue_device_t *vq = &(ctx->recv_virtqueue);

    /* One or more packets are available from the queue. */
    for(;;) {
        int err;
        virtqueue_ring_object_t handle = {0};
        if (!virtqueue_get_available_buf(vq, &handle)) {
            return; /* no more data */
        }

        /* We support normal ethernet packets only, where the max size is well
         * defined. Thus a fixed buffer allocated from the stack is used to get
         * each packet from the queue. Allocating the buffer from the stack is
         * fine for this example. Give the relatively small size it might also
         * be ok in general, and this makes this function thread safe. However,
         * static or dynamic allocation from the heap should be considered, to
         * reduce stack usage.
         */
        char buf[ETH_FRAME_LEN];
        size_t len = virtqueue_scattered_available_size(vq, &handle);
        if (len > sizeof(buf)) {
            ZF_LOGW("Dropping frame, size (%zu) exceeds max (%zu)", len, sizeof(buf));
            /* Return the (chained) buffer(s). We use 0 for the payload length,
             * because there is no data in there. Technically, the ethernet
             * frame is still in there, but that is not relevant any longer.
             */
            if (!virtqueue_add_used_buf(vq, &handle, 0)) {
                /* This is not supposed to happen, and there is nothing we can
                 * do here.
                 */
                ZF_LOGW("Could not release queue buffer");
            }
            continue;
        }

        /* Copy the frame from the chained buffers in the queue to our
         * contiguous buffer.
         */
        err = camkes_virtqueue_device_gather_copy_buffer(vq, &handle, buf, len);
        if (err) {
            ZF_LOGW("Dropping frame, can't gather queue buffers");
            continue;
        }

        handle_recv_data(ctx, buf, len);

        vq->notify();
    }

    UNREACHABLE();
}


static void handle_send_callback(
    ctx_t *ctx
) {
    virtqueue_driver_t *vq = &(ctx->send_virtqueue);

    /* Memory for one or more packets in the queue can be released. */
    for(;;) {
        virtqueue_ring_object_t handle = {0};
        uint32_t wr_len = 0;
        if (!virtqueue_get_used_buf(vq, &handle, &wr_len)) {
            /* No more packets left to clean up. */
            return;
        }

        for(;;) {
            void *buf = NULL;
            unsigned int buf_size = 0;
            vq_flags_t flag = 0;
            int err = camkes_virtqueue_driver_gather_buffer(vq, &handle, &buf,
                                                            &buf_size, &flag);
            if (err) {
                if (-1 != err) {
                    ZF_LOGE("Unexpected failure getting driver queue buffer (%d)",
                            err);
                }
                break;
            }

            /* Clean up and free the buffer we allocated */
            camkes_virtqueue_buffer_free(vq, buf);
        }
    }

    UNREACHABLE();
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
