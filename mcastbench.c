/*
 * Copyright (c) 2025 Rafael F. Zalamena <rzalamena@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <err.h>
#include <errno.h>
#include <ifaddrs.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <event.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif /* IFNAMSIZ */

/* Multicast bench operation mode */
enum mb_operation_mode {
	MBOM_LISTENER,
	MBOM_SENDER,
};

/* Multicast bench socket */
struct mcastbench_socket {
	int fd;

	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} group;
	socklen_t grouplen;

	struct event ev_read;
	struct event ev_timer;
};

union address {
	struct in_addr v4;
	struct in6_addr v6;
};

/* Multicast bench configuration options. */
struct mcastbench_options {
	bool ipv6;
	uint8_t ttl;
	uint16_t port;

	enum mb_operation_mode mode;

	char if_name[IFNAMSIZ];
	int if_index;
	union address if_address;

	union address mcast_address;

	size_t mcast_sources_size;
	union address *mcast_sources;

	size_t sockets_size;
	struct mcastbench_socket *sockets;
};

static void
usage(void)
{
	fprintf(stderr,
	    "usage: mcastbench [-6h] [-i ifname] multicast-address\n"
	    "       mcastbench -l [-6h] [-i ifname] multicast-address [multicast-source]\n"
	    "\n"
	    "Options\n"
	    "  -6: use IPv6\n"
	    "  -h: help (this output)\n"
	    "  -i: interface name\n"
	    "  -l: listen to multicast data\n");

	exit(1);
}

static void
signal_handler(int sig, short event, void *arg)
{
	printf("received signal, exiting...\n");
	exit(0);
}

static int
mcastbench_get_ifinfo(struct mcastbench_options *opts, const char *ifname)
{
	struct ifaddrs *ifa_start;
	struct ifaddrs *ifa;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	unsigned int index;
	bool found_address = false;

	snprintf(opts->if_name, sizeof(opts->if_name), "%s", ifname);
	index = if_nametoindex(opts->if_name);
	if (index == 0) {
		fprintf(stderr, "%s: if_nametoindex: %s\n", __func__,
		    strerror(errno));
		return -1;
	}

	opts->if_index = (int)index;

	if (getifaddrs(&ifa_start) == -1) {
		fprintf(stderr, "%s: getifaddrs: %s\n", __func__,
		    strerror(errno));
		return -1;
	}

	for (ifa = ifa_start; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname) != 0)
			continue;
		if (ifa->ifa_addr == NULL)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET) {
			if (opts->ipv6)
				continue;

			sin = (struct sockaddr_in *)ifa->ifa_addr;
			opts->if_address.v4 = sin->sin_addr;
			found_address = true;
			break;
		} else if (ifa->ifa_addr->sa_family == AF_INET6) {
			if (!opts->ipv6)
				continue;

			sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			opts->if_address.v6 = sin6->sin6_addr;
			found_address = true;
			break;
		}
	}

	freeifaddrs(ifa_start);

	if (!found_address) {
		fprintf(stderr, "%s: no interface address found\n", __func__);
		return -1;
	}

	return 0;
}

static void
mcastbench_socket_read(int fd, short event, void *arg)
{
	struct mcastbench_socket *sock = arg;
	ssize_t n;
	char buffer[128];

	n = recv(sock->fd, buffer, sizeof(buffer), 0);
	if (n == -1) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return;

		printf("%d> recv: %s\n", sock->fd, strerror(errno));
	} else if (n == 0)
		printf("%d> recv: EOF\n", sock->fd);

	printf("%d> received %zd bytes\n", sock->fd, n);
}

static void
mcastbench_socket_send(int fd, short event, void *arg)
{
	struct mcastbench_socket *sock = arg;
	ssize_t n;
	struct timeval tv;
	const char *data = "hello world!";

	/* Schedule next send */
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	event_add(&sock->ev_timer, &tv);

	n = sendto(sock->fd, data, strlen(data), 0, &sock->group.sa,
	    sock->grouplen);
	if (n == -1) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return;

		printf("%d> sendto: %s\n", sock->fd, strerror(errno));
	} else if (n == 0)
		printf("%d> sendto: EOF\n", sock->fd);

	printf("%d> sent %zd bytes\n", sock->fd, n);
}

static void
mcastbench_socket_v4(struct mcastbench_socket *sock, const struct in_addr *ia,
    uint16_t port)
{
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd == -1)
		err(1, "socket");

	memset(&sock->group, 0, sizeof(sock->group));
	sock->group.sin.sin_family = AF_INET;
	sock->group.sin.sin_addr = *ia;
	sock->group.sin.sin_port = port;
	sock->grouplen = sizeof(sock->group.sin);
	sock->fd = fd;

	event_set(&sock->ev_read, sock->fd, EV_READ | EV_PERSIST,
	    mcastbench_socket_read, sock);
	evtimer_set(&sock->ev_timer, mcastbench_socket_send, sock);
}

static void
mcastbench_socket_v6(struct mcastbench_socket *sock, const struct in6_addr *i6a,
    uint16_t port)
{
	int fd;

	fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd == -1)
		err(1, "socket");

	memset(&sock->group, 0, sizeof(sock->group));
	sock->group.sin6.sin6_family = AF_INET6;
	sock->group.sin6.sin6_addr = *i6a;
	sock->group.sin6.sin6_port = port;
	sock->grouplen = sizeof(sock->group.sin6);
	sock->fd = fd;

	event_set(&sock->ev_read, sock->fd, EV_READ | EV_PERSIST,
	    mcastbench_socket_read, sock);
	evtimer_set(&sock->ev_timer, mcastbench_socket_send, sock);
}

static void
mcastbench_socket_bind(struct mcastbench_socket *sock)
{
	if (bind(sock->fd, &sock->group.sa, sock->grouplen) == -1)
		err(1, "bind");
}

static void
mcastbench_socket_ipv4_set_if(struct mcastbench_socket *sock, int if_index)
{
	struct ip_mreqn imr;

	memset(&imr, 0, sizeof(imr));
	imr.imr_ifindex = if_index;

	if (setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_IF, &imr, sizeof(imr))
	    == -1)
		fprintf(stderr, "%s: setsockopt: %s\n", __func__,
		    strerror(errno));
}

static void
mcastbench_socket_ipv6_set_if(struct mcastbench_socket *sock, int if_index)
{
	if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &if_index,
	    sizeof(if_index)) == -1)
		fprintf(stderr, "%s: setsockopt: %s\n", __func__,
		    strerror(errno));
}

static void
mcastbench_socket_ipv4_set_ttl(struct mcastbench_socket *sock, uint8_t ttl)
{
	int ttlval = (int)ttl;

	if (setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttlval,
	    sizeof(ttlval)) == -1)
		fprintf(stderr, "%s: setsockopt: %s\n", __func__,
		    strerror(errno));
}

static void
mcastbench_socket_ipv6_set_ttl(struct mcastbench_socket *sock, uint8_t ttl)
{
	int ttlval = (int)ttl;

	if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttlval,
	    sizeof(ttlval)) == -1)
		fprintf(stderr, "%s: setsockopt: %s\n", __func__,
		    strerror(errno));
}

static void
mcastbench_socket_ipv4_join(const struct mcastbench_options *opts,
    struct mcastbench_socket *sock)
{
	struct ip_mreqn imr;

	memset(&imr, 0, sizeof(imr));
	imr.imr_multiaddr = sock->group.sin.sin_addr;
	imr.imr_ifindex = opts->if_index;
	if (setsockopt(sock->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &imr,
	    sizeof(imr)) == -1)
		fprintf(stderr, "%s: setsockopt: %s\n", __func__,
		    strerror(errno));
}

static void
mcastbench_socket_ipv4_join_source(const struct mcastbench_options *opts,
    struct mcastbench_socket *sock)
{
	struct ip_mreq_source imr;
	int i;

	memset(&imr, 0, sizeof(imr));
	imr.imr_multiaddr = sock->group.sin.sin_addr;
	imr.imr_interface = opts->if_address.v4;

	for (i = 0; i < opts->mcast_sources_size; i++) {
		imr.imr_sourceaddr = opts->mcast_sources[i].v4;
		if (setsockopt(sock->fd, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP,
		    &imr, sizeof(imr)) == -1)
			fprintf(stderr, "%s: setsockopt: %s\n", __func__,
			    strerror(errno));
	}
}

static void
mcastbench_socket_ipv6_join(const struct mcastbench_options *opts,
    struct mcastbench_socket *sock)
{
	struct ipv6_mreq ipv6mr;

	memset(&ipv6mr, 0, sizeof(ipv6mr));
	ipv6mr.ipv6mr_multiaddr = sock->group.sin6.sin6_addr;
	ipv6mr.ipv6mr_interface = (unsigned int)opts->if_index;
	if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &ipv6mr,
	    sizeof(ipv6mr)) == -1)
		fprintf(stderr, "%s: setsockopt: %s\n", __func__,
		    strerror(errno));
}

static void
mcastbench_socket_ipv6_join_source(const struct mcastbench_options *opts,
    struct mcastbench_socket *sock)
{
	struct group_source_req gsr;
	struct sockaddr_in6 *sin6;
	int i;

	memset(&gsr, 0, sizeof(gsr));
	gsr.gsr_interface = (unsigned int)opts->if_index;

	sin6 = (struct sockaddr_in6 *)&gsr.gsr_group;
	sin6->sin6_family = AF_INET6;
	sin6->sin6_addr = opts->mcast_address.v6;

	sin6 = (struct sockaddr_in6 *)&gsr.gsr_source;
	sin6->sin6_family = AF_INET6;
	for (i = 0; i < opts->mcast_sources_size; i++) {
		sin6->sin6_addr = opts->mcast_sources[i].v6;
		if (setsockopt(sock->fd, IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP,
		    &gsr, sizeof(gsr)) == -1)
			fprintf(stderr, "%s: setsockopt: %s\n", __func__,
			    strerror(errno));
	}
}

static void
mcastbench_start_sender_socket(struct mcastbench_options *opts,
    struct mcastbench_socket *sock)
{
	struct timeval tv;

	if (opts->ipv6) {
		mcastbench_socket_v6(sock, &opts->mcast_address.v6, opts->port);
		mcastbench_socket_ipv6_set_if(sock, opts->if_index);
		mcastbench_socket_ipv6_set_ttl(sock, opts->ttl);
	} else {
		mcastbench_socket_v4(sock, &opts->mcast_address.v4, opts->port);
		mcastbench_socket_ipv4_set_if(sock, opts->if_index);
		mcastbench_socket_ipv4_set_ttl(sock, opts->ttl);
	}

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	event_add(&sock->ev_timer, &tv);
}

static void
mcastbench_start_sender(struct mcastbench_options *opts)
{
	size_t i;

	for (i = 0; i < opts->sockets_size; i++) {
		mcastbench_start_sender_socket(opts, &opts->sockets[i]);

		if (opts->ipv6)
			opts->mcast_address.v6.s6_addr16[7] =
			    htons((uint16_t)
			    (ntohs(opts->mcast_address.v6.s6_addr16[7]) + 1));
		else
			opts->mcast_address.v4.s_addr =
			    htonl(ntohl(opts->mcast_address.v4.s_addr) + 1);

	}
}

static void
mcastbench_start_listener_socket(struct mcastbench_options *opts,
    struct mcastbench_socket *sock)
{
	if (opts->ipv6) {
		mcastbench_socket_v6(sock, &opts->mcast_address.v6, opts->port);
		mcastbench_socket_bind(sock);
		mcastbench_socket_ipv6_set_if(sock, opts->if_index);
		if (opts->mcast_sources_size > 0)
			mcastbench_socket_ipv6_join_source(opts, sock);
		else
			mcastbench_socket_ipv6_join(opts, sock);
	} else {
		mcastbench_socket_v4(sock, &opts->mcast_address.v4, opts->port);
		mcastbench_socket_bind(sock);
		mcastbench_socket_ipv4_set_if(sock, opts->if_index);
		if (opts->mcast_sources_size > 0)
			mcastbench_socket_ipv4_join_source(opts, sock);
		else
			mcastbench_socket_ipv4_join(opts, sock);
	}

	event_add(&sock->ev_read, NULL);
}

static void
mcastbench_start_listener(struct mcastbench_options *opts)
{
	size_t i;

	for (i = 0; i < opts->sockets_size; i++) {
		mcastbench_start_listener_socket(opts, &opts->sockets[i]);

		if (opts->ipv6)
			opts->mcast_address.v6.s6_addr16[7] =
			    htons((uint16_t)
			    (ntohs(opts->mcast_address.v6.s6_addr16[7]) + 1));
		else
			opts->mcast_address.v4.s_addr =
			    htonl(ntohl(opts->mcast_address.v4.s_addr) + 1);
	}
}

int
main(int argc, char *argv[])
{
	char *endp;
	long sockets_count;
	int opt;
	int i;
	struct event ev_term, ev_int;
	char addr_str[INET6_ADDRSTRLEN];
	static struct mcastbench_options mb_opts;

	/* Default configuration */
	mb_opts.ttl = 8;
	mb_opts.port = 50123;
	mb_opts.mode = MBOM_SENDER;
	mb_opts.sockets_size = 1;

	while ((opt = getopt(argc, argv, "6hi:ln:")) != -1) {
		switch (opt) {
		case '6':
			mb_opts.ipv6 = true;
			break;
		case 'h':
			usage();
			break;
		case 'i':
			if (mcastbench_get_ifinfo(&mb_opts, optarg) == -1)
				return -1;
			break;
		case 'l':
			mb_opts.mode = MBOM_LISTENER;
			break;
		case 'n':
			errno = 0;
			sockets_count = strtol(optarg, &endp, 10);
			if (endp == optarg || *endp != '\0') {
				fprintf(stderr, "invalid sockets amount: %s\n",
				    optarg);
				return -1;
			}
			if (sockets_count < 1) {
				fprintf(stderr,
				    "must have a positive amount of sockets: %s\n",
				    optarg);
				return -1;
			}
			if (sockets_count > 1024) {
				fprintf(stderr,
				    "too many sockets: %s\n",
				    optarg);
				return -1;
			}

			mb_opts.sockets_size = (size_t)sockets_count;
			break;

		default:
			usage();
			break;
		}
	}
	if ((argc - optind) == 0) {
		fprintf(stderr, "missing multicast group address argument\n");
		usage();
	}
	if (mb_opts.mode == MBOM_SENDER) {
		if ((argc - optind) > 1) {
			fprintf(stderr, "too many arguments\n");
			usage();
		}
	}

	if (inet_pton(mb_opts.ipv6 ? AF_INET6 : AF_INET, argv[optind],
	    &mb_opts.mcast_address) != 1) {
		fprintf(stderr, "invalid multicast group address: %s\n",
		    argv[optind]);
		return 1;
	}
	optind++;

	/* Validate source address(es) */
	mb_opts.mcast_sources_size = argc - optind;
	if (mb_opts.mcast_sources_size > 0) {
		mb_opts.mcast_sources =
		    calloc(mb_opts.mcast_sources_size, sizeof(union address));

		for (i = 0; i < mb_opts.mcast_sources_size; i++) {
			if (inet_pton(mb_opts.ipv6 ? AF_INET6 : AF_INET,
			    argv[optind], &mb_opts.mcast_sources[i]) != 1) {
				fprintf(stderr,
				    "invalid multicast source address: %s\n",
				    argv[optind + 1]);
				return 1;
			}
			optind++;
		}
	}

	mb_opts.sockets =
	    calloc(mb_opts.sockets_size, sizeof(struct mcastbench_socket));
	if (mb_opts.sockets == NULL)
		err(1, "calloc");

	event_init();
	signal_set(&ev_term, SIGTERM, signal_handler, NULL);
	signal_set(&ev_int, SIGINT, signal_handler, NULL);
	signal_add(&ev_term, NULL);
	signal_add(&ev_int, NULL);

	inet_ntop(mb_opts.ipv6 ? AF_INET6 : AF_INET, &mb_opts.if_address,
	    addr_str, sizeof(addr_str));
	printf("interface %s (address %s) selected\n", mb_opts.if_name,
	    addr_str);

	if (mb_opts.mode == MBOM_SENDER)
		mcastbench_start_sender(&mb_opts);
	else
		mcastbench_start_listener(&mb_opts);

	event_dispatch();

	return 0;
}
