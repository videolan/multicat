/*****************************************************************************
 * multilive.c: VRRP-like protocol using multicast
 *****************************************************************************
 * Copyright (C) 2017 VideoLAN
 *
 * Authors: Christophe Massiot <massiot@via.ecp.fr>
 *          Arnaud de Turckheim <quarium@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

/* POLLRDHUP */
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <poll.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "util.h"
#include "ulist.h"

#define DEFAULT_PRIORITY        1
#define DEFAULT_PERIOD          (CLOCK_FREQ / 5)
#define DEFAULT_NOTIFY_PERIOD   (CLOCK_FREQ)
#define DEFAULT_DEAD            5
#define DEFAULT_STARTUP_DELAY   0

#define ANNOUNCE_SIZE           12
#define ANNOUNCE_VERSION_V1     1
#define ANNOUNCE_VERSION        2
#define CONFIG_LINE_SIZE        1024

#define NL_BUFFER 4096

struct source {
    uint32_t id;
    uint64_t last_notified;
    struct uchain uchain;
};

struct peer {
    bool input;
    bool persistent;
    char *name;
    char *conf;
    int fd;
    int ttl;
    int last_errno;
    int ifindex;
    struct uchain uchain;
    struct uchain sources;
};

struct config {
    struct uchain peers;
    int ttl;
};

static struct config config;
static const char *config_file = NULL;
static bool die = false;
static bool need_reload = true;
static uint32_t i_priority = DEFAULT_PRIORITY;
static uint64_t notify_period = DEFAULT_NOTIFY_PERIOD;
static uint32_t i_source = 0;
static int i_nl_fd = -1;

static void nl_get_links(void);

/*****************************************************************************
 * Announce format
 *****************************************************************************/
static inline void announce_set_version(uint8_t *p, uint32_t version)
{
    p[0] = version >> 24;
    p[1] = (version >> 16) & 0xff;
    p[2] = (version >>  8) & 0xff;
    p[3] = (version      ) & 0xff;
}

static inline uint32_t announce_get_version(const uint8_t *p)
{
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static inline void announce_set_priority(uint8_t *p, uint32_t priority)
{
    p[4] = priority >> 24;
    p[5] = (priority >> 16) & 0xff;
    p[6] = (priority >>  8) & 0xff;
    p[7] = (priority      ) & 0xff;
}

static inline uint32_t announce_get_priority(const uint8_t *p)
{
    return (p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7];
}

static inline void announce_set_source(uint8_t *p, uint32_t source)
{
    p[8] = source >> 24;
    p[9] = (source >> 16) & 0xff;
    p[10] = (source >> 8) & 0xff;
    p[11] = (source     ) & 0xff;
}

static inline uint32_t announce_get_source(const uint8_t *p)
{
    return (p[8] << 24) | (p[9] << 16) | (p[10] << 8) | p[11];
}

/*****************************************************************************
 * Up/Down
 *****************************************************************************/
static void Up( void )
{
    msg_Dbg( NULL, "going up" );
    printf("1\n");
}

static void Down( void )
{
    msg_Dbg( NULL, "going down" );
    printf("0\n");
}

/*****************************************************************************
 * Utils
 *****************************************************************************/

static int in_addr_get_ifindex(const in_addr_t *addr)
{
    if (!addr)
        return -1;

    struct ifaddrs *ifa;
    if (getifaddrs(&ifa))
        return -1;

    int ifindex = 0;
    for (struct ifaddrs *i = ifa; i; i = i->ifa_next) {
        if (i->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in *)i->ifa_addr;
            if (in->sin_addr.s_addr == *addr) {
                ifindex = if_nametoindex(i->ifa_name);
            }
        }
    }
    freeifaddrs(ifa);
    return ifindex;
}

/*****************************************************************************
 * Config
 *****************************************************************************/
static struct peer *peer_from_uchain(struct uchain *uchain)
{
    return uchain ? container_of(uchain, struct peer, uchain) : NULL;
}

static struct source *source_from_uchain(struct uchain *uchain)
{
    return uchain ? container_of(uchain, struct source, uchain) : NULL;
}

static struct peer *peer_next(struct uchain *list, struct peer *peer)
{
    if (!peer) {
        if (ulist_empty(list))
            return NULL;
        return peer_from_uchain(list->next);
    } else {
        if (peer->uchain.next == list)
            return NULL;
        return peer_from_uchain(peer->uchain.next);
    }
}

#define peer_foreach(list, name) \
    for (struct peer *name = peer_next(list, NULL); \
         name != NULL; \
         name = peer_next(list, name))

static struct peer *peer_next_input(struct uchain *list, struct peer *peer)
{
    while ((peer = peer_next(list, peer)))
        if (peer->input)
            break;
    return peer;
}

#define peer_foreach_input(list, name) \
    for (struct peer *name = peer_next_input(list, NULL); \
         name != NULL; \
         name = peer_next_input(list, name))

static struct peer *peer_next_output(struct uchain *list, struct peer *peer)
{
    while ((peer = peer_next(list, peer)))
        if (!peer->input)
            break;
    return peer;
}

#define peer_foreach_output(list, name) \
    for (struct peer *name = peer_next_output(list, NULL); \
         name != NULL; \
         name = peer_next_output(list, name))

static struct source *source_next(struct peer *peer, struct source *source)
{
    if (!peer)
        return NULL;

    if (!source) {
        if (ulist_empty(&peer->sources))
            return NULL;
        return source_from_uchain(peer->sources.next);
    }
    if (source->uchain.next == &peer->sources)
        return NULL;
    return source_from_uchain(source->uchain.next);
}

#define source_for_each(peer, name) \
    for (struct source *name = source_next(peer, NULL); \
         name != NULL; \
         name = source_next(peer, name))

static struct source *peer_find_source(struct peer *peer, uint32_t id)
{
    source_for_each(peer, source)
        if (source->id == id)
            return source;
    return NULL;
}

static void peer_init(struct peer *peer)
{
    if (peer)
    {
        peer->input = false;
        peer->persistent = false;
        peer->name = NULL;
        peer->conf = NULL;
        peer->fd = -1;
        peer->ifindex = -1;
        peer->ttl = 0;
        peer->last_errno = 0;
        uchain_init(&peer->uchain);
        ulist_init(&peer->sources);
    }
}

static void peer_close(struct peer *peer)
{
    if (peer) {
        if (peer->fd >= 0)
            msg_Dbg( NULL, "%s peer %s stop",
                     peer->input ? "input" : "output",
                     peer->name ?: peer->conf );

        struct uchain *uchain;
        while ((uchain = ulist_pop(&peer->sources))) {
            struct source *source = source_from_uchain(uchain);
            msg_Dbg( NULL, "%s peer %s source %x down",
                     peer->input ? "input" : "output",
                     peer->name ?: peer->conf, source->id );
            free(source);
        }

        if (peer->fd >= 0)
            close(peer->fd);
        peer->fd = -1;
        peer->ifindex = 0;
    }
}

static void peer_clean(struct peer *peer)
{
    if (peer)
    {
        peer_close(peer);
        msg_Dbg( NULL, "%s peer %s removing",
                 peer->input ? "input" : "output",
                 peer->name ?: peer->conf );
        free(peer->conf);
        free(peer->name);
    }
    peer_init(peer);
}

static int peer_get_link(struct peer *peer)
{
    if (!peer || !peer->conf)
        return -1;

    char *args = strdup(peer->conf);
    if (!args)
        return -1;

    int ifindex = 0;
    if (peer->input) {
        char *saveptr;
        strtok_r(args, "/", &saveptr);

        char *opt;
        while ((opt = strtok_r(NULL, "/", &saveptr)))
        {
            char *arg = index(opt, '=');
            if (!arg)
                continue;
            *arg++ = '\0';

            if (!strcmp(opt, "ifaddr")) {
                in_addr_t in_addr = inet_addr(arg);
                ifindex = in_addr_get_ifindex(&in_addr);
            } else if (!strcmp(opt, "ifname")) {
                ifindex = if_nametoindex(arg);
            } else if (!strcmp(opt, "ifindex")) {
                ifindex = strtol(arg, NULL, 0);
                char name[IFNAMSIZ];
                if (if_indextoname(ifindex, name) <= 0)
                    ifindex = 0;
            }
        }
    } else {
        const char *arg = strchr(args, '@');
        if (arg++) {
            in_addr_t in_addr = inet_addr(arg);
            ifindex = in_addr_get_ifindex(&in_addr);
        }
    }
    free(args);

    return ifindex;
}

static void peer_print(struct peer *peer)
{
    if (!peer || !peer->name)
        return;

    unsigned sources = 0;
    source_for_each(peer, source)
        sources++;

    printf("%s: %u\n", peer->name, sources);
}

static int peer_start(struct peer *peer)
{
    if (!peer)
        return -1;

    if (peer->fd >= 0)
        return 0;

    if (peer->ifindex <= 0)
        return -1;

    msg_Dbg(NULL, "%s peer %s start",
            peer->input ? "input" : "output",
            peer->name ?: peer->conf);

    struct opensocket_opt opt;
    memset(&opt, 0, sizeof(struct opensocket_opt));

    bool b_tcp, b_multicast;
    opt.pb_multicast = &b_multicast;
    int i_fd;

    if (peer->input)
        i_fd = OpenSocketSafe( peer->conf, 0, DEFAULT_PORT, 0, NULL,
                               &b_tcp, &opt );
    else
        i_fd = OpenSocketSafe( peer->conf, peer->ttl, 0, DEFAULT_PORT, NULL,
                               &b_tcp, &opt );
    if ( i_fd < 0 )
    {
        msg_Err( NULL, "unable to open input socket" );
        return -1;
    }

    if ( b_tcp )
    {
        msg_Err( NULL, "TCP is not supported" );
        close(i_fd);
        return -1;
    }

    if ( !b_multicast )
    {
        msg_Err( NULL, "unicast is not supported" );
        close(i_fd);
        return -1;
    }

    peer->fd = i_fd;
    return 0;
}

static struct peer *peer_create(const char *name, const char *conf, int ttl)
{
    if ( !conf )
    {
        msg_Warn( NULL, "invalid peer" );
        return NULL;
    }

    struct peer *peer = malloc(sizeof (*peer));
    char *name_dup = name ? strdup(name) : NULL;
    char *conf_dup = strdup(conf);
    char *args = strdup(conf);
    if ( !peer || !conf_dup || !args || (!name_dup && name) )
    {
        msg_Err( NULL, "allocation failed");
        free( peer );
        free( conf_dup );
        free( name_dup );
        return NULL;
    }

    peer_init(peer);
    peer->input = *conf == '@';
    peer->ttl = ttl;
    peer->conf = conf_dup;
    peer->name = name_dup;

    msg_Dbg(NULL, "%s peer %s created%s%s",
            peer->input ? "input" : "output",
            peer->name ?: peer->conf,
            peer->name ? ": " : "",
            peer->name ? peer->conf : "");

    peer_print(peer);
    return peer;
}

static bool peer_send(struct peer *peer, uint8_t *msg, size_t size)
{
    if ( !peer || peer->fd < 0 )
        return -1;

    if ( sendto( peer->fd, msg, size, 0, NULL, 0 ) < 0 )
    {
        if ( errno == EBADF )
        {
            msg_Err( NULL, "write error (%s)", strerror(errno) );
            die = true;
            return -1;
        }
        else if (errno != peer->last_errno)
        {
            /* otherwise do not die because these errors can be transient */
            msg_Warn( NULL, "write error (%s)", strerror(errno) );
            peer->last_errno = errno;
        }
        peer_close(peer);
        return -1;
    }
    if (peer->last_errno)
        msg_Dbg( NULL, "no more error on peer" );
    peer->last_errno = 0;
    return 0;
}

static int peer_recv(struct peer *peer, uint32_t *priority, uint32_t *source)
{
    if ( !peer || peer->fd < 0 )
        return -1;

    uint8_t buffer[ANNOUNCE_SIZE];
    ssize_t size = read( peer->fd, buffer, ANNOUNCE_SIZE );
    if (size < 0 && errno != EAGAIN && errno != EINTR && errno != ECONNREFUSED)
    {
        msg_Err( NULL, "unrecoverable read error, dying (%s)", strerror(errno) );
        die = true;
        return -1;
    }
    if (size <= 0)
        return -1;

    if (size != ANNOUNCE_SIZE)
    {
        msg_Warn( NULL, "short read, dropping" );
        return -1;
    }

    if (announce_get_version(buffer) > ANNOUNCE_VERSION)
    {
        msg_Warn(NULL, "dropping invalid announce");
        return -1;
    }

    uint32_t current_source = announce_get_source(buffer);
    if (current_source == i_source)
        return -1;

    *source = current_source;
    *priority = announce_get_priority(buffer);

    return 0;
}

static void peer_notified(struct peer *peer, uint32_t id, uint64_t date)
{
    struct source *source = peer_find_source(peer, id);
    if (!source) {
        if (!peer)
            return;

        source = malloc(sizeof (*source));
        if (!source)
            return;

        ulist_add(&peer->sources, &source->uchain);

        msg_Dbg( NULL, "%s peer %s source %x up",
                 peer->input ? "input" : "output",
                 peer->name ?: peer->conf, id );
        peer_print(peer);
    }

    source->id = id;
    source->last_notified = date;
}

static void peer_expire(struct peer *peer, uint64_t date)
{
    if (!peer)
        return;

    struct uchain *uchain, *tmp;
    ulist_delete_foreach(&peer->sources, uchain, tmp) {
        struct source *source = source_from_uchain(uchain);
        if (source->last_notified + 2 * notify_period < date) {
            msg_Dbg( NULL, "%s peer %s source %x down",
                     peer->input ? "input" : "output",
                     peer->name ?: peer->conf, source->id );
            ulist_delete(uchain);
            free(source);
            peer_print(peer);
        }
    }
}

static void config_init(struct config *config)
{
    if (config)
    {
        ulist_init(&config->peers);
        config->ttl = 0;
    }
}

static void config_clean(struct config *config)
{
    if (config)
    {
        struct uchain *uchain;
        while ((uchain = ulist_pop(&config->peers)))
        {
            struct peer *peer = peer_from_uchain(uchain);
            peer_clean(peer);
            free(peer);
        }
    }
    config_init(config);
}

static struct peer *config_find_peer(struct config *config, const char *conf)
{
    if (config && conf)
    {
        peer_foreach(&config->peers, peer) {
            if (!strcmp(peer->conf, conf))
                return peer;
        }
    }
    return NULL;
}

static int config_read(struct config *config, const char *config_file)
{
    if (!config_file)
    {
        nl_get_links();
        return 0;
    }

    msg_Dbg( NULL, "reloading configuration file" );

    FILE *file = fopen(config_file, "r");
    if (!file) {
        msg_Warn( NULL, "fail to open configuration file %s", config_file );
        return -1;
    }

    char buffer[CONFIG_LINE_SIZE];
    char *line;

    struct uchain peers;
    ulist_init(&peers);

    while ((line = fgets( buffer, sizeof (buffer), file ) ))
    {
        line += strspn(line, " \t");
        char *conf = strsep(&line, "\r\n");
        char *name = strsep(&conf, " \t");
        if (conf)
            conf += strspn(conf, " \t");
        if (!conf || !strlen(conf)) {
            conf = name;
            name = NULL;
        }

        struct peer *peer = config_find_peer(config, conf);
        if (peer)
        {
            ulist_delete(&peer->uchain);
            ulist_add(&peers, &peer->uchain);
        }
        else
        {
            peer = peer_create(name, conf, config->ttl);
            if (peer)
                ulist_add(&peers, &peer->uchain);
        }
    }

    fclose(file);

    struct uchain *uchain;
    while ((uchain = ulist_pop(&config->peers)))
    {
        struct peer *peer = peer_from_uchain(uchain);
        if (peer->persistent) {
            ulist_add(&peers, &peer->uchain);
        } else {
            peer_clean(peer);
            free(peer);
        }
    }

    while ((uchain = ulist_pop(&peers)))
    {
        struct peer *peer = peer_from_uchain(uchain);
        ulist_add(&config->peers, &peer->uchain);
    }

    nl_get_links();

    return 0;
}

/*****************************************************************************
 * Signal Handlers
 *****************************************************************************/
static void SigHup( int i_signal )
{
    need_reload = true;
}

static void SigHandler( int i_signal )
{
    die = true;
}

/*****************************************************************************
 * Entry point
 *****************************************************************************/
static void announce(void)
{
    uint8_t buffer[ANNOUNCE_SIZE];
    announce_set_version(buffer, ANNOUNCE_VERSION_V1);
    announce_set_priority(buffer, i_priority);
    announce_set_source(buffer, i_source);

    peer_foreach_output(&config.peers, peer)
        peer_send(peer, buffer, ANNOUNCE_SIZE);

}

static void notify(void)
{
    uint8_t buffer[ANNOUNCE_SIZE];
    announce_set_version(buffer, ANNOUNCE_VERSION);
    announce_set_priority(buffer, 0);
    announce_set_source(buffer, i_source);

    peer_foreach_output(&config.peers, peer)
        peer_send(peer, buffer, ANNOUNCE_SIZE);

}

static void usage(void)
{
    msg_Raw( NULL, "Usage: multilive "
             "[-i <RT priority>] "
             "[-l <syslogtag>] "
             "[-t <ttl>] "
             "[-y <priority>] "
             "[-p <period>] "
             "[-d <dead>] "
             "[-c config_file] "
             "@<src host> <dest host>" );
    msg_Raw( NULL, "    host format: [<connect addr>[:<connect port>]][@[<bind addr][:<bind port>]]" );
    msg_Raw( NULL, "    -y: priority of this instance (32 bits) [1]" );
    msg_Raw( NULL, "    -p: periodicity of announces in 27 MHz units [27000000/5]" );
    msg_Raw( NULL, "    -d: number of periods after which the master is dead [5]" );
    msg_Raw( NULL, "    -g: startup delay in 27Mhz units [0]" );
    msg_Raw( NULL, "    -c: use configuration file" );
    exit(EXIT_FAILURE);
}

static int nl_start(void)
{
    struct sockaddr_nl nl_addr;
    long i_flags;
    int i_nl_fd = -1;

    if ((i_nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1)
    {
        msg_Err( NULL, "socket(netlink) failed (%m)" );
        return -1;
    }

    memset(&nl_addr, 0, sizeof(nl_addr));
    nl_addr.nl_family = AF_NETLINK;
    nl_addr.nl_groups = RTMGRP_LINK;
    nl_addr.nl_pid = getpid();
    if (bind(i_nl_fd, (struct sockaddr *)&nl_addr, sizeof(nl_addr)) == -1)
    {
        msg_Err( NULL, "bind(netlink) failed (%m)" );
        close(i_nl_fd);
        return -1;
    }

    i_flags = fcntl(i_nl_fd, F_GETFL);
    fcntl(i_nl_fd, F_SETFL, i_flags | O_NONBLOCK);
    i_flags = fcntl(i_nl_fd, F_GETFD);
    fcntl(i_nl_fd, F_SETFD, i_flags | FD_CLOEXEC);

    return i_nl_fd;
}

static void link_cb(struct nlmsghdr *p)
{
    struct ifinfomsg *m = NLMSG_DATA(p);

    char buffer[IF_NAMESIZE];
    char *ifname = if_indextoname(m->ifi_index, buffer);

    bool up = m->ifi_flags & IFF_UP;

    if (ifname)
        msg_Dbg( NULL, "interface %i (%s) is %s",
                 m->ifi_index, ifname, up ? "up" : "down");
    else
        msg_Dbg( NULL, "interface %i is %s",
                 m->ifi_index, up ? "up" : "down");

    if (m->ifi_flags & IFF_UP) {
        peer_foreach(&config.peers, peer) {
            if (peer->ifindex <= 0 && peer_get_link(peer) == m->ifi_index) {
                peer->ifindex = m->ifi_index;
                peer_start(peer);
            }
        }
    } else {
        peer_foreach(&config.peers, peer) {
            if (peer->ifindex == m->ifi_index) {
                peer_close(peer);
            }
        }
    }
}

static void nl_read(void)
{
    for ( ; ; )
    {
        char p_buffer[NL_BUFFER];
        struct nlmsghdr *p;
        ssize_t i_read = recv(i_nl_fd, &p_buffer, sizeof(p_buffer), 0);

        if (i_read == -1) break;

        for (p = (struct nlmsghdr *)p_buffer; NLMSG_OK(p, i_read);
             p = NLMSG_NEXT(p, i_read))
        {
            if (p->nlmsg_type == NLMSG_ERROR)
            {
                struct nlmsgerr *m = NLMSG_DATA(p);
                msg_Err( NULL, "netlink error %d", m->error );
            }
            else if (p->nlmsg_type == RTM_GETLINK ||
                     p->nlmsg_type == RTM_NEWLINK ||
                     p->nlmsg_type == RTM_DELLINK)
                link_cb(p);
        }

        if (i_read)
        {
            msg_Err( NULL, "invalid netlink packet received %zu %hu %u",
                    i_read, p->nlmsg_type, p->nlmsg_len);
            break;
        }
    }
}

static void nl_get_links(void)
{
    struct {
        struct nlmsghdr  nh;
        struct ifinfomsg ifinfo;
    } req;

    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_MATCH;
    req.nh.nlmsg_type = RTM_GETLINK;
    req.nh.nlmsg_seq = 1;
    req.ifinfo.ifi_family = AF_UNSPEC;
    req.ifinfo.ifi_change = 0xffffffff; /* ??? */
    send(i_nl_fd, &req, req.nh.nlmsg_len, 0);
}


int main( int i_argc, char **pp_argv )
{
    int c;
    int i_rt_priority = -1;
    const char *psz_syslog_tag = NULL;
    uint64_t i_period = DEFAULT_PERIOD;
    unsigned int i_dead = DEFAULT_DEAD;
    uint64_t i_startup_delay = DEFAULT_STARTUP_DELAY;
    struct sigaction sa;
    sigset_t set;

    i_nl_fd = nl_start();
    if (i_nl_fd < 0)
    {
        msg_Err( NULL, "fail to create netlink socket" );
        exit(EXIT_FAILURE);
    }

    config_init(&config);

    while ( (c = getopt( i_argc, pp_argv, "s:i:l:t:y:p:d:g:c:h" )) != -1 )
    {
        switch ( c )
        {
        case 's':
            i_source = atoi(optarg);
            break;

        case 'i':
            i_rt_priority = strtol( optarg, NULL, 0 );
            break;

        case 'l':
            psz_syslog_tag = optarg;
            break;

        case 't':
            config.ttl = strtol( optarg, NULL, 0 );
            break;

        case 'y':
            i_priority = strtoul( optarg, NULL, 0 );
            break;

        case 'p':
            i_period = strtoull( optarg, NULL, 0 );
            break;

        case 'd':
            i_dead = strtoul( optarg, NULL, 0);
            break;

        case 'g':
            i_startup_delay = strtoull( optarg, NULL, 0 );
            break;

        case 'c':
            config_file = optarg;
            break;

        case 'h':
        default:
            usage();
            break;
        }
    }

    if ( psz_syslog_tag != NULL )
        msg_Openlog( psz_syslog_tag, LOG_NDELAY, LOG_USER );

    while (optind < i_argc) {
        const char *conf = pp_argv[optind++];

        struct peer *peer = config_find_peer(&config, conf);
        if (peer)
        {
            msg_Warn( NULL, "ignore duplicated peer" );
            continue;
        }

        peer = peer_create(NULL, conf, config.ttl);
        if (!peer)
            continue;

        peer->persistent = true;
        ulist_add(&config.peers, &peer->uchain);
    }

    if ( i_rt_priority > 0 )
    {
        struct sched_param param;
        int i_error;

        memset( &param, 0, sizeof(struct sched_param) );
        param.sched_priority = i_rt_priority;
        if ( (i_error = pthread_setschedparam( pthread_self(), SCHED_RR,
                                               &param )) )
        {
            msg_Warn( NULL, "couldn't set thread priority: %s",
                      strerror(i_error) );
        }
    }
    setvbuf(stdout, NULL, _IOLBF, 0);

    srand48( time(NULL) * getpid() );
    if (!i_source) {
        /* Choose a random source so that we recognize the packets we send. */
        i_source = lrand48();
        msg_Dbg( NULL, "random source ID: %"PRIx32, i_source );
    } else
        msg_Dbg( NULL, "source ID: %"PRIx32, i_source );

    /* Choose a random skew so that all instances do not expire exactly at
     * the same time. */
    uint64_t i_master_expiration_skew = lrand48();
    i_master_expiration_skew *= i_period * i_dead;
    i_master_expiration_skew /= UINT32_MAX;
    msg_Dbg( NULL, "expiration skew: %"PRId64, i_master_expiration_skew );

    uint64_t i_master_expiration = i_period * i_dead + wall_Date() +
                                   i_master_expiration_skew + i_startup_delay;
    Down();

    /* Set signal handlers */
    memset( &sa, 0, sizeof(struct sigaction) );
    sa.sa_handler = SigHup;
    sigfillset( &set );

    if ( sigaction( SIGHUP, &sa, NULL ) == -1 )
    {
        msg_Err( NULL, "couldn't set signal handler: %s", strerror(errno) );
        exit(EXIT_FAILURE);
    }

    memset( &sa, 0, sizeof(struct sigaction) );
    sa.sa_handler = SigHandler;
    sigfillset( &set );

    if ( sigaction( SIGTERM, &sa, NULL ) == -1 ||
         sigaction( SIGINT, &sa, NULL ) == -1 ||
         sigaction( SIGPIPE, &sa, NULL ) == -1 )
    {
        msg_Err( NULL, "couldn't set signal handler: %s", strerror(errno) );
        exit(EXIT_FAILURE);
    }

    uint64_t i_next_announce = UINT64_MAX;
    uint64_t next_notify = UINT64_MAX;
    while (!die)
    {
        if (need_reload)
            config_read(&config, config_file);
        need_reload = false;

        uint64_t i_current_date = wall_Date();
        bool has_peer = false;
        peer_foreach(&config.peers, peer)
            if (peer->fd != -1)
                has_peer = true;

        if (!has_peer)
        {
            if (i_next_announce != UINT64_MAX)
                Down();
            i_next_announce = UINT64_MAX;
            i_master_expiration = i_period * i_dead + i_current_date +
                i_master_expiration_skew + i_startup_delay;
        }
        else if ( i_next_announce == UINT64_MAX )
        {
            if ( i_master_expiration <= i_current_date )
            {
                Up();
                i_next_announce = i_current_date;
            }
        }

        if ( i_next_announce <= i_current_date )
        {
            announce();

            i_current_date = wall_Date();
            i_next_announce += i_period;
        }

        if ( i_next_announce == UINT64_MAX )
        {
            if ( next_notify < i_current_date || next_notify == UINT64_MAX)
            {
                notify();
                next_notify = i_current_date + notify_period;
            }
        }
        else
            next_notify = UINT64_MAX;

        /* next action date */
        uint64_t i_next_run = i_next_announce == UINT64_MAX ?
            i_master_expiration : i_next_announce;;
        if (next_notify < i_next_run)
            i_next_run = next_notify;

        /* add 1 ms for rounding */
        int i_timeout = ((i_next_run - i_current_date) * 1000 / CLOCK_FREQ) + 1;
        if ( i_timeout < 0 )
            i_timeout = 0;

        nfds_t nfds = 1;
        peer_foreach_input(&config.peers, peer) {
            if (peer->fd < 0)
                continue;
            nfds++;
        }
        struct pollfd fds[nfds];
        struct pollfd *current = &fds[0];

        current->fd = i_nl_fd;
        current->events = POLLIN | POLLERR | POLLHUP;
        current++;

        peer_foreach_input(&config.peers, peer) {
            if (peer->fd < 0)
                continue;

            current->fd = peer->fd;
            current->events = POLLIN | POLLERR | POLLHUP;
            current++;
        }

        if ( poll( fds, nfds, i_timeout ) < 0 )
        {
            int saved_errno = errno;
            if ( saved_errno == EINTR )
            {
                msg_Dbg( NULL, "poll interrupted" );
                continue;
            }
            msg_Warn( NULL, "couldn't poll(): %s", strerror(errno) );
            die = true;
            continue;
        }
        i_current_date = wall_Date();

        current = &fds[0];

        struct pollfd *pollfd = current++;
        if (pollfd->revents & POLLIN)
            nl_read();

        peer_foreach_input(&config.peers, peer) {
            if (peer->fd < 0)
                continue;

            pollfd = current++;

            if ( pollfd->revents & POLLIN )
            {
                uint32_t priority;
                uint32_t source;
                if (peer_recv( peer, &priority, &source))
                    continue;

                peer_notified(peer, source, i_current_date);

                if ( !priority )
                {
                }
                else if ( priority < i_priority )
                {
                    if ( i_current_date + i_master_expiration_skew <
                         i_master_expiration )
                    {
                        /* Do not take over immediately to avoid fighting with
                         * potential other idle nodes. */
                        i_master_expiration =
                            i_current_date + i_master_expiration_skew;
                    }
                }
                else
                {
                    if ( i_next_announce != UINT64_MAX )
                        Down();
                    i_next_announce = UINT64_MAX;
                    i_master_expiration = i_current_date + i_period * i_dead +
                        i_master_expiration_skew;
                }
            }
            else if ( (pollfd->revents & (POLLERR | POLLHUP)) )
            {
                msg_Err( NULL, "poll error\n" );
                exit(EXIT_FAILURE);
            }

            peer_expire(peer, i_current_date);
        }
    }

    config_clean(&config);

    if ( psz_syslog_tag != NULL )
        msg_Closelog();

    close(i_nl_fd);

    return EXIT_SUCCESS;
}
