/*****************************************************************************
 * smooths.c: smooth a transport stream
 *****************************************************************************
 * Copyright (C) 2023 VideoLAN
 *
 * Authors: Christophe Massiot <cmassiot@upipe.org>
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <sys/uio.h>
#include <limits.h>
#include <ctype.h>
#include <time.h>

#ifndef POLLRDHUP
#   define POLLRDHUP 0
#endif

#include <bitstream/ietf/rtp.h>
#include <bitstream/mpeg/ts.h>
#include <bitstream/mpeg/pes.h>

#include "util.h"
#include "ulist.h"

#define POLL_TIMEOUT 0 /* non-blocking mode */
#define DEFAULT_LATENCY (CLOCK_FREQ / 5)
#define WARN_JITTER (CLOCK_FREQ / 1000)
#define PACKET_SIZE 1328

/*****************************************************************************
 * Local declarations
 *****************************************************************************/
struct packet {
    struct uchain uchain;
    uint8_t p_buffer[PACKET_SIZE];
};

UBASE_FROM_TO(packet, uchain, uchain, uchain)

struct output {
    struct uchain uchain;
    int i_fd;
    char *psz_uri;
    bool b_raw_packets;
    bool b_udp;
    bool b_found;
    struct udprawpkt pktheader;
};

UBASE_FROM_TO(output, uchain, uchain, uchain)

static struct uchain output_list;
static int i_input_fd;

static volatile sig_atomic_t b_die = 0, b_error = 0, b_reload = 1;

static void usage(void)
{
    msg_Raw( NULL, "Usage: smooths [-i <RT priority>] [-l <syslogtag>] [-L <latency>] [-F] -c <conf file> <input item>" );
    msg_Raw( NULL, "    -L: latency in 27 MHz units" );
    msg_Raw( NULL, "    -F: force an active loop instead of sleeping" );
    msg_Raw( NULL, "    -c: path to configuration file containing one line per output item" );
    msg_Raw( NULL, "    item format: [<connect addr>[:<connect port>]][@[<bind addr][:<bind port>]]" );
    exit(EXIT_FAILURE);
}

/*****************************************************************************
 * udp_*: UDP socket handlers
 *****************************************************************************/
static ssize_t udp_Read( void *p_buf, size_t i_len )
{
    ssize_t i_ret;

    if ( (i_ret = recv( i_input_fd, p_buf, i_len, MSG_DONTWAIT )) < 0 &&
         errno != EAGAIN && errno != EWOULDBLOCK )
    {
        msg_Err( NULL, "recv error (%s)", strerror(errno) );
        b_die = b_error = 1;
        return 0;
    }

    return i_ret > 0 ? i_ret : 0;
}

static void udp_ExitRead(void)
{
    close( i_input_fd );
}

static int udp_InitRead( const char *psz_arg )
{
    if ( (i_input_fd = OpenSocket( psz_arg, 0, DEFAULT_PORT, 0,
                                   NULL, NULL, NULL )) < 0 )
        return -1;

    return 0;
}

static ssize_t raw_Write( struct output *p_output,
                          const void *p_buf, size_t i_len )
{
#ifndef __APPLE__
    ssize_t i_ret;
    struct iovec iov[2];

    #if defined(__FreeBSD__)
    p_output->pktheader.udph.uh_ulen
    #else
    p_output->pktheader.udph.len
    #endif
    = htons(sizeof(struct udphdr) + i_len);

    #if defined(__FreeBSD__)
    p_output->pktheader.iph.ip_len = htons(sizeof(struct udprawpkt) + i_len);
    #endif

    iov[0].iov_base = &p_output->pktheader;
    iov[0].iov_len = sizeof(struct udprawpkt);

    iov[1].iov_base = (void *) p_buf;
    iov[1].iov_len = i_len;

    if ( (i_ret = writev( p_output->i_fd, iov, 2 )) < 0 )
    {
        if ( errno == EBADF || errno == ECONNRESET || errno == EPIPE )
        {
            msg_Err( NULL, "write error (%s) on output %s", strerror(errno),
                     p_output->psz_uri );
            b_die = b_error = 1;
        }
        /* otherwise do not set b_die because these errors can be transient */
        return 0;
    }

    return i_ret;
#else
    return -1;
#endif
}

static ssize_t udp_Write( struct output *p_output,
                          const void *p_buf, size_t i_len )
{
    if ( p_output->b_udp )
    {
        p_buf += RTP_HEADER_SIZE;
        i_len -= RTP_HEADER_SIZE;
    }

    if ( p_output->b_raw_packets )
        return raw_Write( p_output, p_buf, i_len );

    ssize_t i_ret;
    if ( (i_ret = send( p_output->i_fd, p_buf, i_len, 0 )) < 0 )
    {
        if ( errno == EBADF || errno == ECONNRESET || errno == EPIPE )
        {
            msg_Err( NULL, "write error (%s) on output %s", strerror(errno),
                     p_output->psz_uri );
            b_die = b_error = 1;
        }
        /* otherwise do not set b_die because these errors can be transient */
        return 0;
    }

    return i_ret;
}

static void udp_ExitWrite( struct output *p_output )
{
    msg_Info( NULL, "closing %s", p_output->psz_uri );
    close( p_output->i_fd );
    free( p_output->psz_uri );
    free( p_output );
}

static struct output *udp_InitWrite( const char *psz_arg )
{
    struct output *p_output = malloc(sizeof(struct output));
    struct opensocket_opt opt;

    msg_Info( NULL, "opening %s", psz_arg );
    memset(&opt, 0, sizeof(struct opensocket_opt));
    opt.p_raw_pktheader = &p_output->pktheader;
    opt.pb_raw_packets = &p_output->b_raw_packets;
    opt.pb_udp = &p_output->b_udp;
    if ( (p_output->i_fd = OpenSocket( psz_arg, 0, 0, DEFAULT_PORT,
                                       NULL, NULL, &opt )) > 0 )
    {
        p_output->psz_uri = strdup(psz_arg);
        return p_output;
    }
    free(p_output);
    return NULL;
}

/*****************************************************************************
 * config_*: configuration file related functions
 *****************************************************************************/
static void config_ReadFile( const char *psz_conf_file )
{
    FILE *p_file;
    char psz_line[2048];

    if ( (p_file = fopen( psz_conf_file, "r" )) == NULL )
    {
        msg_Err( NULL, "can't fopen config file %s", psz_conf_file );
        return;
    }

    while ( fgets( psz_line, sizeof(psz_line), p_file ) != NULL )
    {
        struct uchain *p_uchain;
        char *psz_parser;

        psz_parser = strpbrk( psz_line, " #\n" );
        if ( psz_parser != NULL )
            *psz_parser-- = '\0';
        while ( psz_parser >= psz_line && isblank( *psz_parser ) )
            *psz_parser-- = '\0';
        if ( psz_line[0] == '\0' )
            continue;

        /* Find out if we already have this output */
        ulist_foreach (&output_list, p_uchain)
        {
            struct output *p_output = output_from_uchain(p_uchain);
            if (!strcmp(p_output->psz_uri, psz_line))
            {
                p_output->b_found = true;
                break;
            }
        }
        if ( p_uchain != &output_list )
            continue;

        /* Not found, open it */
        struct output *p_output = udp_InitWrite( psz_line );
        if ( p_output == NULL )
        {
            msg_Warn( NULL, "couldn't parse %s", psz_line );
            continue;
        }
        p_output->b_found = true;
        ulist_add(&output_list, output_to_uchain(p_output));
    }

    fclose( p_file );

    /* Now close outputs that were not in the file, and reset b_found flag */
    struct uchain *p_uchain, *p_tmp;
    ulist_delete_foreach (&output_list, p_uchain, p_tmp)
    {
        struct output *p_output = output_from_uchain(p_uchain);
        if (!p_output->b_found)
        {
            ulist_delete(p_uchain);
            udp_ExitWrite(p_output);
        }
        else
            p_output->b_found = false;
    }
}

static void config_Free(void)
{
    struct uchain *p_uchain, *p_tmp;
    ulist_delete_foreach (&output_list, p_uchain, p_tmp)
    {
        udp_ExitWrite(output_from_uchain(p_uchain));
    }
}

/*****************************************************************************
 * CompareSequences: Compare the sequence numbers from 2 RTP packets
 *****************************************************************************/
static int CompareSequences( struct uchain *p_uchain1,
                             struct uchain *p_uchain2 )
{
    struct packet *p_packet1 = packet_from_uchain(p_uchain1);
    struct packet *p_packet2 = packet_from_uchain(p_uchain2);
    uint16_t i_seqnum1 = rtp_get_seqnum(p_packet1->p_buffer);
    uint16_t i_seqnum2 = rtp_get_seqnum(p_packet2->p_buffer);

    int i_diff = i_seqnum1 - i_seqnum2;
    if (i_diff > 0)
        return (i_diff < 0x8000) ? i_diff : -i_diff;
    else if (i_diff < 0)
        return (i_diff > -0x8000) ? i_diff : -i_diff;
    else
        return 0;
}

/*****************************************************************************
 * Signal Handler
 *****************************************************************************/
static void SigHandler( int i_signal )
{
    if ( i_signal != SIGHUP )
        b_die = b_error = 1;
    else
        b_reload = 1;
}

/*****************************************************************************
 * Entry point
 *****************************************************************************/
int main( int i_argc, char **pp_argv )
{
    int i_priority = -1;
    const char *psz_syslog_tag = NULL;
    uint64_t i_latency = DEFAULT_LATENCY;
    const char *psz_conf_file = NULL;
    bool b_sleep = true;
    int c;
    struct sigaction sa;
    sigset_t set;
    struct uchain packet_list;
    struct packet *p_packet;
    uint64_t i_next_stc = UINT64_MAX;

    /* Parse options */
    while ( (c = getopt( i_argc, pp_argv, "i:l:L:c:Fh" )) != -1 )
    {
        switch ( c )
        {
        case 'i':
            i_priority = strtol( optarg, NULL, 0 );
            break;

        case 'l':
            psz_syslog_tag = optarg;
            break;

        case 'L':
            i_latency = strtol( optarg, NULL, 0 );
            break;

        case 'c':
            psz_conf_file = optarg;
            break;

        case 'F':
            b_sleep = false;
            break;

        case 'h':
        default:
            usage();
            break;
        }
    }
    if ( optind >= i_argc || psz_conf_file == NULL )
        usage();

    if ( psz_syslog_tag != NULL )
        msg_Openlog( psz_syslog_tag, LOG_NDELAY, LOG_USER );

    /* Open sockets */
    if ( udp_InitRead( pp_argv[optind] ) < 0 )
    {
        msg_Err( NULL, "input not found, exiting" );
        exit(EXIT_FAILURE);
    }
    optind++;

    ulist_init(&output_list);

    /* Real-time priority */
    if ( i_priority > 0 )
    {
        struct sched_param param;
        int i_error;

        memset( &param, 0, sizeof(struct sched_param) );
        param.sched_priority = i_priority;
        if ( (i_error = pthread_setschedparam( pthread_self(), SCHED_FIFO,
                                               &param )) )
        {
            msg_Warn( NULL, "couldn't set thread priority: %s",
                      strerror(i_error) );
        }
    }

    /* Set signal handlers */
    memset( &sa, 0, sizeof(struct sigaction) );
    sa.sa_handler = SigHandler;
    sigfillset( &set );

    if ( sigaction( SIGTERM, &sa, NULL ) == -1 ||
         sigaction( SIGHUP, &sa, NULL ) == -1 ||
         sigaction( SIGINT, &sa, NULL ) == -1 ||
         sigaction( SIGPIPE, &sa, NULL ) == -1 )
    {
        msg_Err( NULL, "couldn't set signal handler: %s", strerror(errno) );
        exit(EXIT_FAILURE);
    }

    /* Main loop */
    ulist_init(&packet_list);
    p_packet = malloc( sizeof(struct packet) );
    uchain_init(packet_to_uchain(p_packet));
    while ( !b_die )
    {
        if ( b_reload )
        {
            config_ReadFile( psz_conf_file );
            b_reload = 0;
        }

        uint64_t i_stc = wall_Date();

        if ( i_next_stc <= i_stc )
        {
            /* Output packet */
            struct uchain *p_uchain;
            struct packet *p_current = packet_from_uchain(ulist_pop(&packet_list));
            ulist_foreach (&output_list, p_uchain)
            {
                struct output *output = output_from_uchain(p_uchain);
                udp_Write( output, p_current->p_buffer, PACKET_SIZE );
            }

            if ( i_next_stc <= i_stc - WARN_JITTER )
            {
                msg_Warn( NULL, "CR was missed by %"PRIu64" us",
                          (i_stc - i_next_stc) / 27 );
            }

            /* Now calculate the date of the next packet */
            if ( ulist_empty(&packet_list) )
            {
                i_next_stc = UINT64_MAX;
            }
            else
            {
                uint32_t i_current_timestamp =
                    rtp_get_timestamp( p_current->p_buffer );
                struct packet *p_next =
                    packet_from_uchain(ulist_peek(&packet_list));
                uint32_t i_next_timestamp =
                    rtp_get_timestamp( p_next->p_buffer );
                uint64_t i_diff =
                    ((UINT32_MAX + 1 + (uint64_t)i_next_timestamp -
                      i_current_timestamp) & UINT32_MAX) * 300;

                if ( i_diff > i_latency )
                {
                    i_next_stc += i_latency;
                    msg_Warn( NULL, "resetting CR due to too long delay (%"PRIu64" ms)",
                              i_diff * 1000 / CLOCK_FREQ );
                }
                else
                {
                    i_next_stc += i_diff;
                }

                free(p_current);
            }

            /* Check if there is not another packet to send */
            continue;
        }

        /* Read and queue */
        ssize_t i_read_size = udp_Read( p_packet->p_buffer, PACKET_SIZE );
        if ( i_read_size > 0 )
        {
            if ( !rtp_check_hdr( p_packet->p_buffer ) )
            {
                msg_Warn( NULL, "invalid RTP packet received" );
                continue;
            }

            /* Reorder packet if needed */
            ulist_bubble_reverse(&packet_list, packet_to_uchain(p_packet),
                                 CompareSequences);

            if ( i_next_stc == UINT64_MAX )
            {
                i_next_stc = i_stc + i_latency;
                msg_Warn( NULL, "resetting CR due to empty buffer" );
            }

            p_packet = malloc( sizeof(struct packet) );
            uchain_init(packet_to_uchain(p_packet));
            continue;
        }

        if ( b_sleep )
        {
            if ( i_next_stc != UINT64_MAX )
                wall_Sleep(i_next_stc - i_stc);
            else
                wall_Sleep(WARN_JITTER);
        }
    }

    free(p_packet);
    struct uchain *p_uchain, *p_tmp;
    ulist_delete_foreach (&packet_list, p_uchain, p_tmp)
    {
        free(packet_from_uchain(p_uchain));
    }

    udp_ExitRead();
    config_Free();

    if ( psz_syslog_tag != NULL )
        msg_Closelog();

    return b_error ? EXIT_FAILURE : EXIT_SUCCESS;
}
