/*****************************************************************************
 * reordertp.c: rebuild an RTP stream from several aggregated links
 *****************************************************************************
 * Copyright (C) 2009, 2011, 2014-2017 VideoLAN
 *
 * Authors: Christophe Massiot <massiot@via.ecp.fr>
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
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <poll.h>
#include <syslog.h>

#include <bitstream/ietf/rtp.h>

#include "util.h"

#define POW2_16 65536UL
#define POW2_32 4294967296ULL
#define DEFAULT_BUFFER_LENGTH 400 /* ms */

/* Maximum gap allowed between two CRs. */
#define DEFAULT_CR_MAX_GAP 300 /* ms */
#define DEFAULT_CR_MAX_JITTER 150 /* ms */
#define DEFAULT_CR_AVERAGE 500
#define CR_MAX_SPACE_PACKETS 10

#define DEFAULT_RETX_DELAY 200 /* ms */
#define MIN_RETX_DELAY 10 /* ms */
#define DEFAULT_MAX_RETX_BURST 15 /* packets */
#define RETX_REFRACTORY_TRIGGER 100 /* uncorrected errors */
#define RETX_REFRACTORY_PERIOD 15000 /* ms */
#define RETX_REFRACTORY_RESET 3000 /* ms */

/*****************************************************************************
 * Local declarations
 *****************************************************************************/
typedef struct block_t
{
    uint8_t *p_data;
    unsigned int i_size;
    uint64_t i_date;
    uint16_t i_seqnum;
    struct block_t *p_next, *p_prev;
} block_t;

typedef struct input_t
{
    int i_fd;
    bool b_tcp;
    bool b_multicast;
    block_t *p_block;
    sockaddr_t peer;
} input_t;

static size_t i_asked_payload_size = DEFAULT_PAYLOAD_SIZE;
static size_t i_rtp_header_size = RTP_HEADER_SIZE;

static int i_output_fd;
static input_t *p_inputs = NULL;
static int i_nb_inputs = 0;
static int b_udp = 0;
static int b_redundance = 0;

static block_t *p_first = NULL;
static block_t **pp_retx = NULL;
static block_t *p_last = NULL;
static int i_nb_retx = 0;

typedef struct input_clock_t
{
    /* Synchronization information */
    int64_t                  delta_cr;
    uint64_t                 cr_ref, wall_ref;
    uint64_t                 last_cr; /* reference to detect unexpected stream
                                       * discontinuities                     */
    int                      i_nb_space_packets;
} input_clock_t;

static input_clock_t input_clock;

static uint64_t i_last_timestamp = POW2_32; /* not 27 MHz, but RTP-native */
static uint64_t i_buffer_length = DEFAULT_BUFFER_LENGTH * 27000;
static uint64_t i_cr_max_gap = DEFAULT_CR_MAX_GAP * 27000;
static uint64_t i_cr_max_jitter = DEFAULT_CR_MAX_JITTER * 27000;
static int i_cr_average = DEFAULT_CR_AVERAGE;

static uint64_t i_retx_delay = DEFAULT_RETX_DELAY * 27000;
static int i_retx_fd = -1;
static unsigned int i_max_retx_burst = DEFAULT_MAX_RETX_BURST;
static int i_last_retx_input = 0;
static unsigned int i_retx_uncorrected_errors = 0;
static uint64_t i_retx_uncorrected_errors_expiration = UINT64_MAX;
static uint16_t i_last_output_seqnum = 0;
static uint64_t i_retx_refractory_end = 0;

static void usage(void)
{
    msg_Raw( NULL, "Usage: reordertp [-i <RT priority>] [-l <syslogtag>] [-t <ttl>] [-b <buffer length>] [-U] [-D] [-g <max gap>] [-j <max jitter>] [-r <# of clock ref>] [-n <max retx burst>] [-x <reorder/retx delay>] [-X <retx URL>] [-m <payload size>] [-R <RTP header>] <src host 1> ... [<src host N>] <dest host>" );
    msg_Raw( NULL, "    host format: [<connect addr>[:<connect port>]][@[<bind addr][:<bind port>]]" );
    msg_Raw( NULL, "    -U: strip RTP header" );
    msg_Raw( NULL, "    -D: input has redundant packets" );
    msg_Raw( NULL, "    -b: buffer length in ms [default 400]" );
    msg_Raw( NULL, "    -g: max gap between two clock references in ms [default 300]" );
    msg_Raw( NULL, "    -j: max jitter in ms [default 150]" );
    msg_Raw( NULL, "    -r: number of clock references for low pass filter [default 500]" );
    msg_Raw( NULL, "    -n: max number of retx requests [default 15]" );
    msg_Raw( NULL, "    -x: delay in ms after which retransmission requests are sent [default 200]" );
    msg_Raw( NULL, "    -X: retransmission service host:port[/tcp]" );
    msg_Raw( NULL, "    -m: size of the payload chunk, excluding optional RTP header (default 1316)" );
    msg_Raw( NULL, "    -R: size of the optional RTP header (default 12)" );
    exit(EXIT_FAILURE);
}

/*****************************************************************************
 * clock_Init
 *****************************************************************************/
void clock_Init(void)
{
    input_clock.last_cr = 0;
    input_clock.cr_ref = 0;
    input_clock.wall_ref = 0;
    input_clock.delta_cr = 0;
    input_clock.i_nb_space_packets = 0;
}

/*****************************************************************************
 * clock_ToWall
 *****************************************************************************/
uint64_t clock_ToWall( uint64_t i_clock )
{
    return input_clock.wall_ref + (i_clock + input_clock.delta_cr
                                    - input_clock.cr_ref);
}

/*****************************************************************************
 * clock_NewRef
 *****************************************************************************/
void clock_NewRef( uint64_t i_clock, uint64_t i_wall )
{
    uint64_t i_extrapoled_clock;
    int64_t i_clock_diff = i_clock - input_clock.last_cr;

    if ( i_clock_diff > (int64_t)i_cr_max_gap ||
         i_clock_diff < -(int64_t)i_cr_max_gap )
    {
        msg_Warn( NULL, "clock gap, unexpected stream discontinuity %lld",
                  i_clock_diff );
        clock_Init();
        input_clock.cr_ref = input_clock.last_cr = i_clock;
        input_clock.wall_ref = i_wall;
        return;
    }

    /* Smooth clock reference variations. */
    i_extrapoled_clock = input_clock.cr_ref
                          + i_wall - input_clock.wall_ref;
    i_clock_diff = i_extrapoled_clock - i_clock;

    int64_t i_jitter = i_clock_diff - input_clock.delta_cr;
    if ( i_jitter > (int64_t)i_cr_max_jitter ||
         i_jitter < -(int64_t)i_cr_max_jitter )
    {
        /* The packet must come from outer space. */
        input_clock.i_nb_space_packets++;
        if ( input_clock.i_nb_space_packets > CR_MAX_SPACE_PACKETS )
        {
            msg_Warn( NULL, "too much jitter %lld", i_jitter );
            clock_Init();
            input_clock.cr_ref = input_clock.last_cr = i_clock;
            input_clock.wall_ref = i_wall;
        }
        else
            msg_Dbg( NULL, "ignoring space packet jitter %lld", i_jitter );
        return;
    }
    input_clock.i_nb_space_packets = 0;
    input_clock.last_cr = i_clock;

    /* Bresenham algorithm to smooth variations. */
    /* Gives a lot of importance to the first samples, but we suppose the
     * buffer is *large*, and the most important is to avoid the delta_cr
     * to change too quickly, otherwise packets will be in wrong order. */
    input_clock.delta_cr = (input_clock.delta_cr * (i_cr_average - 1)
                             + i_clock_diff) / i_cr_average;
}

/*****************************************************************************
 * Retx handlers
 *****************************************************************************/
static void RetxPacketSent( block_t *p_block )
{
    int i;
    for ( i = 0; i < i_nb_retx; i++ )
        if ( pp_retx[i] == p_block )
            pp_retx[i] = NULL;

    uint16_t i_seqnum = p_block->i_seqnum;

    if ( i_retx_refractory_end )
    {
        if ( p_block->i_date > i_retx_refractory_end )
        {
            msg_Warn( NULL, "now reenabling retx" );
            i_retx_refractory_end = 0;
        }
    }
    else if ( i_seqnum != i_last_output_seqnum + 1 )
    {
        if ( ++i_retx_uncorrected_errors >= RETX_REFRACTORY_TRIGGER )
        {
            msg_Warn( NULL, "too many errors, disabling retx for a while" );
            i_retx_uncorrected_errors = 0;
            i_retx_refractory_end =
                p_block->i_date + RETX_REFRACTORY_PERIOD * 27000;
        }
        else
        {
            i_retx_uncorrected_errors_expiration =
                p_block->i_date + RETX_REFRACTORY_RESET * 27000;
        }
    }
    else if ( p_block->i_date > i_retx_uncorrected_errors_expiration )
    {
        i_retx_uncorrected_errors_expiration = UINT64_MAX;
        i_retx_uncorrected_errors = 0;
    }


    i_last_output_seqnum = i_seqnum;
}

static void RetxDereference( block_t *p_block )
{
    int i;
    for ( i = 0; i < i_nb_retx; i++ )
        if ( pp_retx[i] == p_block )
            pp_retx[i] = p_block->p_prev;

    /* Can't be the first block of the list */
    p_block->p_prev->p_next = p_block->p_next;
    if ( p_block->p_next != NULL )
        p_block->p_next->p_prev = p_block->p_prev;
    else
        p_last = p_block->p_prev;
}

static int RetxGetFd(sockaddr_t **pp_sockaddr)
{
    if ( i_retx_fd != -1 ) {
        *pp_sockaddr = NULL;
        return i_retx_fd;
    }

    int i_nb_tries = 0;
    while ( i_nb_tries < i_nb_inputs )
    {
        i_nb_tries++;
        i_last_retx_input++;
        i_last_retx_input %= i_nb_inputs;
        if ( p_inputs[i_last_retx_input].peer.so.sa_family != AF_UNSPEC &&
             !p_inputs[i_last_retx_input].b_multicast )
            break;
    }

    if ( i_nb_tries == i_nb_inputs + 1 )
        return -1;

    *pp_sockaddr = &p_inputs[i_last_retx_input].peer;
    return p_inputs[i_last_retx_input].i_fd;
}

static void RetxCheck( uint64_t i_current_date )
{
    int i;
    for ( i = 0; i < i_nb_retx; i++ )
    {
        for ( ; ; )
        {
            block_t *p_prev = pp_retx[i];
            block_t *p_current;

            if ( p_prev != NULL )
                p_current = p_prev->p_next;
            else
                p_current = p_first;

            if ( p_current == NULL ||
                 p_current->i_date > (i_current_date + (i + 1) * i_retx_delay) )
                break;

            pp_retx[i] = p_current;
            if ( p_prev == NULL )
                /* No past, nothing to do */
                continue;

            uint16_t i_prev_seqnum = p_prev->i_seqnum;
            uint16_t i_current_seqnum = p_current->i_seqnum;

            if ( i_current_seqnum == i_prev_seqnum )
            {
                if ( !b_redundance )
                    msg_Dbg( NULL, "duplicate RTP packet %hu",
                             i_current_seqnum );
                RetxDereference( p_current );
                free( p_current );
                continue;
            }

            if ( i_current_seqnum != (i_prev_seqnum + 1) % POW2_16 )
            {
                unsigned int i_nb_packets = (POW2_16 + i_current_seqnum -
                                            (i_prev_seqnum + 1)) % POW2_16;
                sockaddr_t *p_sockaddr;
                int i_fd;
                if ( !i_retx_refractory_end &&
                     i_nb_packets <= i_max_retx_burst &&
                     (i_fd = RetxGetFd(&p_sockaddr)) != -1 )
                {
                    uint8_t p_buffer[RETX_HEADER_SIZE];
                    msg_Dbg( NULL, "missing RTP packets %hu to %hu, retx started",
                             (i_prev_seqnum + 1) % POW2_16,
                             (i_prev_seqnum + i_nb_packets) % POW2_16 );
                    retx_init(p_buffer);
                    retx_set_seqnum(p_buffer, (i_prev_seqnum + 1) % POW2_16);
                    retx_set_num(p_buffer, i_nb_packets);
                    if ( p_sockaddr == NULL )
                        send( i_fd, p_buffer, RETX_HEADER_SIZE, 0 );
                    else
                        sendto( i_fd, p_buffer, RETX_HEADER_SIZE, 0,
                                &p_sockaddr->so, sizeof(sockaddr_t) );
                }
                else
                {
                    msg_Warn( NULL, "missing RTP packets %hu to %hu, no retx",
                             (i_prev_seqnum + 1) % POW2_16,
                             (i_prev_seqnum + i_nb_packets) % POW2_16 );
                }
            }
        }
    }
}

/*****************************************************************************
 * Packet handlers
 *****************************************************************************/
static void PacketSend(void)
{
    block_t *p_block = p_first;
    uint8_t *p_data, *p_end;

    p_first = p_block->p_next;
    if ( p_first == NULL )
        p_last = NULL;
    else
        p_first->p_prev = NULL;

    if ( b_udp )
        p_data = rtp_payload( p_block->p_data );
    else
        p_data = p_block->p_data;
    p_end = p_block->p_data + p_block->i_size;

    if ( send( i_output_fd, p_data, p_end - p_data, 0 ) < 0 )
    {
        if ( errno == EBADF || errno == ECONNRESET || errno == EPIPE )
        {
            msg_Err( NULL, "write error (%s)", strerror(errno) );
            exit(EXIT_FAILURE);
        }
        /* otherwise do not die because these errors can be transient */
    }

    RetxPacketSent( p_block );
    free( p_block );
}

static void BuildTimestamp( uint32_t i_timestamp )
{
    int64_t i_delta_timestamp;

    i_delta_timestamp = (POW2_32 * 3 / 2 + (int64_t)i_timestamp
                          - (i_last_timestamp % POW2_32))
                         % POW2_32 - POW2_32 / 2;
    i_last_timestamp += i_delta_timestamp;
}

static void PacketRecv( block_t *p_block, uint64_t i_date )
{
    uint64_t i_scaled_timestamp;

    if ( !rtp_check_hdr( p_block->p_data ) )
    {
        msg_Warn( NULL, "non-RTP packet received" );
        free( p_block );
        return;
    }

    BuildTimestamp( rtp_get_timestamp( p_block->p_data ) );

    switch ( rtp_get_type( p_block->p_data ) )
    {
    case RTP_TYPE_TS: /* 90 kHz */
        i_scaled_timestamp = i_last_timestamp * 300;
        break;
    default: /* assume milliseconds */
        i_scaled_timestamp = i_last_timestamp * 27000;
        break;
    }

    if ( rtp_check_marker( p_block->p_data ) )
    {
        i_date = 0;
        rtp_clear_marker( p_block->p_data );
    }

    if ( i_date )
        clock_NewRef( i_scaled_timestamp, i_date );

    p_block->i_date = clock_ToWall( i_scaled_timestamp ) + i_buffer_length;
    p_block->i_seqnum = rtp_get_seqnum( p_block->p_data );

    /* Insert the block at the correct position */
    if ( p_last == NULL )
    {
        p_first = p_last = p_block;
        p_block->p_prev = p_block->p_next = NULL;
    }
    else
    {
        block_t *p_prev = p_last;
        while ( p_prev != NULL && 
                (POW2_16 * 3 / 2 + (uint32_t)p_prev->i_seqnum -
                            (uint32_t)p_block->i_seqnum)
                             % POW2_16 > POW2_16 / 2 )
            p_prev = p_prev->p_prev;
        if ( p_prev == NULL )
        {
            p_block->p_next = p_first;
            p_first->p_prev = p_block;
            p_block->p_prev = NULL;
            p_first = p_block;
        }
        else
        {
            p_block->p_prev = p_prev;
            p_block->p_next = p_prev->p_next;
            p_prev->p_next = p_block;
            if ( p_block->p_next != NULL )
                p_block->p_next->p_prev = p_block;
            else
                p_last = p_block;
        }
    }
}

/*****************************************************************************
 * Entry point
 *****************************************************************************/
int main( int i_argc, char **pp_argv )
{
    int i, c;
    int i_priority = -1;
    const char *psz_syslog_tag = NULL;
    int i_ttl = 0;
    struct pollfd *pfd = NULL;
    int i_fd;
    bool b_tcp;
    bool b_multicast = false;

#define ADD_INPUT                                                           \
    p_inputs = realloc( p_inputs, ++i_nb_inputs * sizeof(input_t) );        \
    p_inputs[i_nb_inputs - 1].i_fd = i_fd;                                  \
    p_inputs[i_nb_inputs - 1].b_tcp = b_tcp;                                \
    p_inputs[i_nb_inputs - 1].b_multicast = b_multicast;                    \
    p_inputs[i_nb_inputs - 1].p_block = NULL;                               \
    p_inputs[i_nb_inputs - 1].peer.so.sa_family = AF_UNSPEC;                \
    pfd = realloc( pfd, i_nb_inputs * sizeof(struct pollfd) );              \
    pfd[i_nb_inputs - 1].fd = i_fd;                                         \
    pfd[i_nb_inputs - 1].events = POLLIN | POLLERR | POLLRDHUP | POLLHUP;

    while ( (c = getopt( i_argc, pp_argv, "i:l:t:b:g:j:r:n:x:X:UDm:R:h" )) != -1 )
    {
        switch ( c )
        {
        case 'i':
            i_priority = strtol( optarg, NULL, 0 );
            break;

        case 'l':
            psz_syslog_tag = optarg;
            break;

        case 't':
            i_ttl = strtol( optarg, NULL, 0 );
            break;

        case 'b':
            i_buffer_length = strtoll( optarg, NULL, 0 ) * 27000;
            break;

        case 'g':
            i_cr_max_gap = strtoll( optarg, NULL, 0 ) * 27000;
            break;

        case 'j':
            i_cr_max_jitter = strtoll( optarg, NULL, 0 ) * 27000;
            break;

        case 'r':
            i_cr_average = strtol( optarg, NULL, 0 );
            break;

        case 'n':
            i_max_retx_burst = strtoul( optarg, NULL, 0 );
            break;

        case 'x':
            i_retx_delay = strtoll( optarg, NULL, 0 ) * 27000;
            break;

        case 'X':
            i_retx_fd = i_fd = OpenSocket( optarg, 0, 0, 0, NULL, &b_tcp, NULL );
            if ( i_fd == -1 )
            {
                msg_Err( NULL, "unable to set up retx with %s\n", optarg );
                exit(EXIT_FAILURE);
            }

            ADD_INPUT
            break;

        case 'U':
            b_udp = 1;
            break;

        case 'D':
            b_redundance = 1;
            break;

        case 'm':
            i_asked_payload_size = strtol( optarg, NULL, 0 );
            break;

        case 'R':
            i_rtp_header_size = strtol( optarg, NULL, 0 );
            break;

        case 'h':
        default:
            usage();
            break;
        }
    }
    if ( optind >= i_argc - 1 )
        usage();

    if ( psz_syslog_tag != NULL )
        msg_Openlog( psz_syslog_tag, LOG_NDELAY, LOG_USER );

    while ( optind < i_argc - 1 )
    {
        struct opensocket_opt opt;
        memset(&opt, 0, sizeof(struct opensocket_opt));
        opt.pb_multicast = &b_multicast;

        i_fd = OpenSocket( pp_argv[optind], 0, DEFAULT_PORT, 0, NULL,
                           &b_tcp, &opt );
        if ( i_fd == -1 )
        {
            msg_Err( NULL, "unable to open input %s\n", pp_argv[optind] );
            exit(EXIT_FAILURE);
        }
        optind++;

        ADD_INPUT
    }
    msg_Dbg( NULL, "%d inputs", i_nb_inputs );

    i_nb_retx = i_retx_fd != -1 ? (i_buffer_length - MIN_RETX_DELAY) / i_retx_delay : 0;
    pp_retx = malloc( i_nb_retx * sizeof(block_t *) );
    for ( i = 0; i < i_nb_retx; i++ )
        pp_retx[i] = NULL;
    if ( i_retx_fd != -1 && i_nb_retx )
        msg_Dbg( NULL, "%d retx passes", i_nb_retx );

    i_output_fd = OpenSocket( pp_argv[optind], i_ttl, 0, DEFAULT_PORT, NULL,
                              NULL, NULL );
    if ( i_output_fd == -1 )
    {
        msg_Err( NULL, "unable to open output %s\n", pp_argv[optind] );
        exit(EXIT_FAILURE);
    }
    clock_Init();

    if ( i_priority > 0 )
    {
        struct sched_param param;
        int i_error;

        memset( &param, 0, sizeof(struct sched_param) );
        param.sched_priority = i_priority;
        if ( (i_error = pthread_setschedparam( pthread_self(), SCHED_RR,
                                               &param )) )
        {
            msg_Warn( NULL, "couldn't set thread priority: %s",
                      strerror(i_error) );
        }
    }

    for ( ; ; )
    {
        int i_timeout = -1;
        uint64_t i_current_date;

        while ( p_first != NULL
                 && p_first->i_date <= (i_current_date = wall_Date()) + 26999 )
            PacketSend();

        i_current_date = wall_Date();
        RetxCheck( i_current_date );
        i_current_date = wall_Date();

        if ( p_first != NULL )
            i_timeout = (p_first->i_date - i_current_date) / 27000;

        if ( poll( pfd, i_nb_inputs, i_timeout ) < 0 )
        {
            int saved_errno = errno;
            msg_Warn( NULL, "couldn't poll(): %s", strerror(errno) );
            if ( saved_errno == EINTR ) continue;
            exit(EXIT_FAILURE);
        }
        i_current_date = wall_Date();

        for ( i = 0; i < i_nb_inputs; i++ )
        {
            input_t *p_input = &p_inputs[i];

            if ( pfd[i].revents & POLLIN )
            {
                ssize_t i_size = i_asked_payload_size + i_rtp_header_size;
                uint8_t *p_buffer;

                if ( p_input->p_block == NULL )
                {
                    p_input->p_block = malloc( sizeof(block_t) + i_size );
                    p_buffer = p_input->p_block->p_data =
                        (uint8_t *)p_input->p_block + sizeof(block_t);
                    p_input->p_block->i_size = 0;
                }
                else
                {
                    p_buffer = p_input->p_block->p_data +
                               p_input->p_block->i_size;
                    i_size -= p_input->p_block->i_size;
                }

                if ( p_input->b_tcp )
                    i_size = read( p_input->i_fd, p_buffer, i_size );
                else
                {
                    socklen_t len = sizeof(sockaddr_t);
                    i_size = recvfrom( p_input->i_fd, p_buffer, i_size, 0,
                                       &p_input->peer.so, &len );
                }
                if ( i_size < 0 && errno != EAGAIN && errno != EINTR &&
                     errno != ECONNREFUSED )
                {
                    msg_Err( NULL, "unrecoverable read error, dying (%s)",
                             strerror(errno) );
                    exit(EXIT_FAILURE);
                }
                if ( i_size <= 0 ) continue;

                p_input->p_block->i_size += i_size;

                if ( p_input->b_tcp &&
                     p_input->p_block->i_size !=
                         i_asked_payload_size + i_rtp_header_size )
                    continue;

                if ( i_retx_fd == -1 || i )
                    PacketRecv( p_input->p_block, i_current_date );
                else
                    PacketRecv( p_input->p_block, 0 );

                p_input->p_block = NULL;
            }
            else if ( pfd[i].revents & (POLLERR | POLLRDHUP | POLLHUP) )
            {
                msg_Err( NULL, "poll error on input %d" );
                exit(EXIT_FAILURE);
            }

        }
    }

    if ( psz_syslog_tag != NULL )
        msg_Closelog();

    return EXIT_SUCCESS;
}

