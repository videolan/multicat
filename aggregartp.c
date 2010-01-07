/*****************************************************************************
 * aggregartp.c: split an RTP stream for several contribution links
 *****************************************************************************
 * Copyright (C) 2009 VideoLAN
 * $Id: aggregartp.c 48 2007-11-30 14:08:21Z cmassiot $
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

#include "util.h"

#define MAX_OUTPUTS 4
#define DEFAULT_MTU 1500

/*****************************************************************************
 * Local declarations
 *****************************************************************************/
typedef struct output_t
{
    int i_fd;
    unsigned int i_weight;

    unsigned int i_weighted_size, i_remainder;
} output_t;

static int i_input_fd;
static output_t p_outputs[MAX_OUTPUTS];
static unsigned int i_max_weight = 0;
static bool b_overwrite_timestamps = false;
static bool b_overwrite_ssrc = false;
static in_addr_t i_ssrc = 0;
static uint16_t i_rtp_cc = 0;

static void usage(void)
{
    msg_Raw( NULL, "Usage: aggregartp [-i <RT priority>] [-t <ttl>] [-w] [-s <SSRC IP>] [-U] [-m <mtu>] @<src host> <dest host 1>[,<weight 1>] ... [<dest host N>,<weight N>]" );
    msg_Raw( NULL, "    host format: [<connect addr>[:<connect port>]][@[<bind addr][:<bind port>]]" );
    msg_Raw( NULL, "    -w: overwrite RTP timestamps" );
    msg_Raw( NULL, "    -S: overwrite RTP SSRC" );
    msg_Raw( NULL, "    -U: prepend RTP header" );
    exit(EXIT_FAILURE);
}

/*****************************************************************************
 * NextOutput: pick the output for the next packet
 *****************************************************************************/
static output_t *NextOutput(void)
{
    unsigned int i_min_size = p_outputs[0].i_weighted_size;
    int i, i_output = 0;

    for ( i = 1; i < MAX_OUTPUTS && p_outputs[i].i_weight; i++ )
    {
        if ( p_outputs[i].i_weighted_size < i_min_size )
        {
            i_min_size = p_outputs[i].i_weighted_size;
            i_output = i;
        }
    }

    for ( i = 0; i < MAX_OUTPUTS && p_outputs[i].i_weight; i++ )
        p_outputs[i].i_weighted_size -= i_min_size;

    return &p_outputs[i_output];
}

/*****************************************************************************
 * Entry point
 *****************************************************************************/
int main( int i_argc, char **pp_argv )
{
    int i, c;
    int i_priority = -1;
    int i_ttl = 0;
    bool b_udp = false;
    int i_mtu = DEFAULT_MTU;
    uint8_t *p_buffer, *p_read_buffer;

    while ( (c = getopt( i_argc, pp_argv, "i:t:wo:Um:h" )) != -1 )
    {
        switch ( c )
        {
        case 'i':
            i_priority = strtol( optarg, NULL, 0 );
            break;

        case 't':
            i_ttl = strtol( optarg, NULL, 0 );
            break;

        case 'w':
            b_overwrite_timestamps = true;
            break;

        case 'o':
        {
            struct in_addr maddr;
            if ( !inet_aton( optarg, &maddr ) )
                usage();
            i_ssrc = maddr.s_addr;
            b_overwrite_ssrc = true;
            break;
        }

        case 'U':
            b_udp = true;
            break;

        case 'm':
            i_mtu = strtol( optarg, NULL, 0 );
            break;

        case 'h':
        default:
            usage();
            break;
        }
    }
    if ( optind >= i_argc - 1 )
        usage();

    i_input_fd = OpenSocket( pp_argv[optind], 0, NULL );
    optind++;

    i = 0;
    while ( optind < i_argc && i < MAX_OUTPUTS )
    {
        p_outputs[i].i_fd = OpenSocket( pp_argv[optind++], i_ttl,
                                        &p_outputs[i].i_weight );
        p_outputs[i].i_weighted_size = p_outputs[i].i_remainder = 0;
        i_max_weight += p_outputs[i].i_weight;
        i++;
    }
    if ( optind < i_argc )
    {
        msg_Err( NULL, "max number of outputs: %d (recompile)", MAX_OUTPUTS );
        exit(EXIT_FAILURE);
    }
    msg_Dbg( NULL, "%d outputs weight %u", i, i_max_weight );
    for ( ; i < MAX_OUTPUTS; i++ )
        p_outputs[i].i_weight = 0;

    if ( b_udp )
    {
        p_buffer = malloc( i_mtu + RTP_HEADER_SIZE );
        p_read_buffer = p_buffer + RTP_HEADER_SIZE;
    }
    else
        p_buffer = p_read_buffer = malloc( i_mtu );

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
        ssize_t i_size = read( i_input_fd, p_read_buffer, i_mtu );
        output_t *p_output;

        if ( i_size < 0 && errno != EAGAIN && errno != EINTR )
        {
            msg_Err( NULL, "unrecoverable read error, dying (%s)",
                     strerror(errno) );
            exit(EXIT_FAILURE);
        }
        if ( i_size <= 0 ) continue;

        if ( b_udp )
        {
            rtp_SetHdr( p_buffer, i_rtp_cc );
            i_rtp_cc++;
            i_size += RTP_HEADER_SIZE;
            rtp_SetSSRC( p_buffer, (uint8_t *)&i_ssrc );
            /* this isn't RFC-compliant, but we assume that at the other end,
             * the RTP header will be stripped */
            rtp_SetTimestamp( p_buffer, wall_Date() / 300 );
        }
        else
        {
            if ( b_overwrite_ssrc )
                rtp_SetSSRC( p_buffer, (uint8_t *)&i_ssrc );
            if ( b_overwrite_timestamps )
                rtp_SetTimestamp( p_buffer, wall_Date() / 300 );
        }

        p_output = NextOutput();
        if ( write( p_output->i_fd, p_buffer, i_size ) < 0 )
            msg_Warn( NULL, "write error (%s)", strerror(errno) );

        p_output->i_weighted_size += (i_size + p_output->i_remainder)
                                       / p_output->i_weight;
        p_output->i_remainder = (i_size + p_output->i_remainder)
                                       % p_output->i_weight;
    }

    return EXIT_SUCCESS;
}

