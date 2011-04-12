/*****************************************************************************
 * multicat.c: netcat-equivalent for multicast
 *****************************************************************************
 * Copyright (C) 2009 VideoLAN
 * $Id: multicat.c 48 2007-11-30 14:08:21Z cmassiot $
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
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "util.h"

#define RTP_HEADER_MAX_SIZE (RTP_HEADER_SIZE + 15 * 4)
#define RTP_TS_TYPE 33

/*****************************************************************************
 * Local declarations
 *****************************************************************************/
static int i_input_fd, i_output_fd;
FILE *p_input_aux, *p_output_aux;
static uint16_t i_pcr_pid = 0;
static bool b_overwrite_ssrc = false;
static in_addr_t i_ssrc = 0;
static bool b_input_udp = false, b_output_udp = false;
static size_t i_asked_payload_size = DEFAULT_PAYLOAD_SIZE;

static volatile sig_atomic_t b_die = 0;
static uint16_t i_rtp_cc;
static uint64_t i_stc = 0; /* system time clock, used for date calculations */
static uint64_t i_pcr = 0, i_pcr_stc = 0; /* for RTP/TS output */
void (*pf_Skip)( size_t i_len, int i_nb_chunks );
ssize_t (*pf_Read)( void *p_buf, size_t i_len );
ssize_t (*pf_Write)( const void *p_buf, size_t i_len );

static void usage(void)
{
    msg_Raw( NULL, "Usage: multicat [-i <RT priority>] [-t <ttl>] [-p <PCR PID>] [-s <chunks>] [-n <chunks>] [-d <time>] [-a] [-S <SSRC IP>] [-u] [-U] [-m <payload size>] <input item> <output item>" );
    msg_Raw( NULL, "    item format: <file path | device path | FIFO path | network host>" );
    msg_Raw( NULL, "    host format: [<connect addr>[:<connect port>]][@[<bind addr][:<bind port>]]" );
    msg_Raw( NULL, "    -p: overwrite or create RTP timestamps using PCR PID (MPEG-2/TS)" );
    msg_Raw( NULL, "    -s: skip the first N chunks of payload" );
    msg_Raw( NULL, "    -n: exit after playing N chunks of payload" );
    msg_Raw( NULL, "    -d: exit after definite time (in 27 MHz units)" );
    msg_Raw( NULL, "    -a: append to existing destination file (risky)" );
    msg_Raw( NULL, "    -S: overwrite or create RTP SSRC" );
    msg_Raw( NULL, "    -u: source has no RTP header" );
    msg_Raw( NULL, "    -U: destination has no RTP header" );
    msg_Raw( NULL, "    -m: size of the payload chunk, excluding optional RTP header (default 1316)" );
    exit(EXIT_FAILURE);
}

/*****************************************************************************
 * Signal Handler
 *****************************************************************************/
static void SigHandler( int i_signal )
{
    b_die = 1;
}

/*****************************************************************************
 * udp_*: UDP socket handlers
 *****************************************************************************/
static int i_udp_nb_skips = 0;

static void udp_Skip( size_t i_len, int i_nb_chunks )
{
    i_udp_nb_skips = i_nb_chunks;
}

static ssize_t udp_Read( void *p_buf, size_t i_len )
{
    ssize_t i_ret;
    if ( (i_ret = recv( i_input_fd, p_buf, i_len, 0 )) < 0 )
    {
        msg_Err( NULL, "recv error (%s)", strerror(errno) );
        b_die = 1;
        return 0;
    }

    i_stc = wall_Date();
    if ( i_udp_nb_skips )
    {
        i_udp_nb_skips--;
        return 0;
    }
    return i_ret;
}

static ssize_t udp_Write( const void *p_buf, size_t i_len )
{
    size_t i_ret;
    if ( (i_ret = send( i_output_fd, p_buf, i_len, 0 )) < 0 )
        msg_Err( NULL, "write error (%s)", strerror(errno) );
    return i_ret;
}

/*****************************************************************************
 * stream_*: FIFO and character device handlers
 *****************************************************************************/
static int i_stream_nb_skips = 0;

static void stream_Skip( size_t i_len, int i_nb_chunks )
{
    i_stream_nb_skips = i_nb_chunks;
}

static ssize_t stream_Read( void *p_buf, size_t i_len )
{
    ssize_t i_ret;

    if ( (i_ret = read( i_input_fd, p_buf, i_len )) < 0 )
    {
        msg_Err( NULL, "read error (%s)", strerror(errno) );
        b_die = 1;
        return 0;
    }

    i_stc = wall_Date();
    if ( i_stream_nb_skips )
    {
        i_stream_nb_skips--;
        return 0;
    }
    return i_ret;
}

static ssize_t stream_Write( const void *p_buf, size_t i_len )
{
    size_t i_ret;
    if ( (i_ret = write( i_output_fd, p_buf, i_len )) < 0 )
        msg_Err( NULL, "write error (%s)", strerror(errno) );
    return i_ret;
}

/*****************************************************************************
 * file_*: handler for the auxiliary file format
 *****************************************************************************/
static void file_Skip( size_t i_len, int i_nb_chunks )
{
    lseek( i_input_fd, (off_t)i_len * (off_t)i_nb_chunks, SEEK_SET );
    fseeko( p_input_aux, 8 * (off_t)i_nb_chunks, SEEK_SET );
}

static ssize_t file_Read( void *p_buf, size_t i_len )
{
    /* for correct throughput without rounding approximations */
    static uint64_t i_file_first_stc = 0, i_file_first_wall = 0;

    uint8_t p_aux[8];
    uint64_t i_wall;
    ssize_t i_ret;

    if ( (i_ret = read( i_input_fd, p_buf, i_len )) < 0 )
    {
        msg_Err( NULL, "read error (%s)", strerror(errno) );
        b_die = 1;
        return 0;
    }
    if ( i_ret == 0 )
    {
        msg_Dbg( NULL, "end of file reached" );
        b_die = 1;
        return 0;
    }

    if ( fread( p_aux, 8, 1, p_input_aux ) != 1 )
    {
        msg_Warn( NULL, "premature end of aux file reached" );
        b_die = 1;
        return 0;
    }
    i_stc = ((uint64_t)p_aux[0] << 56)
            | ((uint64_t)p_aux[1] << 48)
            | ((uint64_t)p_aux[2] << 40)
            | ((uint64_t)p_aux[3] << 32)
            | ((uint64_t)p_aux[4] << 24)
            | ((uint64_t)p_aux[5] << 16)
            | ((uint64_t)p_aux[6] << 8)
            | ((uint64_t)p_aux[7] << 0);
    i_wall = wall_Date();

    if ( !i_file_first_wall )
    {
        i_file_first_wall = i_wall;
        i_file_first_stc = i_stc;
    }

    if ( (i_stc - i_file_first_stc) > (i_wall - i_file_first_wall) )
        wall_Sleep( (i_stc - i_file_first_stc) - (i_wall - i_file_first_wall) );
    return i_ret;
}

static ssize_t file_Write( const void *p_buf, size_t i_len )
{
    uint8_t p_aux[8];
    ssize_t i_ret;

    if ( (i_ret = write( i_output_fd, p_buf, i_len )) < 0 )
    {
        msg_Err( NULL, "couldn't write to file" );
        return i_ret;
    }

    p_aux[0] = i_stc >> 56;
    p_aux[1] = (i_stc >> 48) & 0xff;
    p_aux[2] = (i_stc >> 40) & 0xff;
    p_aux[3] = (i_stc >> 32) & 0xff;
    p_aux[4] = (i_stc >> 24) & 0xff;
    p_aux[5] = (i_stc >> 16) & 0xff;
    p_aux[6] = (i_stc >> 8) & 0xff;
    p_aux[7] = (i_stc >> 0) & 0xff;
    if ( fwrite( p_aux, 8, 1, p_output_aux ) != 1 )
        msg_Err( NULL, "couldn't write to auxiliary file" );

    return i_ret;
}

/*****************************************************************************
 * GetPCR: read PCRs to align RTP timestamps with PCR scale (RFC compliance)
 *****************************************************************************/
static void GetPCR( const uint8_t *p_buffer, size_t i_read_size )
{
    while ( i_read_size >= TS_SIZE )
    {
        uint16_t i_pid = ts_GetPID( p_buffer );

        if ( !ts_CheckSync( p_buffer ) )
        {
            msg_Warn( NULL, "invalid TS packet (sync=0x%x)", p_buffer[0] );
            return;
        }
        if ( (i_pid == i_pcr_pid || i_pcr_pid == 8192)
              && ts_HasPCR( p_buffer ) )
        {
            i_pcr = ts_GetPCR( p_buffer ) * 300 + ts_GetPCRExt( p_buffer );
            i_pcr_stc = i_stc;
        }
        p_buffer += TS_SIZE;
        i_read_size -= TS_SIZE;
    }
}

/*****************************************************************************
 * Entry point
 *****************************************************************************/
int main( int i_argc, char **pp_argv )
{
    int i_priority = -1;
    int i_ttl = 0;
    int i_skip_chunks = 0, i_nb_chunks = -1;
    uint64_t i_duration = 0, i_last_stc = 0;
    bool b_append = false;
    uint8_t *p_buffer, *p_read_buffer;
    size_t i_max_read_size, i_max_write_size;
    int c;
    struct sigaction sa;
    sigset_t set;

    /* Parse options */
    while ( (c = getopt( i_argc, pp_argv, "i:t:p:s:n:d:aS:uUm:h" )) != -1 )
    {
        switch ( c )
        {
        case 'i':
            i_priority = strtol( optarg, NULL, 0 );
            break;

        case 't':
            i_ttl = strtol( optarg, NULL, 0 );
            break;

        case 'p':
            i_pcr_pid = strtol( optarg, NULL, 0 );
            break;

        case 's':
            i_skip_chunks = strtol( optarg, NULL, 0 );
            break;

        case 'n':
            i_nb_chunks = strtol( optarg, NULL, 0 );
            break;

        case 'd':
            i_duration = strtoull( optarg, NULL, 0 );
            break;

        case 'a':
            b_append = true;
            break;

        case 'S':
        {
            struct in_addr maddr;
            if ( !inet_aton( optarg, &maddr ) )
                usage();
            i_ssrc = maddr.s_addr;
            b_overwrite_ssrc = true;
            break;
        }

        case 'u':
            b_input_udp = true;
            break;

        case 'U':
            b_output_udp = true;
            break;

        case 'm':
            i_asked_payload_size = strtol( optarg, NULL, 0 );
            break;

        case 'h':
        default:
            usage();
            break;
        }
    }
    if ( optind >= i_argc - 1 )
        usage();

    /* Open sockets */
    if ( (i_input_fd = OpenSocket( pp_argv[optind], i_ttl, NULL )) >= 0 )
    {
        pf_Read = udp_Read;
        pf_Skip = udp_Skip;
    }
    else
    {
        bool b_stream;
        i_input_fd = OpenFile( pp_argv[optind], true, false, &b_stream );
        if ( !b_stream )
        {
            p_input_aux = OpenAuxFile( pp_argv[optind], true, false );
            pf_Read = file_Read;
            pf_Skip = file_Skip;
        }
        else
        {
            pf_Read = stream_Read;
            pf_Skip = stream_Skip;
        }
        b_input_udp = true; /* We don't need no, RTP header */
    }
    optind++;

    if ( (i_output_fd = OpenSocket( pp_argv[optind], i_ttl, NULL ))
           >= 0 )
        pf_Write = udp_Write;
    else
    {
        bool b_stream;
        i_output_fd = OpenFile( pp_argv[optind], false, b_append, &b_stream );
        if ( !b_stream )
        {
            p_output_aux = OpenAuxFile( pp_argv[optind], false, b_append );
            pf_Write = file_Write;
        }
        else
            pf_Write = stream_Write;
        b_output_udp = true; /* We don't need no, RTP header */
    }
    optind++;

    srand( time(NULL) * getpid() );
    i_max_read_size = i_asked_payload_size + (b_input_udp ? 0 :
                                              RTP_HEADER_MAX_SIZE);
    i_max_write_size = i_asked_payload_size + (b_output_udp ? 0 :
                                        (b_input_udp ? RTP_HEADER_SIZE :
                                         RTP_HEADER_MAX_SIZE));
    p_buffer = malloc( (i_max_read_size > i_max_write_size) ? i_max_read_size :
                       i_max_write_size );
    p_read_buffer = p_buffer + ((b_input_udp && !b_output_udp) ?
                                RTP_HEADER_SIZE : 0);
    if ( b_input_udp && !b_output_udp )
        i_rtp_cc = rand() & 0xffff;

    if ( i_skip_chunks )
        pf_Skip( i_asked_payload_size, i_skip_chunks );

    /* Real-time priority */
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

    /* Set signal handlers */
    memset( &sa, 0, sizeof(struct sigaction) );
    sa.sa_handler = SigHandler;
    sigfillset( &set );

    if ( sigaction( SIGTERM, &sa, NULL ) == -1 ||
         sigaction( SIGHUP, &sa, NULL ) == -1 ||
         sigaction( SIGINT, &sa, NULL ) == -1 )
    {
        msg_Err( NULL, "couldn't set signal handler: %s", strerror(errno) );
        exit(EXIT_FAILURE);
    }

    /* Main loop */
    while ( !b_die )
    {
        ssize_t i_read_size = pf_Read( p_read_buffer, i_max_read_size );
        uint8_t *p_payload;
        size_t i_payload_size;
        uint8_t *p_write_buffer;
        size_t i_write_size;

        if ( i_read_size <= 0 ) continue;

        /* Determine start and size of payload */
        if ( !b_input_udp )
        {
            if ( !rtp_CheckHdr( p_read_buffer ) )
                msg_Warn( NULL, "invalid RTP packet received" );
            p_payload = rtp_GetPayload( p_read_buffer );
            i_payload_size = p_read_buffer + i_read_size - p_payload;
        }
        else
        {
            p_payload = p_read_buffer;
            i_payload_size = i_read_size;
        }

        /* Pad to get the asked payload size */
        while ( i_payload_size + TS_SIZE <= i_asked_payload_size )
        {
            ts_Pad( &p_payload[i_payload_size] );
            i_read_size += TS_SIZE;
            i_payload_size += TS_SIZE;
        }

        /* Prepare header and size of output */
        if ( b_output_udp )
        {
            p_write_buffer = p_payload;
            i_write_size = i_payload_size;
        }
        else /* RTP output */
        {
            if ( b_input_udp )
            {
                p_write_buffer = p_buffer;
                i_write_size = i_payload_size + RTP_HEADER_SIZE;

                rtp_SetHdr( p_write_buffer, i_rtp_cc );
                i_rtp_cc++;

                if ( i_pcr_pid )
                {
                    GetPCR( p_payload, i_payload_size );
                    rtp_SetTimestamp( p_write_buffer,
                                      (i_pcr + (i_stc - i_pcr_stc)) / 300 );
                }
                else
                {
                    /* This isn't RFC-compliant but no one really cares */
                    rtp_SetTimestamp( p_write_buffer, i_stc / 300 );
                }
                rtp_SetSSRC( p_write_buffer, (uint8_t *)&i_ssrc );
            }
            else /* RTP output, RTP input */
            {
                p_write_buffer = p_read_buffer;
                i_write_size = i_read_size;

                if ( i_pcr_pid )
                {
                    if ( rtp_GetType( p_write_buffer ) != RTP_TS_TYPE )
                        msg_Warn( NULL, "input isn't MPEG transport stream" );
                    else
                        GetPCR( p_payload, i_payload_size );
                    rtp_SetTimestamp( p_write_buffer,
                                      (i_pcr + (i_stc - i_pcr_stc)) / 300 );
                }
                if ( b_overwrite_ssrc )
                    rtp_SetSSRC( p_write_buffer, (uint8_t *)&i_ssrc );
            }
        }

        pf_Write( p_write_buffer, i_write_size );

        if ( i_nb_chunks > 0 )
            i_nb_chunks--;
        if ( !i_nb_chunks )
            b_die = 1;

        if ( i_duration )
        {
            if ( i_last_stc )
            {
                if ( i_last_stc <= i_stc )
                    b_die = 1;
            }
            else
                i_last_stc = i_stc + i_duration;
        }
    }

    return EXIT_SUCCESS;
}

