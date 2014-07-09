/*****************************************************************************
 * multicat.c: netcat-equivalent for multicast
 *****************************************************************************
 * Copyright (C) 2009, 2011-2012 VideoLAN
 * $Id$
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

#ifdef SIOCGSTAMPNS
#   define HAVE_TIMESTAMPS
#endif

#ifndef POLLRDHUP
#   define POLLRDHUP 0
#endif

#include <bitstream/ietf/rtp.h>
#include <bitstream/mpeg/ts.h>

#include "util.h"

#undef DEBUG_WRITEBACK
#define POLL_TIMEOUT 1000 /* 1 s */
#define MAX_LATENESS INT64_C(27000000) /* 1 s */
#define FILE_FLUSH INT64_C(2700000) /* 100 ms */

/*****************************************************************************
 * Local declarations
 *****************************************************************************/
static int i_input_fd, i_output_fd;
FILE *p_input_aux, *p_output_aux;
static int i_ttl = 0;
static bool b_sleep = true;
static uint16_t i_pcr_pid = 0;
static bool b_overwrite_ssrc = false;
static in_addr_t i_ssrc = 0;
static bool b_input_udp = false, b_output_udp = false;
static size_t i_asked_payload_size = DEFAULT_PAYLOAD_SIZE;
static size_t i_rtp_header_size = RTP_HEADER_SIZE;
static uint64_t i_rotate_size = DEFAULT_ROTATE_SIZE;
struct udprawpkt pktheader;
bool b_raw_packets = false;

static volatile sig_atomic_t b_die = 0;
static uint16_t i_rtp_seqnum;
static uint64_t i_stc = 0; /* system time clock, used for date calculations */
static uint64_t i_first_stc = 0;
static uint64_t i_pcr = 0, i_pcr_stc = 0; /* for RTP/TS output */
uint64_t (*pf_Date)(void) = wall_Date;
void (*pf_Sleep)( uint64_t ) = wall_Sleep;
ssize_t (*pf_Read)( void *p_buf, size_t i_len );
bool (*pf_Delay)(void) = NULL;
void (*pf_ExitRead)(void);
ssize_t (*pf_Write)( const void *p_buf, size_t i_len );
void (*pf_ExitWrite)(void);

static void usage(void)
{
    msg_Raw( NULL, "Usage: multicat [-i <RT priority>] [-t <ttl>] [-X] [-T <file name>] [-f] [-p <PCR PID>] [-s <chunks>] [-n <chunks>] [-k <start time>] [-d <duration>] [-a] [-r <file duration>] [-S <SSRC IP>] [-u] [-U] [-m <payload size>] [-R <RTP header size>] [-w] <input item> <output item>" );
    msg_Raw( NULL, "    item format: <file path | device path | FIFO path | directory path | network host>" );
    msg_Raw( NULL, "    host format: [<connect addr>[:<connect port>]][@[<bind addr][:<bind port>]]" );
    msg_Raw( NULL, "    -X: also pass-through all packets to stdout" );
    msg_Raw( NULL, "    -T: write an XML file with the current characteristics of transmission" );
    msg_Raw( NULL, "    -f: output packets as fast as possible" );
    msg_Raw( NULL, "    -p: overwrite or create RTP timestamps using PCR PID (MPEG-2/TS)" );
    msg_Raw( NULL, "    -s: skip the first N chunks of payload [deprecated]" );
    msg_Raw( NULL, "    -n: exit after playing N chunks of payload [deprecated]" );
    msg_Raw( NULL, "    -k: start at the given position (in 27 MHz units, negative = from the end)" );
    msg_Raw( NULL, "    -d: exit after definite time (in 27 MHz units)" );
    msg_Raw( NULL, "    -a: append to existing destination file (risky)" );
    msg_Raw( NULL, "    -r: in directory mode, rotate file after this duration (default: 97200000000 ticks = 1 hour)" );
    msg_Raw( NULL, "    -S: overwrite or create RTP SSRC" );
    msg_Raw( NULL, "    -u: source has no RTP header" );
    msg_Raw( NULL, "    -U: destination has no RTP header" );
    msg_Raw( NULL, "    -m: size of the payload chunk, excluding optional RTP header (default 1316)" );
    msg_Raw( NULL, "    -R: size of the optional RTP header (default 12)" );
    msg_Raw( NULL, "    -w: send with RAW (needed for /srcaddr)" );
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
 * Poll: factorize polling code
 *****************************************************************************/
static bool Poll(void)
{
    struct pollfd pfd;
    int i_ret;

    pfd.fd = i_input_fd;
    pfd.events = POLLIN | POLLERR | POLLRDHUP | POLLHUP;

    i_ret = poll( &pfd, 1, POLL_TIMEOUT );
    if ( i_ret < 0 )
    {
        msg_Err( NULL, "poll error (%s)", strerror(errno) );
        b_die = 1;
        return false;
    }
    if ( pfd.revents & (POLLERR | POLLRDHUP | POLLHUP) )
    {
        msg_Err( NULL, "poll error" );
        b_die = 1;
        return false;
    }
    if ( !i_ret ) return false;

    return true;
}

/*****************************************************************************
 * tcp_*: TCP socket handlers (only what differs from UDP)
 *****************************************************************************/
static uint8_t *p_tcp_buffer = NULL;
static size_t i_tcp_size = 0;

static ssize_t tcp_Read( void *p_buf, size_t i_len )
{
    if ( p_tcp_buffer == NULL )
        p_tcp_buffer = malloc(i_len);

    uint8_t *p_read_buffer;
    ssize_t i_read_size = i_len;
    p_read_buffer = p_tcp_buffer + i_tcp_size;
    i_read_size -= i_tcp_size;

    if ( (i_read_size = recv( i_input_fd, p_read_buffer, i_read_size, 0 )) < 0 )
    {
        msg_Err( NULL, "recv error (%s)", strerror(errno) );
        b_die = 1;
        return 0;
    }

    i_tcp_size += i_read_size;
    i_stc = pf_Date();

    if ( i_tcp_size != i_len )
        return 0;

    memcpy( p_buf, p_tcp_buffer, i_len );
    i_tcp_size = 0;
    return i_len;
}

/*****************************************************************************
 * udp_*: UDP socket handlers
 *****************************************************************************/
static off_t i_udp_nb_skips = 0;
static bool b_tcp = false;

static ssize_t udp_Read( void *p_buf, size_t i_len )
{
    ssize_t i_ret;
    if ( !i_udp_nb_skips && !i_first_stc )
        i_first_stc = pf_Date();

    if ( !Poll() )
    {
        i_stc = pf_Date();
        return 0;
    }

    if ( !b_tcp )
    {
        if ( (i_ret = recv( i_input_fd, p_buf, i_len, 0 )) < 0 )
        {
            msg_Err( NULL, "recv error (%s)", strerror(errno) );
            b_die = 1;
            return 0;
        }

#ifdef HAVE_TIMESTAMPS
        struct timespec ts;
        if ( !ioctl( i_input_fd, SIOCGSTAMPNS, &ts ) )
            i_stc = ts.tv_sec * UINT64_C(27000000) + ts.tv_nsec * 27 / 1000;
        else
#endif
        i_stc = pf_Date();
    }
    else
        i_ret = tcp_Read( p_buf, i_len );

    if ( i_udp_nb_skips )
    {
        i_udp_nb_skips--;
        return 0;
    }
    return i_ret;
}

static void udp_ExitRead(void)
{
    close( i_input_fd );
    if ( p_tcp_buffer != NULL )
        free( p_tcp_buffer );
}

static int udp_InitRead( const char *psz_arg, size_t i_len,
                         off_t i_nb_skipped_chunks, int64_t i_pos )
{
    if ( i_pos || (i_input_fd = OpenSocket( psz_arg, i_ttl, DEFAULT_PORT, 0,
                                            NULL, &b_tcp, NULL )) < 0 )
        return -1;

    i_udp_nb_skips = i_nb_skipped_chunks;

    pf_Read = udp_Read;
    pf_ExitRead = udp_ExitRead;
#ifdef HAVE_TIMESTAMPS
    if ( !b_tcp )
        pf_Date = real_Date;
#endif
    return 0;
}

static ssize_t raw_Write( const void *p_buf, size_t i_len )
{
#ifndef __APPLE__
    ssize_t i_ret;
    struct iovec iov[2];

    #ifdef __FAVOR_BSD
    pktheader.udph.uh_ulen
    #else
    pktheader.udph.len
    #endif
    = htons(sizeof(struct udphdr) + i_len);

    iov[0].iov_base = &pktheader;
    iov[0].iov_len = sizeof(struct udprawpkt);

    iov[1].iov_base = (void *) p_buf;
    iov[1].iov_len = i_len;

    if ( (i_ret = writev( i_output_fd, iov, 2 )) < 0 )
    {
        if ( errno == EBADF || errno == ECONNRESET || errno == EPIPE )
        {
            msg_Err( NULL, "write error (%s)", strerror(errno) );
            b_die = 1;
        }
        /* otherwise do not set b_die because these errors can be transient */
        return 0;
    }

    return i_ret;
#else
    return -1;
#endif
}

/* Please note that the write functions also work for TCP */
static ssize_t udp_Write( const void *p_buf, size_t i_len )
{
    ssize_t i_ret;
    if ( (i_ret = send( i_output_fd, p_buf, i_len, 0 )) < 0 )
    {
        if ( errno == EBADF || errno == ECONNRESET || errno == EPIPE )
        {
            msg_Err( NULL, "write error (%s)", strerror(errno) );
            b_die = 1;
        }
        /* otherwise do not set b_die because these errors can be transient */
        return 0;
    }

    return i_ret;
}

static void udp_ExitWrite(void)
{
    close( i_output_fd );
}

static int udp_InitWrite( const char *psz_arg, size_t i_len, bool b_append )
{
    struct opensocket_opt opt;

    memset(&opt, 0, sizeof(struct opensocket_opt));
    if (b_raw_packets) {
        opt.p_raw_pktheader = &pktheader;
    }
    if ( (i_output_fd = OpenSocket( psz_arg, i_ttl, 0, DEFAULT_PORT,
                                    NULL, NULL, &opt )) < 0 )
        return -1;
    if (b_raw_packets) { 
        pf_Write = raw_Write;
    } else {
        pf_Write = udp_Write;
    }
    pf_ExitWrite = udp_ExitWrite;
    return 0;
}

/*****************************************************************************
 * stream_*: FIFO and character device handlers
 *****************************************************************************/
static off_t i_stream_nb_skips = 0;

static ssize_t stream_Read( void *p_buf, size_t i_len )
{
    ssize_t i_ret;
    if ( !i_stream_nb_skips && !i_first_stc )
        i_first_stc = pf_Date();

    if ( !Poll() )
    {
        i_stc = pf_Date();
        return 0;
    }

    if ( (i_ret = read( i_input_fd, p_buf, i_len )) < 0 )
    {
        msg_Err( NULL, "read error (%s)", strerror(errno) );
        b_die = 1;
        return 0;
    }

    i_stc = pf_Date();
    if ( i_stream_nb_skips )
    {
        i_stream_nb_skips--;
        return 0;
    }
    return i_ret;
}

static void stream_ExitRead(void)
{
    close( i_input_fd );
}

static int stream_InitRead( const char *psz_arg, size_t i_len,
                            off_t i_nb_skipped_chunks, int64_t i_pos )
{
    if ( i_pos ) return -1;

    i_input_fd = OpenFile( psz_arg, true, false );
    i_stream_nb_skips = i_nb_skipped_chunks;

    pf_Read = stream_Read;
    pf_ExitRead = stream_ExitRead;
    return 0;
}

static ssize_t stream_Write( const void *p_buf, size_t i_len )
{
    ssize_t i_ret;
retry:
    if ( (i_ret = write( i_output_fd, p_buf, i_len )) < 0 )
    {
        if (errno == EAGAIN || errno == EINTR)
            goto retry;
        msg_Err( NULL, "write error (%s)", strerror(errno) );
        b_die = 1;
    }
    return i_ret;
}

static void stream_ExitWrite(void)
{
    close( i_output_fd );
}

static int stream_InitWrite( const char *psz_arg, size_t i_len, bool b_append )
{
    i_output_fd = OpenFile( psz_arg, false, b_append );

    pf_Write = stream_Write;
    pf_ExitWrite = stream_ExitWrite;
    return 0;
}

/*****************************************************************************
 * file_*: handler for the auxiliary file format
 *****************************************************************************/
static uint64_t i_file_next_flush = 0;

static ssize_t file_Read( void *p_buf, size_t i_len )
{
    uint8_t p_aux[8];
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
    i_stc = FromSTC( p_aux );
    if ( !i_first_stc ) i_first_stc = i_stc;

    return i_ret;
}

static bool file_Delay(void)
{
    /* for correct throughput without rounding approximations */
    static uint64_t i_file_first_stc = 0, i_file_first_wall = 0;
    uint64_t i_wall = pf_Date();

    if ( !i_file_first_wall )
    {
        i_file_first_wall = i_wall;
        i_file_first_stc = i_stc;
    }
    else
    {
        int64_t i_delay = (i_stc - i_file_first_stc) -
                          (i_wall - i_file_first_wall);
        if ( i_delay > 0 )
            pf_Sleep( i_delay );
        else if ( i_delay < -MAX_LATENESS )
        {
            msg_Warn( NULL, "too much lateness, resetting clocks" );
            i_file_first_wall = i_wall;
            i_file_first_stc = i_stc;
        }
    }
    return true;
}

static void file_ExitRead(void)
{
    close( i_input_fd );
    fclose( p_input_aux );
}

static int file_InitRead( const char *psz_arg, size_t i_len,
                          off_t i_nb_skipped_chunks, int64_t i_pos )
{
    char *psz_aux_file = GetAuxFile( psz_arg, i_len );
    if ( i_pos )
    {
        i_nb_skipped_chunks = LookupAuxFile( psz_aux_file, i_pos, false );
        if ( i_nb_skipped_chunks < 0 )
        {
            free( psz_aux_file );
            return -1;
        }
    }

    i_input_fd = OpenFile( psz_arg, true, false );
    p_input_aux = OpenAuxFile( psz_aux_file, true, false );
    free( psz_aux_file );

    lseek( i_input_fd, (off_t)i_len * i_nb_skipped_chunks, SEEK_SET );
    fseeko( p_input_aux, 8 * i_nb_skipped_chunks, SEEK_SET );

    pf_Read = file_Read;
    pf_Delay = file_Delay;
    pf_ExitRead = file_ExitRead;
    return 0;
}

static ssize_t file_Write( const void *p_buf, size_t i_len )
{
    uint8_t p_aux[8];
    ssize_t i_ret;
#ifdef DEBUG_WRITEBACK
    uint64_t start = pf_Date(), end;
#endif

    if ( (i_ret = write( i_output_fd, p_buf, i_len )) < 0 )
    {
        msg_Err( NULL, "couldn't write to file (%s)", strerror(errno) );
        b_die = 1;
        return i_ret;
    }
#ifdef DEBUG_WRITEBACK
    end = pf_Date();
    if (end - start > 270000) /* 10 ms */
        msg_Err(NULL, "too long waiting in write(%"PRId64")", (end - start) / 27000);
#endif

    ToSTC( p_aux, i_stc );
    if ( fwrite( p_aux, 8, 1, p_output_aux ) != 1 )
    {
        msg_Err( NULL, "couldn't write to auxiliary file" );
        b_die = 1;
    }
    if (!i_file_next_flush)
        i_file_next_flush = i_stc + FILE_FLUSH;
    else if (i_file_next_flush <= i_stc)
    {
        fflush( p_output_aux );
        i_file_next_flush = i_stc + FILE_FLUSH;
    }

    return i_ret;
}

static void file_ExitWrite(void)
{
    close( i_output_fd );
    fclose( p_output_aux );
}

static int file_InitWrite( const char *psz_arg, size_t i_len, bool b_append )
{
    char *psz_aux_file = GetAuxFile( psz_arg, i_len );
    if ( b_append )
        CheckFileSizes( psz_arg, psz_aux_file, i_len );
    i_output_fd = OpenFile( psz_arg, false, b_append );
    p_output_aux = OpenAuxFile( psz_aux_file, false, b_append );
    free( psz_aux_file );

    pf_Write = file_Write;
    pf_ExitWrite = file_ExitWrite;
    return 0;
}

/*****************************************************************************
 * dir_*: handler for the auxiliary directory format
 *****************************************************************************/
static char *psz_input_dir_name;
static size_t i_input_dir_len;
static uint64_t i_input_dir_file;
static uint64_t i_input_dir_delay;

static ssize_t dir_Read( void *p_buf, size_t i_len )
{
    ssize_t i_ret;
try_again:
    i_ret = file_Read( p_buf, i_len );
    if ( !i_ret )
    {
        b_die = 0; /* we're not dead yet */
        close( i_input_fd );
        fclose( p_input_aux );
        i_input_fd = 0;

        i_input_dir_file++;

        i_input_fd = OpenDirFile( psz_input_dir_name, i_input_dir_file,
                                  true, i_input_dir_len, &p_input_aux );
        if ( i_input_fd < 0 )
        {
            msg_Err( NULL, "end of files reached" );
            b_die = 1;
            return 0;
        }
        goto try_again;
    }
    return i_ret;
}

static bool dir_Delay(void)
{
    uint64_t i_wall = pf_Date() - i_input_dir_delay;
    int64_t i_delay = i_stc - i_wall;

    if ( i_delay > 0 )
        pf_Sleep( i_delay );
    else if ( i_delay < -MAX_LATENESS )
    {
        msg_Warn( NULL, "dropping late packet" );
        return false;
    }
    return true;
}

static void dir_ExitRead(void)
{
    free( psz_input_dir_name );
    if ( i_input_fd )
    {
        close( i_input_fd );
        fclose( p_input_aux );
    }
}

static int dir_InitRead( const char *psz_arg, size_t i_len,
                         off_t i_nb_skipped_chunks, int64_t i_pos )
{
    if ( i_nb_skipped_chunks )
    {
        msg_Err( NULL, "unable to skip chunks with directory input" );
        return -1;
    }

    if ( i_pos <= 0 )
        i_pos += real_Date();
    if ( i_pos <= 0 )
    {
        msg_Err( NULL, "invalid position" );
        return -1;
    }
    i_first_stc = i_stc = i_pos;
    i_input_dir_delay = real_Date() - i_stc;

    psz_input_dir_name = strdup( psz_arg );
    i_input_dir_len = i_len;
    i_input_dir_file = GetDirFile( i_rotate_size, i_pos );

    i_nb_skipped_chunks = LookupDirAuxFile( psz_input_dir_name,
                                            i_input_dir_file, i_stc,
                                            i_input_dir_len );
    if ( i_nb_skipped_chunks < 0 )
    {
        /* Try at most one more chunk */
        i_input_dir_file++;
        i_nb_skipped_chunks = LookupDirAuxFile( psz_input_dir_name,
                                                i_input_dir_file, i_stc,
                                                i_input_dir_len );
        if ( i_nb_skipped_chunks < 0 )
        {
            msg_Err( NULL, "position not found" );
            return -1;
        }
    }

    i_input_fd = OpenDirFile( psz_input_dir_name, i_input_dir_file,
                              true, i_input_dir_len, &p_input_aux );

    lseek( i_input_fd, (off_t)i_len * i_nb_skipped_chunks, SEEK_SET );
    fseeko( p_input_aux, 8 * i_nb_skipped_chunks, SEEK_SET );

    pf_Date = real_Date;
    pf_Sleep = real_Sleep;
    pf_Read = dir_Read;
    pf_Delay = dir_Delay;
    pf_ExitRead = dir_ExitRead;
    return 0;
}

static char *psz_output_dir_name;
static size_t i_output_dir_len;
static uint64_t i_output_dir_file;

static ssize_t dir_Write( const void *p_buf, size_t i_len )
{
    uint64_t i_dir_file = GetDirFile( i_rotate_size, i_stc );
    if ( !i_output_fd || i_dir_file != i_output_dir_file )
    {
        if ( i_output_fd )
        {
            close( i_output_fd );
            fclose( p_output_aux );
        }

        i_output_dir_file = i_dir_file;

        i_output_fd = OpenDirFile( psz_output_dir_name, i_output_dir_file,
                                   false, i_output_dir_len, &p_output_aux );
    }

    return file_Write( p_buf, i_len );
}

static void dir_ExitWrite(void)
{
    free( psz_output_dir_name );
    if ( i_output_fd )
    {
        close( i_output_fd );
        fclose( p_output_aux );
    }
}

static int dir_InitWrite( const char *psz_arg, size_t i_len, bool b_append )
{
    psz_output_dir_name = strdup( psz_arg );
    i_output_dir_len = i_len;
    i_output_dir_file = 0;
    i_output_fd = 0;

    pf_Date = real_Date;
    pf_Sleep = real_Sleep;
    pf_Write = dir_Write;
    pf_ExitWrite = dir_ExitWrite;

    return 0;
}

/*****************************************************************************
 * GetPCR: read PCRs to align RTP timestamps with PCR scale (RFC compliance)
 *****************************************************************************/
static void GetPCR( const uint8_t *p_buffer, size_t i_read_size )
{
    while ( i_read_size >= TS_SIZE )
    {
        uint16_t i_pid = ts_get_pid( p_buffer );

        if ( !ts_validate( p_buffer ) )
        {
            msg_Warn( NULL, "invalid TS packet (sync=0x%x)", p_buffer[0] );
            return;
        }
        if ( (i_pid == i_pcr_pid || i_pcr_pid == 8192)
              && ts_has_adaptation(p_buffer) && ts_get_adaptation(p_buffer)
              && tsaf_has_pcr(p_buffer) )
        {
            i_pcr = tsaf_get_pcr( p_buffer ) * 300 + tsaf_get_pcrext( p_buffer );
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
    bool b_passthrough = false;
    int i_stc_fd = -1;
    off_t i_skip_chunks = 0, i_nb_chunks = -1;
    int64_t i_seek = 0;
    uint64_t i_duration = 0;
    bool b_append = false;
    uint8_t *p_buffer, *p_read_buffer;
    size_t i_max_read_size, i_max_write_size;
    int c;
    struct sigaction sa;
    sigset_t set;

    /* Parse options */
    while ( (c = getopt( i_argc, pp_argv, "i:t:XT:fp:s:n:k:d:ar:S:uUm:R:wh" )) != -1 )
    {
        switch ( c )
        {
        case 'i':
            i_priority = strtol( optarg, NULL, 0 );
            break;

        case 't':
            i_ttl = strtol( optarg, NULL, 0 );
            break;

        case 'X':
            b_passthrough = true;
            break;

        case 'T':
            i_stc_fd = open( optarg, O_WRONLY | O_CREAT | O_TRUNC, 0644 );
            if ( i_stc_fd < 0 )
                msg_Warn( NULL, "unable to open %s (%s)\n", optarg,
                          strerror(errno) );
            break;

        case 'f':
            b_sleep = false;
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

        case 'k':
            i_seek = strtoull( optarg, NULL, 0 );
            break;

        case 'd':
            i_duration = strtoull( optarg, NULL, 0 );
            break;

        case 'a':
            b_append = true;
            break;

        case 'r':
            i_rotate_size = strtoull( optarg, NULL, 0 );
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

        case 'R':
            i_rtp_header_size = strtol( optarg, NULL, 0 );
            break;

        case 'w':
            b_raw_packets = true;
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
    if ( udp_InitRead( pp_argv[optind], i_asked_payload_size, i_skip_chunks,
                       i_seek ) < 0 )
    {
        int i_ret;
        mode_t i_mode = StatFile( pp_argv[optind] );
        if ( !i_mode )
        {
            msg_Err( NULL, "input not found, exiting" );
            exit(EXIT_FAILURE);
        }

        if ( S_ISDIR( i_mode ) )
            i_ret = dir_InitRead( pp_argv[optind], i_asked_payload_size,
                                  i_skip_chunks, i_seek );
        else if ( S_ISCHR( i_mode ) || S_ISFIFO( i_mode ) )
            i_ret = stream_InitRead( pp_argv[optind], i_asked_payload_size,
                                     i_skip_chunks, i_seek );
        else
            i_ret = file_InitRead( pp_argv[optind], i_asked_payload_size,
                                   i_skip_chunks, i_seek );
        if ( i_ret == -1 )
        {
            msg_Err( NULL, "couldn't open input, exiting" );
            exit(EXIT_FAILURE);
        }
        b_input_udp = true; /* We don't need no, RTP header */
    }
    optind++;

    if ( udp_InitWrite( pp_argv[optind], i_asked_payload_size, b_append ) < 0 )
    {
        int i_ret;
        mode_t i_mode = StatFile( pp_argv[optind] );

        if ( S_ISDIR( i_mode ) )
            i_ret = dir_InitWrite( pp_argv[optind], i_asked_payload_size,
                                   b_append );
        else if ( S_ISCHR( i_mode ) || S_ISFIFO( i_mode ) )
            i_ret = stream_InitWrite( pp_argv[optind], i_asked_payload_size,
                                      b_append );
        else
            i_ret = file_InitWrite( pp_argv[optind], i_asked_payload_size,
                                    b_append );
        if ( i_ret == -1 )
        {
            msg_Err( NULL, "couldn't open output, exiting" );
            exit(EXIT_FAILURE);
        }
        b_output_udp = true; /* We don't need no, RTP header */
    }
    optind++;

    srand( time(NULL) * getpid() );
    i_max_read_size = i_asked_payload_size + (b_input_udp ? 0 :
                                              i_rtp_header_size);
    i_max_write_size = i_asked_payload_size + (b_output_udp ? 0 :
                                        (b_input_udp ? RTP_HEADER_SIZE :
                                         i_rtp_header_size));
    p_buffer = malloc( (i_max_read_size > i_max_write_size) ? i_max_read_size :
                       i_max_write_size );
    p_read_buffer = p_buffer + ((b_input_udp && !b_output_udp) ?
                                RTP_HEADER_SIZE : 0);
    if ( b_input_udp && !b_output_udp )
        i_rtp_seqnum = rand() & 0xffff;

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
         sigaction( SIGINT, &sa, NULL ) == -1 ||
         sigaction( SIGPIPE, &sa, NULL ) == -1 )
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

        if ( i_duration && i_stc > i_first_stc + i_duration )
            break;

        if ( i_read_size <= 0 ) continue;

        if ( b_sleep && pf_Delay != NULL)
            if (!pf_Delay())
                goto dropped_packet;

        /* Determine start and size of payload */
        if ( !b_input_udp )
        {
            if ( !rtp_check_hdr( p_read_buffer ) )
                msg_Warn( NULL, "invalid RTP packet received" );
            p_payload = rtp_payload( p_read_buffer );
            i_payload_size = p_read_buffer + i_read_size - p_payload;
        }
        else
        {
            p_payload = p_read_buffer;
            i_payload_size = i_read_size;
        }

        /* Skip last incomplete TS packet */
        i_read_size -= i_payload_size % TS_SIZE;
        i_payload_size -= i_payload_size % TS_SIZE;

        /* Pad to get the asked payload size */
        while ( i_payload_size + TS_SIZE <= i_asked_payload_size )
        {
            ts_pad( &p_payload[i_payload_size] );
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

                rtp_set_hdr( p_write_buffer );
                rtp_set_type( p_write_buffer, RTP_TYPE_TS );
                rtp_set_seqnum( p_write_buffer, i_rtp_seqnum );
                i_rtp_seqnum++;

                if ( i_pcr_pid )
                {
                    GetPCR( p_payload, i_payload_size );
                    rtp_set_timestamp( p_write_buffer,
                                       (i_pcr + (i_stc - i_pcr_stc)) / 300 );
                }
                else
                {
                    /* This isn't RFC-compliant but no one really cares */
                    rtp_set_timestamp( p_write_buffer, i_stc / 300 );
                }
                rtp_set_ssrc( p_write_buffer, (uint8_t *)&i_ssrc );
            }
            else /* RTP output, RTP input */
            {
                p_write_buffer = p_read_buffer;
                i_write_size = i_read_size;

                if ( i_pcr_pid )
                {
                    if ( rtp_get_type( p_write_buffer ) != RTP_TYPE_TS )
                        msg_Warn( NULL, "input isn't MPEG transport stream" );
                    else
                        GetPCR( p_payload, i_payload_size );
                    rtp_set_timestamp( p_write_buffer,
                                       (i_pcr + (i_stc - i_pcr_stc)) / 300 );
                }
                if ( b_overwrite_ssrc )
                    rtp_set_ssrc( p_write_buffer, (uint8_t *)&i_ssrc );
            }
        }

        pf_Write( p_write_buffer, i_write_size );
        if ( b_passthrough )
            if ( write( STDOUT_FILENO, p_write_buffer, i_write_size )
                  != i_write_size )
                msg_Warn( NULL, "write(stdout) error (%s)", strerror(errno) );

dropped_packet:
        if ( i_stc_fd != -1 )
        {
            char psz_stc[256];
            size_t i_len = sprintf( psz_stc, "<?xml version=\"1.0\" encoding=\"utf-8\"?><MULTICAT><STC value=\"%"PRIu64"\"/></MULTICAT>", i_stc );
            memset( psz_stc + i_len, '\n', sizeof(psz_stc) - i_len );
            if ( lseek( i_stc_fd, 0, SEEK_SET ) == (off_t)-1 )
                msg_Warn( NULL, "lseek date file failed (%s)",
                          strerror(errno) );
            if ( write( i_stc_fd, psz_stc, sizeof(psz_stc) ) != sizeof(psz_stc) )
                msg_Warn( NULL, "write date file error (%s)", strerror(errno) );
        }

        if ( i_nb_chunks > 0 )
            i_nb_chunks--;
        if ( !i_nb_chunks )
            break;
    }

    pf_ExitRead();
    pf_ExitWrite();

    return EXIT_SUCCESS;
}

