/*****************************************************************************
 * multilive.c: VRRP-like protocol using multicast
 *****************************************************************************
 * Copyright (C) 2017 VideoLAN
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
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <poll.h>
#include <syslog.h>

#include "util.h"

#define DEFAULT_PRIORITY        1
#define DEFAULT_PERIOD          (CLOCK_FREQ / 5)
#define DEFAULT_DEAD            5
#define DEFAULT_STARTUP_DELAY   0

#define ANNOUNCE_SIZE           12
#define ANNOUNCE_VERSION        1

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
 * Entry point
 *****************************************************************************/
static void usage(void)
{
    msg_Raw( NULL, "Usage: multilive [-i <RT priority>] [-l <syslogtag>] [-t <ttl>] [-y <priority>] [-p <period>] [-d <dead>] @<src host> <dest host>" );
    msg_Raw( NULL, "    host format: [<connect addr>[:<connect port>]][@[<bind addr][:<bind port>]]" );
    msg_Raw( NULL, "    -y: priority of this instance (32 bits) [1]" );
    msg_Raw( NULL, "    -p: periodicity of announces in 27 MHz units [27000000/5]" );
    msg_Raw( NULL, "    -d: number of periods after which the master is dead [5]" );
    msg_Raw( NULL, "    -g: startup delay in 27Mhz units [0]" );
    exit(EXIT_FAILURE);
}

int main( int i_argc, char **pp_argv )
{
    int c;
    int i_rt_priority = -1;
    const char *psz_syslog_tag = NULL;
    int i_ttl = 0;
    uint32_t i_priority = DEFAULT_PRIORITY;
    uint64_t i_period = DEFAULT_PERIOD;
    unsigned int i_dead = DEFAULT_DEAD;
    uint64_t i_startup_delay = DEFAULT_STARTUP_DELAY;
    struct pollfd *pfd = malloc(sizeof(struct pollfd));

    while ( (c = getopt( i_argc, pp_argv, "i:l:t:y:p:d:g:h" )) != -1 )
    {
        switch ( c )
        {
        case 'i':
            i_rt_priority = strtol( optarg, NULL, 0 );
            break;

        case 'l':
            psz_syslog_tag = optarg;
            break;

        case 't':
            i_ttl = strtol( optarg, NULL, 0 );
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

    struct opensocket_opt opt;
    memset(&opt, 0, sizeof(struct opensocket_opt));

    bool b_input_tcp, b_input_multicast;
    opt.pb_multicast = &b_input_multicast;
    int i_input_fd = OpenSocket( pp_argv[optind++], 0, DEFAULT_PORT, 0,
                                 NULL, &b_input_tcp, &opt );
    if ( i_input_fd == -1 )
    {
        msg_Err( NULL, "unable to open input socket" );
        exit(EXIT_FAILURE);
    }

    bool b_output_tcp, b_output_multicast;
    opt.pb_multicast = &b_output_multicast;
    int i_output_fd = OpenSocket( pp_argv[optind++], i_ttl, 0, DEFAULT_PORT,
                                  NULL, &b_output_tcp, &opt );
    if ( i_output_fd == -1 )
    {
        msg_Err( NULL, "unable to open input socket" );
        exit(EXIT_FAILURE);
    }
    if ( b_input_tcp || b_output_tcp )
    {
        msg_Err( NULL, "TCP is not supported" );
        exit(EXIT_FAILURE);
    }
    if ( !b_input_multicast || !b_output_multicast )
    {
        msg_Err( NULL, "unicast is not supported" );
        exit(EXIT_FAILURE);
    }

    pfd[0].fd = i_input_fd;
    pfd[0].events = POLLIN | POLLERR | POLLRDHUP | POLLHUP;

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
    /* Choose a random source so that we recognize the packets we send. */
    uint32_t i_source = lrand48();
    msg_Dbg( NULL, "random source ID: %"PRIx32, i_source );

    /* Choose a random skew so that all instances do not expire exactly at
     * the same time. */
    uint64_t i_master_expiration_skew = lrand48();
    i_master_expiration_skew *= i_period * i_dead;
    i_master_expiration_skew /= UINT32_MAX;
    msg_Dbg( NULL, "expiration skew: %"PRId64, i_master_expiration_skew );

    uint64_t i_master_expiration = i_period * i_dead + wall_Date() +
                                   i_master_expiration_skew + i_startup_delay;
    Down();

    uint64_t i_next_announce = UINT64_MAX;
    uint8_t p_buffer[ANNOUNCE_SIZE];
    for ( ; ; )
    {
        uint64_t i_current_date = wall_Date();

        if ( i_next_announce == UINT64_MAX )
        {
            if ( i_master_expiration <= i_current_date )
            {
                Up();
                i_next_announce = i_current_date;
            }
        }

        if ( i_next_announce <= i_current_date )
        {
            announce_set_version(p_buffer, ANNOUNCE_VERSION);
            announce_set_priority(p_buffer, i_priority);
            announce_set_source(p_buffer, i_source);
            if ( sendto( i_output_fd, p_buffer, ANNOUNCE_SIZE, 0, NULL, 0 )
                  < 0 )
            {
                if ( errno == EBADF || errno == ECONNRESET || errno == EPIPE )
                {
                    msg_Err( NULL, "write error (%s)", strerror(errno) );
                    exit(EXIT_FAILURE);
                }
                else
                    /* otherwise do not die because these errors can be transient */
                    msg_Warn( NULL, "write error (%s)", strerror(errno) );
            }

            i_current_date = wall_Date();
            i_next_announce += i_period;
        }

        /* next action date */
        uint64_t i_next_run = i_next_announce != UINT64_MAX ?
            i_next_announce : i_master_expiration;

        /* add 1 ms for rounding */
        int i_timeout = ((i_next_run - i_current_date) * 1000 / CLOCK_FREQ) + 1;
        if ( i_timeout < 0 )
            i_timeout = 0;

        if ( poll( pfd, 1, i_timeout ) < 0 )
        {
            int saved_errno = errno;
            msg_Warn( NULL, "couldn't poll(): %s", strerror(errno) );
            if ( saved_errno == EINTR ) continue;
            exit(EXIT_FAILURE);
        }
        i_current_date = wall_Date();

        if ( pfd[0].revents & POLLIN )
        {
            ssize_t i_size = read( i_input_fd, p_buffer, ANNOUNCE_SIZE );

            if ( i_size < 0 && errno != EAGAIN && errno != EINTR &&
                 errno != ECONNREFUSED )
            {
                msg_Err( NULL, "unrecoverable read error, dying (%s)",
                         strerror(errno) );
                exit(EXIT_FAILURE);
            }
            if ( i_size <= 0 ) continue;

            if ( i_size != ANNOUNCE_SIZE ||
                 announce_get_version(p_buffer) != ANNOUNCE_VERSION)
            {
                msg_Warn( NULL, "dropping invalid announce" );
                continue;
            }

            if ( announce_get_source(p_buffer) == i_source )
                continue;

            if ( announce_get_priority(p_buffer) < i_priority )
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
        else if ( (pfd[0].revents & (POLLERR | POLLRDHUP | POLLHUP)) )
        {
            msg_Err( NULL, "poll error\n" );
            exit(EXIT_FAILURE);
        }
    }

    if ( psz_syslog_tag != NULL )
        msg_Closelog();

    return EXIT_SUCCESS;
}
