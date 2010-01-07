/*****************************************************************************
 * util.c: Utils for the multicat suite
 *****************************************************************************
 * Copyright (C) 2004, 2009 VideoLAN
 * $Id: util.c 27 2009-10-20 19:15:04Z massiot $
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
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "util.h"

/*****************************************************************************
 * Local declarations
 *****************************************************************************/
#define MAX_MSG 1024
#define PSZ_AUX_EXT "aux"

int i_verbose = VERB_DBG;

/*****************************************************************************
 * msg_Info
 *****************************************************************************/
void msg_Info( void *_unused, const char *psz_format, ... )
{
    if ( i_verbose >= VERB_INFO )
    {
        va_list args;
        char psz_fmt[MAX_MSG];
        va_start( args, psz_format );

        snprintf( psz_fmt, MAX_MSG, "info: %s\n", psz_format );
        vfprintf( stderr, psz_fmt, args );
    }
}

/*****************************************************************************
 * msg_Err
 *****************************************************************************/
void msg_Err( void *_unused, const char *psz_format, ... )
{
    va_list args;
    char psz_fmt[MAX_MSG];
    va_start( args, psz_format );

    snprintf( psz_fmt, MAX_MSG, "error: %s\n", psz_format );
    vfprintf( stderr, psz_fmt, args );
}

/*****************************************************************************
 * msg_Warn
 *****************************************************************************/
void msg_Warn( void *_unused, const char *psz_format, ... )
{
    if ( i_verbose >= VERB_WARN )
    {
        va_list args;
        char psz_fmt[MAX_MSG];
        va_start( args, psz_format );

        snprintf( psz_fmt, MAX_MSG, "warning: %s\n", psz_format );
        vfprintf( stderr, psz_fmt, args );
    }
}

/*****************************************************************************
 * msg_Dbg
 *****************************************************************************/
void msg_Dbg( void *_unused, const char *psz_format, ... )
{
    if ( i_verbose >= VERB_DBG )
    {
        va_list args;
        char psz_fmt[MAX_MSG];
        va_start( args, psz_format );

        snprintf( psz_fmt, MAX_MSG, "debug: %s\n", psz_format );
        vfprintf( stderr, psz_fmt, args );
    }
}

/*****************************************************************************
 * msg_Raw
 *****************************************************************************/
void msg_Raw( void *_unused, const char *psz_format, ... )
{
    va_list args;
    char psz_fmt[MAX_MSG];
    va_start( args, psz_format );

    snprintf( psz_fmt, MAX_MSG, "%s\n", psz_format );
    vfprintf( stderr, psz_fmt, args );
}

/*****************************************************************************
 * wall_Date: returns a 27 MHz timestamp
 *****************************************************************************/
uint64_t wall_Date( void )
{
#if defined (HAVE_CLOCK_NANOSLEEP)
    struct timespec ts;

    /* Try to use POSIX monotonic clock if available */
    if( clock_gettime( CLOCK_MONOTONIC, &ts ) == EINVAL )
        /* Run-time fallback to real-time clock (always available) */
        (void)clock_gettime( CLOCK_REALTIME, &ts );

    return ((uint64_t)ts.tv_sec * (uint64_t)27000000)
            + (uint64_t)(ts.tv_nsec * 27 / 1000);
#else
    struct timeval tv_date;

    /* gettimeofday() could return an error, and should be tested. However, the
     * only possible error, according to 'man', is EFAULT, which can not happen
     * here, since tv is a local variable. */
    gettimeofday( &tv_date, NULL );
    return( (uint64_t) tv_date.tv_sec * 27000000 + (uint64_t) tv_date.tv_usec * 27 );
#endif
}

/*****************************************************************************
 * wall_Sleep
 *****************************************************************************/
void wall_Sleep( uint64_t i_delay )
{
    struct timespec ts;
    ts.tv_sec = i_delay / 27000000;
    ts.tv_nsec = (i_delay % 27000000) * 1000 / 27;

#if defined( HAVE_CLOCK_NANOSLEEP )
    int val;
    while ( ( val = clock_nanosleep( CLOCK_MONOTONIC, 0, &ts, &ts ) ) == EINTR );
    if( val == EINVAL )
    {
        ts.tv_sec = i_delay / 27000000;
        ts.tv_nsec = (i_delay % 27000000) * 1000 / 27;
        while ( clock_nanosleep( CLOCK_REALTIME, 0, &ts, &ts ) == EINTR );
    }
#else
    while ( nanosleep( &ts, &ts ) && errno == EINTR );
#endif
}

/*****************************************************************************
 * PrintSocket: print socket characteristics for debug purposes
 *****************************************************************************/
static void PrintSocket( const char *psz_text, struct sockaddr_in *p_bind,
                         struct sockaddr_in *p_connect )
{
    msg_Dbg( NULL, "%s bind:%s:%u", psz_text,
             inet_ntoa( p_bind->sin_addr ), ntohs( p_bind->sin_port ) );
    msg_Dbg( NULL, "%s connect:%s:%u", psz_text,
             inet_ntoa( p_connect->sin_addr ), ntohs( p_connect->sin_port ) );
}

/*****************************************************************************
 * ParseHost: parse a host:port string
 *****************************************************************************/
static int ParseHost( struct sockaddr_in *p_sock, char *psz_host )
{
    char *psz_token = strrchr( psz_host, ':' );
    if ( psz_token )
    {
        char *psz_parser;
        *psz_token++ = '\0';
        p_sock->sin_port = htons( strtol( psz_token, &psz_parser, 0 ) );
        if ( *psz_parser ) return -1;
    }
    else
        p_sock->sin_port = htons( DEFAULT_PORT );

    if ( !*psz_host )
        p_sock->sin_addr.s_addr = INADDR_ANY;
    else if ( !inet_aton( psz_host, &p_sock->sin_addr ) )
        return -1;

    return 0;
}

/*****************************************************************************
 * OpenSocket: parse argv and open sockets
 *****************************************************************************/
int OpenSocket( const char *_psz_arg, int i_ttl, unsigned int *pi_weight )
{
    char *psz_token;
    struct sockaddr_in bind_addr, connect_addr;
    int i_fd, i;
    char *psz_arg = strdup(_psz_arg);

    bind_addr.sin_family = connect_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = connect_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = connect_addr.sin_port = 0;

    psz_token = strrchr( psz_arg, ',' );
    if ( psz_token )
    {
        *psz_token++ = '\0';
        if ( pi_weight )
            *pi_weight = strtoul( psz_token, NULL, 0 );
    }
    else if ( pi_weight )
        *pi_weight = 1;

    psz_token = strrchr( psz_arg, '@' );
    if ( psz_token )
    {
        *psz_token++ = '\0';
        if ( ParseHost( &bind_addr, psz_token ) < 0 )
        {
            free(psz_arg);
            return -1;
        }
    }

    if ( psz_arg[0] && ParseHost( &connect_addr, psz_arg ) < 0 )
    {
        free(psz_arg);
        return -1;
    }
    free( psz_arg );

    if ( (i_fd = socket( AF_INET, SOCK_DGRAM, 0 )) < 0 )
    {
        msg_Err( NULL, "unable to open socket (%s)", strerror(errno) );
        exit(EXIT_FAILURE);
    }

    i = 1;
    if ( setsockopt( i_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&i,
                     sizeof(i) ) == -1 )
    {
        msg_Err( NULL, "unable to set socket (%s)", strerror(errno) );
        exit(EXIT_FAILURE);
    }

    /* Increase the receive buffer size to 1/2MB (8Mb/s during 1/2s) to avoid
     * packet loss caused by scheduling problems */
    i = 0x80000;
    setsockopt( i_fd, SOL_SOCKET, SO_RCVBUF, (void *) &i, sizeof( i ) );

    if ( bind( i_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr) ) < 0 )
    {
        msg_Err( NULL, "couldn't bind" );
        PrintSocket( "socket definition:", &bind_addr, &connect_addr );
        exit(EXIT_FAILURE);
    }

    /* Join the multicast group if the socket is a multicast address */
    if ( IN_MULTICAST( ntohl(bind_addr.sin_addr.s_addr)) )
    {
        struct ip_mreq imr;

        imr.imr_multiaddr.s_addr = bind_addr.sin_addr.s_addr;
        imr.imr_interface.s_addr = INADDR_ANY; /* FIXME could be an option */

        /* Join Multicast group without source filter */
        if ( setsockopt( i_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         (char *)&imr, sizeof(struct ip_mreq) ) == -1 )
        {
            msg_Err( NULL, "couldn't join multicast group" );
            PrintSocket( "socket definition:", &bind_addr, &connect_addr );
            exit(EXIT_FAILURE);
        }
    }

    if ( connect_addr.sin_addr.s_addr )
    {
        if ( connect( i_fd, (struct sockaddr *)&connect_addr,
                      sizeof(connect_addr) ) < 0 )
        {
            msg_Err( NULL, "cannot connect socket (%s)",
                     strerror(errno) );
            PrintSocket( "socket definition:", &bind_addr, &connect_addr );
            exit(EXIT_FAILURE);
        }

        if ( IN_MULTICAST( ntohl(connect_addr.sin_addr.s_addr) ) && i_ttl )
        {
            if ( setsockopt( i_fd, IPPROTO_IP, IP_MULTICAST_TTL,
                             (void *)&i_ttl, sizeof(i_ttl) ) == -1 )
            {
                msg_Err( NULL, "couldn't set TTL" );
                PrintSocket( "socket definition:", &bind_addr, &connect_addr );
                exit(EXIT_FAILURE);
            }
        }
    }

    return i_fd;
}

/*****************************************************************************
 * OpenFile: parse argv and open file descriptors
 *****************************************************************************/
int OpenFile( const char *psz_arg, bool b_read, bool b_append, bool *pb_stream )
{
    struct stat sb;
    int i_fd;
    int i_mode = b_read ? O_RDONLY : O_WRONLY;

    if ( stat( psz_arg, &sb ) < 0 )
    {
        if ( b_read )
        {
            msg_Err( NULL, "file %s doesn't exist (%s)", psz_arg,
                     strerror(errno) );
            exit(EXIT_FAILURE);
        }
        *pb_stream = false;
        i_mode |= O_CREAT;
    }
    else if ( S_ISCHR(sb.st_mode) || S_ISFIFO(sb.st_mode) )
    {
        *pb_stream = true;
    }
    else
    {
        *pb_stream = false;
        if ( !b_read )
        {
            if ( b_append )
                i_mode |= O_APPEND;
            else
                i_mode |= O_TRUNC;
        }
    }

    if ( (i_fd = open( psz_arg, i_mode, 0644 )) < 0 )
    {
        msg_Err( NULL, "couldn't open file %s (%s)", psz_arg, strerror(errno) );
        exit(EXIT_FAILURE);
    }

    return i_fd;
}

/*****************************************************************************
 * OpenAuxFile
 *****************************************************************************/
FILE *OpenAuxFile( const char *psz_arg, bool b_read, bool b_append )
{
    char psz_aux[strlen(psz_arg) + strlen(PSZ_AUX_EXT) + 2];
    char *psz_token;
    FILE *p_aux;

    strcpy( psz_aux, psz_arg );
    psz_token = strrchr( psz_aux, '.' );
    if ( psz_token ) *psz_token = '\0';
    strcat( psz_aux, "." PSZ_AUX_EXT );

    if ( (p_aux = fopen( psz_aux,
                           b_read ? "rb" : (b_append ? "ab" : "wb") )) < 0 )
    {
        msg_Err( NULL, "couldn't open file %s (%s)", psz_aux,
                 strerror(errno) );
        exit(EXIT_FAILURE);
    }

    return p_aux;
}
