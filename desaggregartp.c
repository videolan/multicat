/*****************************************************************************
 * desaggregartp.c: rebuild an RTP stream from several aggregated links
 *****************************************************************************
 * Copyright (C) 2009 VideoLAN
 * $Id: desaggregartp.c 48 2007-11-30 14:08:21Z cmassiot $
 *
 * Authors: Christophe Massiot <massiot@via.ecp.fr>
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
#include <poll.h>

#include "util.h"

#define POW2_32 UINT32_MAX
#define DEFAULT_BUFFER_LENGTH 200 /* ms */
#define DEFAULT_MTU 1500
#define MAX_INPUTS 4

/* Maximum gap allowed between two CRs. */
#define CR_MAX_GAP 300 /* ms */
#define CR_MAX_JITTER 100 /* ms */
#define CR_AVERAGE 150

/*****************************************************************************
 * Local declarations
 *****************************************************************************/
typedef struct block_t
{
    uint8_t *p_data;
    unsigned int i_size;
    uint64_t i_date;
    struct block_t *p_next, *p_prev;
} block_t;

static int i_output_fd;
static int pi_inputs_fd[MAX_INPUTS];
static int i_nb_inputs = 0;
static int b_udp = 0;

block_t *p_first = NULL;
block_t *p_last = NULL;

typedef struct input_clock_t
{
    /* Synchronization information */
    int64_t                 delta_cr;
    uint64_t                 cr_ref, wall_ref;
    uint64_t                 last_cr; /* reference to detect unexpected stream
                                       * discontinuities                     */
} input_clock_t;

static input_clock_t input_clock;

static uint64_t i_last_timestamp = POW2_32; /* not 27 MHz, but RTP-native */
static uint64_t i_buffer_length = DEFAULT_BUFFER_LENGTH * 27000;

static void usage(void)
{
    msg_Raw( NULL, "Usage: desaggregartp [-i <RT priority>] [-t <ttl>] [-b <buffer length>] [-U] [-m <mtu>] <src host 1> ... [<src host N>] <dest host>" );
    msg_Raw( NULL, "    host format: [<connect addr>[:<connect port>]][@[<bind addr][:<bind port>]]" );
    msg_Raw( NULL, "    -U: strip RTP header" );
    msg_Raw( NULL, "    -b: buffer length in ms" );
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
    int64_t i_clock_diff = input_clock.last_cr - i_clock;

    if ( i_clock_diff > (CR_MAX_GAP * 27000)
      || i_clock_diff < -(CR_MAX_GAP * 27000) )
    {
        msg_Warn( NULL, "clock gap, unexpected stream discontinuity %lld",
                  i_clock_diff );
        clock_Init();
        input_clock.cr_ref = input_clock.last_cr = i_clock;
        input_clock.wall_ref = i_wall;
        return;
    }

    input_clock.last_cr = i_clock;

    /* Smooth clock reference variations. */
    i_extrapoled_clock = input_clock.cr_ref
                          + i_wall - input_clock.wall_ref;
    i_clock_diff = i_extrapoled_clock - i_clock;

    if ( (i_clock_diff - input_clock.delta_cr) > (CR_MAX_JITTER * 27000)
      || (i_clock_diff - input_clock.delta_cr) < -(CR_MAX_JITTER * 27000) )
    {
        msg_Warn( NULL, "too much jitter %lld",
                  i_clock_diff - input_clock.delta_cr );
        clock_Init();
        input_clock.cr_ref = input_clock.last_cr = i_clock;
        input_clock.wall_ref = i_wall;
        return;
    }

    /* Bresenham algorithm to smooth variations. */
    input_clock.delta_cr = (input_clock.delta_cr * (CR_AVERAGE - 1)
                             + i_clock_diff) / CR_AVERAGE;
}

/*****************************************************************************
 * Packet handlers
 *****************************************************************************/
static void SendPacket(void)
{
    block_t *p_block = p_first;
    uint8_t *p_data, *p_end;

    p_first = p_block->p_next;
    if ( p_first == NULL )
        p_last = NULL;
    else
        p_first->p_prev = NULL;

    if ( b_udp )
        p_data = rtp_GetPayload( p_block->p_data );
    else
        p_data = p_block->p_data;
    p_end = p_block->p_data + p_block->i_size;

    if ( write( i_output_fd, p_data, p_end - p_data ) < 0 )
        msg_Warn( NULL, "write error (%s)", strerror(errno) );
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

static void RecvPacket( block_t *p_block, uint64_t i_date )
{
    uint64_t i_scaled_timestamp;

    if ( !rtp_CheckHdr( p_block->p_data ) )
    {
        msg_Warn( NULL, "non-RTP packet received" );
        free( p_block );
        return;
    }

    BuildTimestamp( rtp_GetTimestamp( p_block->p_data ) );

    switch ( rtp_GetType( p_block->p_data ) )
    {
    case 33: /* MPEG-2 TS: 90 kHz */
        i_scaled_timestamp = i_last_timestamp * 300;
        break;
    default: /* assume milliseconds */
        i_scaled_timestamp = i_last_timestamp * 27000;
        break;
    }

    clock_NewRef( i_scaled_timestamp, i_date );
    p_block->i_date = clock_ToWall( i_scaled_timestamp ) + i_buffer_length;

    /* Insert the block at the correct position */
    if ( p_last == NULL )
    {
        p_first = p_last = p_block;
        p_block->p_prev = p_block->p_next = NULL;
    }
    else
    {
        block_t *p_prev = p_last;
        while ( p_prev != NULL && p_prev->i_date > p_block->i_date )
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
    int i_ttl = 0;
    int i_mtu = DEFAULT_MTU;
    struct pollfd pfd[MAX_INPUTS];

    while ( (c = getopt( i_argc, pp_argv, "i:t:b:Um:h" )) != -1 )
    {
        switch ( c )
        {
        case 'i':
            i_priority = strtol( optarg, NULL, 0 );
            break;

        case 't':
            i_ttl = strtol( optarg, NULL, 0 );
            break;

        case 'b':
            i_buffer_length = strtoll( optarg, NULL, 0 ) * 1000;
            break;

        case 'U':
            b_udp = 1;
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

    i_nb_inputs = 0;
    while ( optind < i_argc - 1 && i_nb_inputs < MAX_INPUTS )
    {
        pi_inputs_fd[i_nb_inputs] = OpenSocket( pp_argv[optind++], 0, NULL );
        pfd[i_nb_inputs].fd = pi_inputs_fd[i_nb_inputs];
        pfd[i_nb_inputs].events = POLLIN;
        i_nb_inputs++;
    }
    if ( optind < i_argc - 1 )
    {
        msg_Err( NULL, "max number of inputs: %d (recompile)", MAX_INPUTS );
        exit(EXIT_FAILURE);
    }
    msg_Dbg( NULL, "%d inputs", i_nb_inputs );

    i_output_fd = OpenSocket( pp_argv[optind], i_ttl, NULL );
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
            SendPacket();

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
            if ( pfd[i].revents & POLLIN )
            {
                block_t *p_block = malloc( sizeof(block_t) + i_mtu );
                ssize_t i_size;

                p_block->p_data = (uint8_t *)p_block + sizeof(block_t);
                i_size = read( pi_inputs_fd[i], p_block->p_data, i_mtu );
                if ( i_size < 0 && errno != EAGAIN && errno != EINTR )
                {
                    msg_Err( NULL, "unrecoverable read error, dying (%s)",
                             strerror(errno) );
                    exit(EXIT_FAILURE);
                }
                if ( i_size <= 0 )
                {
                    free( p_block );
                    continue;
                }

                p_block->i_size = i_size;
                RecvPacket( p_block, i_current_date );
            }
        }
    }

    return EXIT_SUCCESS;
}

