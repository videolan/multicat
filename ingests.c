/*****************************************************************************
 * ingests.c: create the aux file for a transport stream file
 *****************************************************************************
 * Copyright (C) 2009, 2011 VideoLAN
 * $Id: ingests.c 52 2009-10-06 16:48:00Z cmassiot $
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <bitstream/mpeg/ts.h>

#include "util.h"

/*****************************************************************************
 * Local declarations
 *****************************************************************************/
#define READ_ONCE 100
#define MAX_PCR_GAP (500ULL * 27000ULL) /* that's 500 ms */

#define POW2_33 8589934592ULL

static uint16_t i_pcr_pid = 0;
static size_t i_ts_in_payload = DEFAULT_PAYLOAD_SIZE / TS_SIZE;

static int i_fd;
static FILE *p_output_aux;
static int i_ts_read = 0;

static bool b_init = true;
static int i_ts_since_output = 0;
static uint64_t i_last_pcr = POW2_33 * 300;
static uint64_t i_last_pcr_diff = 0;
static int i_last_nb_payloads = 0;
static uint64_t i_last_stc = 0;

static void usage(void)
{
    msg_Raw( NULL, "Usage: ingests -p <PCR PID> [-m <payload size>] <input ts>" );
    exit(EXIT_FAILURE);
}

/*****************************************************************************
 * OutputAux: date payload packets
 *****************************************************************************/
static void OutputAux( int i_nb_payloads, uint64_t i_duration )
{
    uint8_t p_aux[i_nb_payloads*sizeof(uint64_t)];
    int i;

    for ( i = 0; i < i_nb_payloads; i++ )
    {
        uint64_t i_stc = i_last_stc + i_duration * (i + 1) / i_nb_payloads;

        p_aux[8 * i + 0] = i_stc >> 56;
        p_aux[8 * i + 1] = (i_stc >> 48) & 0xff;
        p_aux[8 * i + 2] = (i_stc >> 40) & 0xff;
        p_aux[8 * i + 3] = (i_stc >> 32) & 0xff;
        p_aux[8 * i + 4] = (i_stc >> 24) & 0xff;
        p_aux[8 * i + 5] = (i_stc >> 16) & 0xff;
        p_aux[8 * i + 6] = (i_stc >> 8) & 0xff;
        p_aux[8 * i + 7] = (i_stc >> 0) & 0xff;
    }
    i_last_stc += i_duration;

    if ( fwrite( p_aux, 8, i_nb_payloads, p_output_aux ) != i_nb_payloads )
        msg_Err( NULL, "couldn't write to auxiliary file" );
}

/*****************************************************************************
 * Output: date as many payload packets as possible
 *****************************************************************************/
static void Output(void)
{
    int i_nb_payloads = (i_ts_since_output + i_ts_in_payload - 1)
                          / i_ts_in_payload;

    if ( i_ts_since_output <= 0 )
        return;

    if ( b_init )
    {
        /* Emulate CBR */
        OutputAux( i_last_nb_payloads,
                   i_last_pcr_diff * i_last_nb_payloads / i_nb_payloads );
        b_init = false;
    }

    OutputAux( i_nb_payloads, i_last_pcr_diff );
    i_ts_since_output -= i_nb_payloads * i_ts_in_payload;
    i_last_nb_payloads = i_nb_payloads;
}

/*****************************************************************************
 * OutputFirst: manipulate structures to emulate CBR at the beginning
 *****************************************************************************/
static void OutputFirst(void)
{
    i_last_nb_payloads = (i_ts_since_output + i_ts_in_payload - 1)
                          / i_ts_in_payload;
    i_ts_since_output -= i_last_nb_payloads * i_ts_in_payload;
}

/*****************************************************************************
 * OutputFirst: emulate CBR at the end
 *****************************************************************************/
static void OutputLast(void)
{
    int i_nb_payloads = (i_ts_since_output + i_ts_in_payload - 1)
                          / i_ts_in_payload;
    OutputAux( i_nb_payloads,
               i_last_pcr_diff * i_nb_payloads / i_last_nb_payloads );
}

/*****************************************************************************
 * TSHandle: find a PCR and stamp packets
 *****************************************************************************/
static void TSHandle( uint8_t *p_ts )
{
    uint16_t i_pid = ts_get_pid( p_ts );

    if ( !ts_validate( p_ts ) )
    {
        msg_Err( NULL, "lost TS synchro, go and fix your file (pos=%llu)",
                 (uint64_t)i_ts_read * TS_SIZE );
        exit(EXIT_FAILURE);
    }

    i_ts_since_output++;

    if ( (i_pid == i_pcr_pid || i_pcr_pid == 8192)
          && ts_has_adaptation(p_ts) && ts_get_adaptation(p_ts)
          && tsaf_has_pcr(p_ts) )
    {
        uint64_t i_pcr = tsaf_get_pcr( p_ts ) * 300 + tsaf_get_pcrext( p_ts );

        if ( i_last_pcr == POW2_33 * 300 ) /* init */
        {
            i_last_pcr = i_pcr;
            OutputFirst();
            return;
        }
        if ( (POW2_33 * 300 + i_pcr) - i_last_pcr < MAX_PCR_GAP )
            /* Clock wrapped */
            i_last_pcr_diff = POW2_33 * 300 + i_pcr - i_last_pcr;
        else if ( (i_pcr <= i_last_pcr) ||
                  (i_pcr - i_last_pcr > MAX_PCR_GAP) )
            /* Do not change the slope - consider CBR */
            msg_Warn( NULL, "PCR discontinuity (%llu->%llu, pos=%llu)",
                      i_last_pcr, i_pcr, (uint64_t)i_ts_read * TS_SIZE );
        else
            i_last_pcr_diff = i_pcr - i_last_pcr;

        i_last_pcr = i_pcr;
        Output();
    }
}

/*****************************************************************************
 * Entry point
 *****************************************************************************/
int main( int i_argc, char **pp_argv )
{
    uint8_t *p_buffer;
    unsigned int i_payload_size = DEFAULT_PAYLOAD_SIZE;
    mode_t i_mode;

    for ( ; ; )
    {
        char c;

        if ( (c = getopt(i_argc, pp_argv, "p:m:h")) == -1 )
            break;

        switch ( c )
        {
        case 'p':
            i_pcr_pid = strtoul(optarg, NULL, 0);
            break;

        case 'm':
            i_payload_size = strtoul(optarg, NULL, 0);
            i_ts_in_payload = i_payload_size / TS_SIZE;
            if ( i_payload_size % TS_SIZE )
            {
                msg_Err( NULL, "payload size must be a multiple of 188" );
                exit(EXIT_FAILURE);
            }
            break;

        case 'h':
        default:
            usage();
            break;
        }
    }
    if ( optind >= i_argc || !i_pcr_pid )
        usage();

    i_mode = StatFile( pp_argv[optind] );
    if ( S_ISCHR( i_mode ) || S_ISFIFO( i_mode ) || S_ISDIR( i_mode ) )
        usage();
    i_fd = OpenFile( pp_argv[optind], true, false );

    char *psz_aux_file = GetAuxFile( pp_argv[optind], i_payload_size );
    p_output_aux = OpenAuxFile( psz_aux_file, false, false );
    free( psz_aux_file );

    p_buffer = malloc( TS_SIZE * READ_ONCE );

    for ( ; ; )
    {
        int i;
        ssize_t i_ret;

        if ( (i_ret = read( i_fd, p_buffer, TS_SIZE * READ_ONCE )) < 0 )
        {
            msg_Err( NULL, "read error (%s)", strerror(errno) );
            break;
        }
        if ( i_ret == 0 )
        {
            msg_Dbg( NULL, "end of file reached" );
            break;
        }

        for ( i = 0; i < i_ret / TS_SIZE; i++ )
        {
            TSHandle( p_buffer + TS_SIZE * i );
            i_ts_read++;
        }
    }

    free( p_buffer );
    if ( !i_last_pcr_diff )
        msg_Err( NULL, "no PCR found" );
    else
        OutputLast(); /* Emulate CBR */
    fclose( p_output_aux );
    close( i_fd );

    return 0;
}

