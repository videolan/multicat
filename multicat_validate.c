/*****************************************************************************
 * multicat_validate.c: validate position in directory input
 *****************************************************************************
 * Copyright (C) 2009, 2011, 2015-2016 VideoLAN
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
#include <syslog.h>

#include "util.h"

#define DEFAULT_TOLERANCE 27000000ULL

/*****************************************************************************
 * Local declarations
 *****************************************************************************/
static uint64_t i_rotate_size = DEFAULT_ROTATE_SIZE;
static uint64_t i_rotate_offset = DEFAULT_ROTATE_OFFSET;
static int64_t i_tolerance = DEFAULT_TOLERANCE;
static size_t i_asked_payload_size = DEFAULT_PAYLOAD_SIZE;
static int64_t i_delay = 0;
static const char *psz_dir_name;
static uint64_t i_dir_file;
static bool b_status = false;

static void usage(void)
{
    msg_Raw( NULL, "Usage: multicat_validate [-l <syslogtag>] [-k <start time>] [-r <file duration>] [-O <rotate offset>] [-W <tolerance>] [-m <payload size>] <input directory>" );
    msg_Raw( NULL, "    -k: start at the given position (in 27 MHz units, negative = from the end)" );
    msg_Raw( NULL, "    -r: in directory mode, rotate file after this duration (default: 97200000000 ticks = 1 hour)" );
    msg_Raw( NULL, "    -O: in directory mode, rotate file after duration + this offset (default: 0 tick = calendar hour)" );
    msg_Raw( NULL, "    -W: maximum tolerated wait time before the forthcoming packet (by default: 27000000 ticks = 1 second)" );
    msg_Raw( NULL, "    -m: size of the payload chunk, excluding optional RTP header (default 1316)" );
    exit(EXIT_FAILURE);
}

static void HandleSTC( uint64_t i_stc )
{
    uint64_t i_wall;
    int64_t i_sleep;
retry:
    i_wall = real_Date() - i_delay;
    i_sleep = (int64_t)i_stc - (int64_t)i_wall;

    if ( i_sleep > (int64_t)i_rotate_size )
    {
        msg_Err( NULL, "invalid aux file %"PRIu64" (stc %"PRIu64")",
                 i_dir_file, i_stc );
        exit(1);
    }

    if ( i_sleep > i_tolerance )
    {
        if ( b_status )
        {
            printf( "0\n" );
            b_status = false;
        }

        real_Sleep( i_sleep - i_tolerance );
        goto retry;
    }

    if ( !b_status )
        printf( "1\n" );
    b_status = true;

    if ( i_sleep > 0 )
        real_Sleep( i_sleep );
}

/*****************************************************************************
 * Entry point
 *****************************************************************************/
int main( int i_argc, char **pp_argv )
{
    const char *psz_syslog_tag = NULL;
    off_t i_nb_skipped_chunks;
    FILE *p_input_aux;
    int c;
    uint64_t i_stc;

    setvbuf(stdout, NULL, _IOLBF, 0);

    while ( (c = getopt( i_argc, pp_argv, "l:k:r:O:W:m:h" )) != -1 )
    {
        switch ( c )
        {
        case 'l':
            psz_syslog_tag = optarg;
            break;

        case 'k':
            i_delay = strtoull( optarg, NULL, 0 );
            break;

        case 'r':
            i_rotate_size = strtoull( optarg, NULL, 0 );
            break;

        case 'O':
            i_rotate_offset = strtoull( optarg, NULL, 0 );
            break;

        case 'W':
            i_tolerance = strtoull( optarg, NULL, 0 );
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
    if ( optind >= i_argc )
        usage();
    psz_dir_name = pp_argv[optind];
    printf( "0\n" );

    if ( psz_syslog_tag != NULL )
        msg_Openlog( psz_syslog_tag, LOG_NDELAY, LOG_USER );

    if ( i_delay <= 0 )
    {
        i_delay *= -1;
        i_stc = real_Date() - i_delay;
    }
    else
    {
        i_stc = i_delay;
        i_delay = real_Date() - i_stc;
    }

    i_dir_file = GetDirFile( i_rotate_size, i_rotate_offset, i_stc );
    i_nb_skipped_chunks = LookupDirAuxFile( psz_dir_name, i_dir_file, i_stc,
                                            i_asked_payload_size );
    if ( i_nb_skipped_chunks < 0 )
    {
        /* Try at most one more chunk */
        i_dir_file++;
        i_nb_skipped_chunks = LookupDirAuxFile( psz_dir_name, i_dir_file, i_stc,
                                                i_asked_payload_size );
        if ( i_nb_skipped_chunks < 0 )
        {
            msg_Err( NULL, "position not found" );
            exit(1);
        }
    }

    close( OpenDirFile( psz_dir_name, i_dir_file, true, i_asked_payload_size,
                        &p_input_aux ) );

    int ret = fseeko( p_input_aux, 8 * i_nb_skipped_chunks, SEEK_SET );
    if ( ret == -1 )
    {
        msg_Err( NULL, "fseeko failed" );
        exit(1);
    }

    for ( ; ; )
    {
        uint8_t p_aux[8];

        if ( fread( p_aux, 8, 1, p_input_aux ) != 1 )
        {
            int i_fd;
            fclose( p_input_aux );

            i_dir_file++;

            i_fd = OpenDirFile( psz_dir_name, i_dir_file, true,
                                i_asked_payload_size, &p_input_aux );
            if ( i_fd < 0 )
            {
                msg_Err( NULL, "end of files reached" );
                exit(1);
            }
            close( i_fd );
        }
        i_stc = FromSTC( p_aux );

        HandleSTC( i_stc );
    }

    if ( psz_syslog_tag != NULL )
        msg_Closelog();
}
