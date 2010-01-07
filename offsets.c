/*****************************************************************************
 * offsets.c: find position in an aux file
 *****************************************************************************
 * Copyright (C) 2009 VideoLAN
 * $Id: offsets.c 10 2005-11-16 18:09:00Z cmassiot $
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

/*****************************************************************************
 * Entry point
 *****************************************************************************/
int main( int i_argc, char **pp_argv )
{
    uint8_t *p_aux;
    uint64_t i_wanted;
    off_t i_offset1 = 0, i_offset2;
    int i_stc_fd;
    struct stat stc_stat;
    uint64_t i_stc0;

    if ( i_argc != 3 )
    {
        fprintf( stderr, "Usage: offsets <aux file> <27 MHz timestamp>\n" );
        exit(EXIT_FAILURE);
    }

    i_wanted = strtoull( pp_argv[2], NULL, 0 );
    if ( !i_wanted )
    {
        printf( "0\n" );
        exit(EXIT_SUCCESS);
    }

    if ( (i_stc_fd = open( pp_argv[1], O_RDONLY )) == -1 )
    {
        fprintf( stderr, "unable to open %s (%s)\n", pp_argv[1],
                 strerror(errno) );
        exit(EXIT_FAILURE);
    }

    if ( fstat( i_stc_fd, &stc_stat ) == -1 )
    {
        fprintf( stderr, "unable to stat %s (%s)\n", pp_argv[1],
                 strerror(errno) );
        exit(EXIT_FAILURE);
    }

    p_aux = mmap( NULL, stc_stat.st_size, PROT_READ, MAP_SHARED,
                  i_stc_fd, 0 );
    if ( p_aux == MAP_FAILED )
    {
        fprintf( stderr, "unable to mmap %s (%s)\n", pp_argv[1],
                 strerror(errno) );
        exit(EXIT_FAILURE);
    }

    if ( p_aux[0] == 0x47 && p_aux[188] == 0x47 && p_aux[376] == 0x47 )
    {
        fprintf( stderr, "this is a TS file, not an aux file\n" );
        exit(EXIT_FAILURE);
    }

    i_offset2 = stc_stat.st_size / sizeof(uint64_t);
    i_stc0 = ((uint64_t)p_aux[0] << 56)
              | ((uint64_t)p_aux[1] << 48)
              | ((uint64_t)p_aux[2] << 40)
              | ((uint64_t)p_aux[3] << 32)
              | ((uint64_t)p_aux[4] << 24)
              | ((uint64_t)p_aux[5] << 16)
              | ((uint64_t)p_aux[6] << 8)
              | ((uint64_t)p_aux[7] << 0);

    for ( ; ; )
    {
        off_t i_mid_offset = (i_offset1 + i_offset2) / 2;
        uint8_t *p_mid_aux = p_aux + i_mid_offset * sizeof(uint64_t);
        uint64_t i_mid_stc = ((uint64_t)p_mid_aux[0] << 56)
                              | ((uint64_t)p_mid_aux[1] << 48)
                              | ((uint64_t)p_mid_aux[2] << 40)
                              | ((uint64_t)p_mid_aux[3] << 32)
                              | ((uint64_t)p_mid_aux[4] << 24)
                              | ((uint64_t)p_mid_aux[5] << 16)
                              | ((uint64_t)p_mid_aux[6] << 8)
                              | ((uint64_t)p_mid_aux[7] << 0);


        if ( i_offset1 == i_mid_offset )
            break;

        if ( i_mid_stc - i_stc0 >= i_wanted )
            i_offset2 = i_mid_offset;
        else
            i_offset1 = i_mid_offset;
    }

    munmap( p_aux, stc_stat.st_size );
    close( i_stc_fd );

    printf( "%jd\n", (intmax_t)i_offset2 );

    exit(EXIT_SUCCESS);
}

