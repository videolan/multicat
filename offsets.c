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
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include "util.h"

/*****************************************************************************
 * Entry point
 *****************************************************************************/
int main( int i_argc, char **pp_argv )
{
    int64_t i_wanted;
    off_t i_ret;

    if ( i_argc != 3 )
    {
        msg_Err( NULL, "Usage: offsets <aux file> <27 MHz timestamp>" );
        msg_Err( NULL, "[offsets is deprecated, see multicat instead]" );
        exit(EXIT_FAILURE);
    }

    i_wanted = strtoll( pp_argv[2], NULL, 0 );
    if ( !i_wanted )
    {
        printf( "0\n" );
        exit(EXIT_SUCCESS);
    }

    i_ret = LookupAuxFile( pp_argv[1], i_wanted, false );
    if ( i_ret == -1 )
        exit(EXIT_FAILURE);

    printf( "%jd\n", (intmax_t)i_ret );

    exit(EXIT_SUCCESS);
}

