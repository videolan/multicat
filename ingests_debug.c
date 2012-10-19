/*****************************************************************************
 * ingests_debug.c: debug aux files
 *****************************************************************************
 * Copyright (C) 2012 VideoLAN
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include "util.h"

#define MAX_DIFF (10 * 27000)
#define MIN_DIFF (27000)

/*****************************************************************************
 * Entry point
 *****************************************************************************/
int main( int i_argc, char **pp_argv )
{
    uint64_t i_last_stc = 0;
    uint64_t i_first = 0;
    for ( ; ; )
    {
        uint8_t p_aux[sizeof(uint64_t)];
        uint64_t i_stc;
        if (fread(p_aux, sizeof(p_aux), 1, stdin) <= 0)
            break;
        i_stc = FromSTC(p_aux);
        if (!i_first) i_first = i_stc;
        if (i_stc - i_last_stc > MAX_DIFF)
            fprintf(stderr, "%"PRIu64": diff exceeded %"PRId64"\n", (i_stc - i_first) / 27000, (i_stc - i_last_stc) / 27000);
        else if (i_stc - i_last_stc < MIN_DIFF)
            fprintf(stderr, "%"PRIu64": diff too low %"PRId64"\n", (i_stc - i_first) / 27000, (i_stc - i_last_stc) / 27000);
        i_last_stc = i_stc;
    }
    exit(EXIT_SUCCESS);
}

