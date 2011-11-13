/*****************************************************************************
 * lasts.c: give the duration of an aux file
 *****************************************************************************
 * Copyright (C) 2009, 2011 VideoLAN
 * $Id: lasts.c 10 2005-11-16 18:09:00Z cmassiot $
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
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/*****************************************************************************
 * Entry point
 *****************************************************************************/
int main(int i_argc, char **ppsz_argv)
{
    uint64_t i_stc0, i_stcn;
    uint8_t p_aux[8];
    int i_fd;

    if (i_argc != 2 || !strcmp(ppsz_argv[1], "-h") ||
        !strcmp(ppsz_argv[1], "--help"))
    {
        fprintf(stderr, "Usage: lasts <aux file>");
        exit(EXIT_FAILURE);
    }

    i_fd = open(ppsz_argv[1], O_RDONLY);
    if (i_fd == -1)
    {
        fprintf(stderr, "cannot open (%m)\n");
        exit(EXIT_FAILURE);
    }

    if (read(i_fd, p_aux, sizeof(p_aux)) != sizeof(p_aux))
    {
        fprintf(stderr, "cannot read (%m)\n");
        close(i_fd);
        exit(EXIT_FAILURE);
    }

    i_stc0 = ((uint64_t)p_aux[0] << 56)
          | ((uint64_t)p_aux[1] << 48)
          | ((uint64_t)p_aux[2] << 40)
          | ((uint64_t)p_aux[3] << 32)
          | ((uint64_t)p_aux[4] << 24)
          | ((uint64_t)p_aux[5] << 16)
          | ((uint64_t)p_aux[6] << 8)
          | ((uint64_t)p_aux[7] << 0);

    if (lseek(i_fd, -(off_t)sizeof(p_aux), SEEK_END) == -1)
    {
        fprintf(stderr, "cannot lseek (%m)\n");
        close(i_fd);
        exit(EXIT_FAILURE);
    }

    if (read(i_fd, p_aux, sizeof(p_aux)) != sizeof(p_aux))
    {
        fprintf(stderr, "cannot read (%m)\n");
        close(i_fd);
        exit(EXIT_FAILURE);
    }
    close(i_fd);

    i_stcn = ((uint64_t)p_aux[0] << 56)
          | ((uint64_t)p_aux[1] << 48)
          | ((uint64_t)p_aux[2] << 40)
          | ((uint64_t)p_aux[3] << 32)
          | ((uint64_t)p_aux[4] << 24)
          | ((uint64_t)p_aux[5] << 16)
          | ((uint64_t)p_aux[6] << 8)
          | ((uint64_t)p_aux[7] << 0);

    printf( "%"PRIu64"\n", i_stcn - i_stc0);

    exit(EXIT_SUCCESS);
}

