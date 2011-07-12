/*****************************************************************************
 * util.h: Utils for the multicat suite
 *****************************************************************************
 * Copyright (C) 2009 VideoLAN
 * $Id: multicat.h 65 2009-11-15 22:57:53Z massiot $
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

#define HAVE_CLOCK_NANOSLEEP

#define DEFAULT_PORT 1234
#define DEFAULT_PAYLOAD_SIZE 1316
#define DEFAULT_ROTATE_SIZE UINT64_C(97200000000)
#define TS_SIZE 188
#define RTP_HEADER_SIZE 12

#define VERB_DBG  3
#define VERB_INFO 2
#define VERB_WARN 1

/*****************************************************************************
 * Prototypes
 *****************************************************************************/
void msg_Info( void *_unused, const char *psz_format, ... );
void msg_Err( void *_unused, const char *psz_format, ... );
void msg_Warn( void *_unused, const char *psz_format, ... );
void msg_Dbg( void *_unused, const char *psz_format, ... );
void msg_Raw( void *_unused, const char *psz_format, ... );
uint64_t wall_Date( void );
void wall_Sleep( uint64_t i_delay );
uint64_t real_Date( void );
void real_Sleep( uint64_t i_delay );
int OpenSocket( const char *_psz_arg, int i_ttl, unsigned int *pi_weight );
mode_t StatFile(const char *psz_arg);
int OpenFile( const char *psz_arg, bool b_read, bool b_append );
char *GetAuxFile( const char *psz_arg, size_t i_payload_size );
FILE *OpenAuxFile( const char *psz_arg, bool b_read, bool b_append );
off_t LookupAuxFile( const char *psz_arg, int64_t i_wanted, bool b_absolute );
uint64_t GetDirFile( uint64_t i_rotate_size, int64_t i_wanted );
int OpenDirFile( const char *psz_dir_path, uint64_t i_file, bool b_read,
                 size_t i_payload_size, FILE **pp_aux_file );
off_t LookupDirAuxFile( const char *psz_dir_path, uint64_t i_file,
                        int64_t i_wanted, size_t i_payload_size );

/*****************************************************************************
 * Aux files helpers
 *****************************************************************************/
static inline uint64_t FromSTC( const uint8_t *p_aux )
{
    return ((uint64_t)p_aux[0] << 56)
         | ((uint64_t)p_aux[1] << 48)
         | ((uint64_t)p_aux[2] << 40)
         | ((uint64_t)p_aux[3] << 32)
         | ((uint64_t)p_aux[4] << 24)
         | ((uint64_t)p_aux[5] << 16)
         | ((uint64_t)p_aux[6] << 8)
         | ((uint64_t)p_aux[7] << 0);
}

static inline void ToSTC( uint8_t *p_aux, uint64_t i_stc )
{
    p_aux[0] = i_stc >> 56;
    p_aux[1] = (i_stc >> 48) & 0xff;
    p_aux[2] = (i_stc >> 40) & 0xff;
    p_aux[3] = (i_stc >> 32) & 0xff;
    p_aux[4] = (i_stc >> 24) & 0xff;
    p_aux[5] = (i_stc >> 16) & 0xff;
    p_aux[6] = (i_stc >> 8) & 0xff;
    p_aux[7] = (i_stc >> 0) & 0xff;
}

/*****************************************************************************
 * Miscellaneous RTP handlers
 *****************************************************************************/
/*
 * Reminder : RTP header
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |V=2|P|X|  CC   |M|     PT      |       sequence number         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           timestamp                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           synchronization source (SSRC) identifier            |
   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
   |            contributing source (CSRC) identifiers             |
   |                             ....                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

static inline bool rtp_CheckHdr( const uint8_t *p_hdr )
{
    return (p_hdr[0] & 0xc0) == 0x80;
}

static inline uint8_t rtp_GetType( const uint8_t *p_hdr )
{
    return p_hdr[1] & 0x7f;
}

static inline uint32_t rtp_GetTimestamp( uint8_t *p_hdr )
{
    return (p_hdr[4] << 24) | (p_hdr[5] << 16) | (p_hdr[6] << 8) | p_hdr[7];
}

static inline uint8_t *rtp_GetPayload( uint8_t *p_hdr )
{
    unsigned int i_size = RTP_HEADER_SIZE;
    i_size += 4 * (p_hdr[0] & 0xf);
    if ( p_hdr[0] & 0x10 ) /* header extension */
        i_size += 4 * (1 + (p_hdr[i_size + 2] << 8) + p_hdr[i_size + 3]);
    return p_hdr + i_size;
}

static inline void rtp_SetTimestamp( uint8_t *p_hdr, uint32_t i_timestamp )
{
    p_hdr[4] = (i_timestamp >> 24) & 0xff;
    p_hdr[5] = (i_timestamp >> 16) & 0xff;
    p_hdr[6] = (i_timestamp >> 8) & 0xff;
    p_hdr[7] = i_timestamp & 0xff;
}

static inline void rtp_SetSSRC( uint8_t *p_hdr, const uint8_t pi_ssrc[4] )
{
    p_hdr[8] = pi_ssrc[0];
    p_hdr[9] = pi_ssrc[1];
    p_hdr[10] = pi_ssrc[2];
    p_hdr[11] = pi_ssrc[3];
}

static inline void rtp_SetHdr( uint8_t *p_hdr, uint16_t i_rtp_cc )
{
    p_hdr[0] = 0x80;
    p_hdr[1] = 33; /* assume MPEG-2 ts */
    p_hdr[2] = i_rtp_cc >> 8;
    p_hdr[3] = i_rtp_cc & 0xff;
}

/*****************************************************************************
 * Miscellaneous TS handlers
 *****************************************************************************/
static inline bool ts_CheckSync( const uint8_t *p_ts )
{
    return p_ts[0] == 0x47;
}

static inline uint16_t ts_GetPID( const uint8_t *p_ts )
{
    return (((uint16_t)p_ts[1] & 0x1f) << 8) | p_ts[2];
}

static inline int ts_HasPCR( const uint8_t *p_ts )
{
    return ( p_ts[3] & 0x20 ) && /* adaptation field present */
           ( p_ts[4] >= 7 ) && /* adaptation field size */
           ( p_ts[5] & 0x10 ); /* has PCR */
}

static inline uint64_t ts_GetPCR( const uint8_t *p_ts )
{
    return ( (uint64_t)p_ts[6] << 25 ) |
           ( (uint64_t)p_ts[7] << 17 ) |
           ( (uint64_t)p_ts[8] << 9 ) |
           ( (uint64_t)p_ts[9] << 1 ) |
           ( (uint64_t)p_ts[10] >> 7 );
}

static inline uint64_t ts_GetPCRExt( const uint8_t *p_ts )
{
    return (((uint64_t)p_ts[10] & 1) << 8) | (uint64_t)p_ts[11];
}

static inline void ts_Pad( uint8_t *p_ts )
{
    p_ts[0] = 0x47;
    p_ts[1] = 0x1f;
    p_ts[2] = 0xff;
    p_ts[3] = 0x10;
    memset( p_ts + 4, 0xff, TS_SIZE - 4 );
};
