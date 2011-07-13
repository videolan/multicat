#!/bin/sh
###############################################################################
# multicat_expire.sh
###############################################################################
# Copyright (C) 2011 VideoLAN
# $Id: dvbiscovery.sh 178 2011-01-01 19:13:26Z massiot $
#
# Authors: Christophe Massiot <massiot@via.ecp.fr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
###############################################################################

usage() {
	echo "Usage: $0 <directory> <number of chunks>" >&2
	exit 1
}

if test $# -ne 2 -o "$1" = "-h" -o "$1" = "--help"; then
	usage
fi

DIR=$1
WANTED_CHUNKS=$2
NB_CHUNKS=`ls -f "$DIR/*.ts" | wc -l`

if test $NB_CHUNKS -gt $WANTED_CHUNKS; then
	ls -t "$DIR/*.ts" | tail -n $(($WANTED_CHUNKS-$NB_CHUNKS)) | xargs echo
fi
