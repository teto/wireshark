
/* wmem_interval_tree.h
 * Definitions for the Wireshark Memory Manager Red-Black Tree
 * Based on the red-black tree implementation in epan/emem.*
 * Copyright 2015, Matthieu coudron <matthieu.coudron@lip6.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>
#include <stdio.h>
#include <glib.h>

#include "wmem_core.h"
#include "wmem_strutl.h"
#include "wmem_tree.h"
#include "wmem_user_cb.h"


// Penser a maj le max edge
void
wmem_itree_insert(wmem_itree_t *tree, wmem_range_t r)
{


}
