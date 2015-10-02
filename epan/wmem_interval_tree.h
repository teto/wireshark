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
#ifndef __WMEM_TREE_H__
#define __WMEM_TREE_H__

#include "wmem_core.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup wmem
 *  @{
 *    @defgroup wmem-interval-tree Interval Tree
 *
 *
 *    @{
 */

struct _wmem_tree_t;
typedef struct _wmem_tree_t wmem_itree_t;


// TODO should be able to use different keys, 32 bits for instance ? and pass an enum
// Use 64 bits to allow for mptcp
struct _wmem_range_t {

guint64 low;
guint64 high;
guint64 max_edge;   /* max value among right subtrees */

};

typedef struct _wmem_range_t wmem_range_t;

WS_DLL_PUBLIC
void
wmem_itree_insert(wmem_itree_t *tree, wmem_range_t );

/* 
Save results in 
*/
WS_DLL_PUBLIC
void
wmem_itree_find_interval(wmem_itree_t *tree, wmem_range_t interval, wmem_range_t *results);



/* 
Save results in 
*/
WS_DLL_PUBLIC
void
wmem_itree_find_point(wmem_itree_t *tree, guint64_t point, wmem_range_t *results);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_TREE_H__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
