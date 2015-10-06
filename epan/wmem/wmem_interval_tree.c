
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
#include "wmem_interval_tree.h"
#include "wmem_user_cb.h"


gboolean
do_range_overlap(wmem_range_t *r1, wmem_range_t *r2)
{
    if (r1->low <= r2->high || r2->low <= r1->high)
        return TRUE;

    return FALSE;
}

wmem_itree_t *
wmem_itree_new(wmem_allocator_t *allocator)
{
    return wmem_tree_new(allocator);
}

/*
probleme c que la on regarde d'abord les enfants gacuhe, soit mm puis les enfantsz de droite
*/
gboolean
update_maximum(void *value, void *userdata _U_)
{
    wmem_tree_node_t *node = (wmem_tree_node_t *) value;
    wmem_range_t *range = (wmem_range_t *)node->data;

    wmem_range_t *range_l = (node->left) ? (wmem_range_t *)node->left->data : NULL;
    wmem_range_t *range_r = (node->right) ? (wmem_range_t *)node->right->data : NULL;

    guint32 maxEdge = range->max_edge;

    // TODO assigner le max entre ses enfants et son high
    // Pointeur vers la data, remonter a la racine
//    if(maxEdge < range->high) {
        /* may need to update here */
        maxEdge = MAX(maxEdge, range->high) ;
//    }

    if(range_r && range_r->max_edge > maxEdge) {
        maxEdge = MAX(maxEdge, range_r->max_edge) ;
    }
    if(range_l && range_l->max_edge > maxEdge) {
        maxEdge = MAX(maxEdge, range_l->max_edge) ;
    }

    range->max_edge = maxEdge;

    return FALSE;
}

// Update the maxima once the tree is built
void
wmem_itree_update_maxima(wmem_itree_t *tree)
{
    // Make use of

    //typedef gboolean (*wmem_foreach_func)(void *value, void *userdata);
    //
    ///** Traverse the tree and call callback(value, userdata) for each value found.
    // * Returns TRUE if the traversal was ended prematurely by the callback.
    // */
    gboolean result;
//    result = wmem_tree_foreach(tree, wmem_foreach_func callback, void *user_data);
//    wmem_tree_foreach_nodes
    result = wmem_tree_foreach_matt(tree, &update_maximum, NULL);
}

// Penser a maj le max edge
// For tests suppose in a first attempt that Sequence numbers are coded on 32bits
// use wmem_tree_key_t with a size of 2 for
// TODO need to update max_edge at the end of tree construction else it will be very hard to do
// Will be hard to handle duplicates, need to have a GSlist of wmem_range ?
void
wmem_itree_insert(wmem_itree_t *tree, wmem_range_t *range)
{
    // TODO should update the maxedge accordingly
//    wmem_tree_node_t *node =
    // Returns a pointer to the range
    wmem_tree_insert32(tree, range->low, range);

    // Not efficient at all but ok for testing I suppose ?
    wmem_itree_update_maxima(tree);
//    wmem_range_t * rootRange = (wmem_range_t *)tree->root->data;
//    node

    // TODO do it at the end of the fonction
//    if(rootRange->max_edge < range->high) {
//        /* may need to update here */
//        rootRange->max_edge < range->high;
//    }

    #if 0
    // Base case: Tree is empty, new node becomes root
    if (wmem_tree_is_empty() == TRUE)
        return newNode(i);

    // Get low value of interval at root
    int l = root->i->low;

    // If root's low value is smaller, then new interval goes to
    // left subtree
    if (i.low < l)
        root->left = insert(root->left, i);

    // Else, new node goes to right subtree.
    else
        root->right = insert(root->right, i);

    // Update the max value of this ancestor if needed
    if (root->max < i.high)
        root->max = i.high;

    return root;
    #endif

}

#if 0
// The main function that searches a given interval i in a given
// Interval Tree.
Interval *overlapSearch(ITNode *root, Interval i)
{
    // Base Case, tree is empty
    if (root == NULL) return NULL;

    // If given interval overlaps with root
    if (doOVerlap(*(root->i), i))
        return root->i;

    // If left child of root is present and max of left child is
    // greater than or equal to given interval, then i may
    // overlap with an interval is left subtree
    if (root->left != NULL && root->left->max >= i.low)
        return overlapSearch(root->left, i);

    // Else interval can only overlap with right subtree
    return overlapSearch(root->right, i);
}
#endif


// TODO mettre wmem_tree_node_t en public
//wmem_itree_find_overlap(wmem_tree_node_t *tree, wmem_range_t interval, wmem_range_t *results)
//{
//    // need to scheme through it manually
//}


void
print_range(void *value, void* userData)
{
    printf("custom printf: %p", value);
}
void
wmem_itree_find_interval(wmem_itree_t *tree, wmem_range_t interval, wmem_range_t *results)
{
//    interval
}

void
wmem_itree_find_point(wmem_itree_t *tree, guint32 point, wmem_range_t *results)
{
    // construit un range de 1,1
//    wmem_range_t fakeRange;
//
//    wmem_itree_find_interval()
}
