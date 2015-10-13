
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



static gboolean
print_range(void *value, void* userData _U_)
{
    wmem_range_t *range = (wmem_range_t *)value;
    printf("Range: low=%u high=%u max_edge=%u", range->low, range->high, range->max_edge);
//    printf("Data: %p\n", range->data);
    return TRUE;
}


gboolean
do_range_overlap(wmem_range_t *r1, wmem_range_t *r2)
{
    if (r1->low <= r2->high && r2->low <= r1->high)
        return TRUE;

    return FALSE;
}

wmem_itree_t *
wmem_itree_new(wmem_allocator_t *allocator)
{
    wmem_itree_t *tree = wmem_tree_new(allocator);
    tree->is_interval_tree = TRUE;
    return tree;
}

/*
*/
void
update_max_edge(wmem_tree_node_t *node)
{
    wmem_range_t *range;
    wmem_range_t *range_l;
    wmem_range_t *range_r;
    guint32 maxEdge  = 0;

    if(!node) {
        return ;
    }

    range = (wmem_range_t *)node->data;

    printf("Updating maximum\n");
//    print_range(range, 0);

    range_l = (node->left) ? (wmem_range_t *) (node->left->data) : NULL;
    range_r = (node->right) ? (wmem_range_t *) (node->right->data) : NULL;

    maxEdge = range->max_edge;

    // TODO assigner le max entre ses enfants et son high
    // Pointeur vers la data, remonter a la racine
//    if(maxEdge < range->high) {
        /* may need to update here */
//    maxEdge = MAX(maxEdge, ) ;
//    }

    //&& range_r->max_edge > maxEdge
    if(range_r) {
        maxEdge = MAX(maxEdge, range_r->max_edge) ;
    }
    //&& range_l->max_edge > maxEdge
    if(range_l) {
        maxEdge = MAX(maxEdge, range_l->max_edge) ;
    }

    /* if there was an update of this node max_edge, propagate this to the parent nodes */
    if(range->max_edge <= maxEdge) {
        range->max_edge = maxEdge;
        update_max_edge(node->parent);
    }
//    if(node->parent && node->parent->left != node) {
//    // in case of rotation
//        update_maximum(node->parent->left);
//
//    }

//    return FALSE;
}

#if 0
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
#endif

// Penser a maj le max edge
// For tests suppose in a first attempt that Sequence numbers are coded on 32bits
// use wmem_tree_key_t with a size of 2 for
// TODO need to update max_edge at the end of tree construction else it will be very hard to do
// Will be hard to handle duplicates, need to have a GSlist of wmem_range ?
void
wmem_itree_insert(wmem_itree_t *tree, wmem_range_t *range)
{
    // TODO should update the maxedge accordingly
    wmem_tree_node_t *node;
    // Returns a pointer to the range
    printf("Inserting range\n");
    print_range(range, 0);

    g_assert(range->low <= range->high);
    range->max_edge = range->high;
    node = wmem_tree_insert32_matt(tree, range->low, range);

    // If no rotations, still a need to update max_edge
    update_max_edge(node);
//    if()
//    update_maximum(node);
    // Not efficient at all but ok for testing I suppose ?
    // TODO pass the node
//    wmem_itree_update_maxima(tree);
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

static void
wmem_itree_find_interval_in_subtree(wmem_tree_node_t *node, wmem_range_t requested, wmem_range_t **results)
{
    wmem_range_t* current;

    if(!node) {
        return;
    }
    current = (wmem_range_t*)node->data;

    if(requested.low > current->max_edge) {
        return;
    }

    if(do_range_overlap(current, &requested)) {
        printf("Found a match");
        print_range(current, 0);
        *results = current;
        return;
    }

//    if(root->left) {
    wmem_itree_find_interval_in_subtree(node->left, requested, results);
    wmem_itree_find_interval_in_subtree(node->right, requested, results);
//    }
}

// TODO lui passer une GSlist comme results
void
wmem_itree_find_interval(wmem_itree_t *tree, wmem_range_t requested, wmem_range_t **results)
{
    printf("Requesting interval: ");
    print_range(&requested, 0);
    printf("\n");

//    interval
    /* TODO */
    if(wmem_tree_is_empty(tree))
        return ;

    wmem_itree_find_interval_in_subtree(tree->root, requested, results);


}

void
wmem_itree_find_point(wmem_itree_t *tree, guint32 point, wmem_range_t **results)
{
    // construit un range de 1,1
    wmem_range_t fakeRange;
    fakeRange.low  = point;
    fakeRange.high = point;

    wmem_itree_find_interval(tree, fakeRange, results);
}

void
wmem_print_itree(wmem_tree_t *tree)
{
    wmem_print_tree_with_values(tree, &print_range);
}


//wmem_print_tree
//()
//static void
//wmem_itree_print(const char *prefix, wmem_tree_node_t *node, guint32 level, wmem_foreach_func callback)
//{
