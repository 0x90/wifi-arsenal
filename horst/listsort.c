/* horst - Highly Optimized Radio Scanning Tool
 *
 * Copyright (C) 2005-2014 Bruno Randolf (br1@einfach.org)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *
 * This is based on work under the following license:
 *
 * This file is copyright 2001 Simon Tatham.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL SIMON TATHAM BE LIABLE FOR
 * ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "ccan/list/list.h"
#include "listsort.h"

/*
 * sorting a linked list.
 *
 * The algorithm used is Mergesort, because that works really well
 * on linked lists, without requiring the O(N) extra space it needs
 * when you do it on arrays.
 *
 */


/*
 * This is the actual sort function.
 * It assumes head to be a pointer to the first list element, and not beeing a
 * list element itself (as common in the linux linked list implementation).
 * If the first element moves, head is adjusted accordingly.
 */
void
listsort(struct list_node *head,
	int(*cmp)(const struct list_node*, const struct list_node*))
{
	struct list_node *list, *p, *q, *e, *tail, *oldhead;
	int insize, nmerges, psize, qsize, i;

	if (!head || head->next == head)
		return;

	list = head->next;
	insize = 1;

	while (1)
	{
		p = list;
		oldhead = list;	/* used for circular linkage */
		list = NULL;
		tail = NULL;
		nmerges = 0;	/* count number of merges we do in this pass */

		while (p)
		{
			nmerges++;  /* there exists a merge to be done */

			/* step `insize' places along from p */
			q = p;
			psize = 0;
			for (i = 0; i < insize; i++) {
				psize++;
				q = (q->next == oldhead || q->next == head ? NULL : q->next);
				if (!q)
					break;
			}

			/* if q hasn't fallen off end, we have two lists to merge */
			qsize = insize;

			/* now we have two lists; merge them */
			while (psize > 0 || (qsize > 0 && q))
			{
				/* decide whether next element of merge comes from p or q */
				if (psize == 0) {
					/* p is empty; e must come from q. */
					e = q; q = q->next; qsize--;
					if (q == oldhead || q == head) q = NULL;
				} else if (qsize == 0 || !q) {
					/* q is empty; e must come from p. */
					e = p; p = p->next; psize--;
					if (p == oldhead || p == head) p = NULL;
				} else if (cmp(p,q) <= 0) {
					/* First element of p is lower (or same);
					 * e must come from p. */
					e = p; p = p->next; psize--;
					if (p == oldhead || p == head) p = NULL;
				} else {
					/* First element of q is lower; e must come from q. */
					e = q; q = q->next; qsize--;
					if (q == oldhead || q == head) q = NULL;
				}
				/* add the next element to the merged list */
				if (tail)
					tail->next = e;
				else
					list = e;
				/* Maintain reverse pointers */
				e->prev = tail;
				tail = e;
			}

			/* now p has stepped `insize' places along, and q has too */
			p = q;
		}
		tail->next = list;
		list->prev = tail;

		/* If we have done only one merge, we're finished. */
		if (nmerges <= 1) {  /* allow for nmerges==0, the empty list case */
			/* adjust head */
			head->next = list;
			head->prev = list->prev;
			list->prev->next = head;
			list->prev = head;
			return;
		}
		/* Otherwise repeat, merging lists twice the size */
		insize *= 2;
	}
}


#if 0
/*
 * Small test rig with three test orders. The list length 13 is
 * chosen because that means some passes will have an extra list at
 * the end and some will not.
 */

#include <stdio.h>

struct element {
	struct list_head list;
	int i;
};

int
elem_cmp(const struct list_head *a, const struct list_head *b)
{
	struct element *ea = list_entry(a, struct element, list);
	struct element *eb = list_entry(b, struct element, list);
	//printf("  cmp %d - %d\n", ea->i, eb->i);
	return ea->i - eb->i;
}

#if 0
/* old outdated test */
int main(void) {
	#define n 13
	struct element k[n], *head, *p;
	struct list_head* lh;

	int order[][n] = {
		{ 0,1,2,3,4,5,6,7,8,9,10,11,12 },
		{ 6,2,8,4,11,1,12,7,3,9,5,0,10 },
		{ 12,11,10,9,8,7,6,5,4,3,2,1,0 },
	};
	int i, j;

	for (j = 0; j < n; j++)
		k[j].i = j;

	listsort(NULL, &elem_cmp);

	for (i = 0; i < sizeof(order)/sizeof(*order); i++)
	{
		int *ord = order[i];
		head = &k[ord[0]];
		for (j = 0; j < n; j++) {
			if (j == n-1)
				k[ord[j]].list.next = &k[ord[0]].list;
			else
				k[ord[j]].list.next = &k[ord[j+1]].list;
			if (j == 0)
				k[ord[j]].list.prev = &k[ord[n-1]].list;
			else
			    k[ord[j]].list.prev = &k[ord[j-1]].list;
		}

		printf("before:");
		p = head;
		do {
			printf(" %d", p->i);
			//if (p->list.next && p->list.next->prev != p->list)
			//	printf(" [REVERSE LINK ERROR!]");
			p = list_entry(p->list.next, struct element, list);
		} while (p != head);
		printf("\n");

		lh = listsort(&head->list, &elem_cmp);
		head = list_entry(lh, struct element, list);

		printf(" after:");
		p = head;
		do {
			printf(" %d", p->i);
			//if (p->next && p->next->prev != p)
			//	printf(" [REVERSE LINK ERROR!]");
			p = list_entry(p->list.next, struct element, list);
		} while (p != head);
		printf("\n");

	}
	return 0;
}
#endif

int main(void)
{
	struct list_head lh;
	struct element e[5];
	struct element* ep;

	list_head_init(&lh);

	e[0].i = 5;
	e[1].i = 2;
	e[2].i = 1;
	e[3].i = 3;
	e[4].i = 4;

	list_add_tail(&lh, &e[0].list);
	list_add_tail(&lh, &e[1].list);
	list_add_tail(&lh, &e[2].list);
	list_add_tail(&lh, &e[3].list);
	list_add_tail(&lh, &e[4].list);

	list_for_each(&lh, ep, list) {
		printf("%d ", ep->i);
	}
	printf("\n");

	listsort(&lh, &elem_cmp);

	list_for_each(&lh, ep, list) {
		printf("%d ", ep->i);
		//printf("  [%p next %p prev %p]\n", &ep->list, ep->list.next, ep->list.prev);
		if (ep->list.next->prev != &ep->list)
			printf("* reverse link error!\n");
	}
	printf("\n");

	return 0;
}
#endif
