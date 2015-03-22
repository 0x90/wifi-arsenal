#include <ccan/list/list.h>
#include <ccan/tap/tap.h>
#include <ccan/list/list.c>
#include "helper.h"

struct parent {
	const char *name;
	struct list_head children;
	unsigned int num_children;
};

struct child {
	const char *name;
	struct list_node list;
};

static LIST_HEAD(static_list);

int main(int argc, char *argv[])
{
	struct parent parent;
	struct child c1, c2, c3, *c, *n;
	unsigned int i;
	struct list_head list = LIST_HEAD_INIT(list);
	opaque_t *q, *nq;
	struct list_head opaque_list = LIST_HEAD_INIT(opaque_list);

	plan_tests(68);
	/* Test LIST_HEAD, LIST_HEAD_INIT, list_empty and check_list */
	ok1(list_empty(&static_list));
	ok1(list_check(&static_list, NULL));
	ok1(list_empty(&list));
	ok1(list_check(&list, NULL));

	parent.num_children = 0;
	list_head_init(&parent.children);
	/* Test list_head_init */
	ok1(list_empty(&parent.children));
	ok1(list_check(&parent.children, NULL));

	c2.name = "c2";
	list_add(&parent.children, &c2.list);
	/* Test list_add and !list_empty. */
	ok1(!list_empty(&parent.children));
	ok1(c2.list.next == &parent.children.n);
	ok1(c2.list.prev == &parent.children.n);
	ok1(parent.children.n.next == &c2.list);
	ok1(parent.children.n.prev == &c2.list);
	/* Test list_check */
	ok1(list_check(&parent.children, NULL));

	c1.name = "c1";
	list_add(&parent.children, &c1.list);
	/* Test list_add and !list_empty. */
	ok1(!list_empty(&parent.children));
	ok1(c2.list.next == &parent.children.n);
	ok1(c2.list.prev == &c1.list);
	ok1(parent.children.n.next == &c1.list);
	ok1(parent.children.n.prev == &c2.list);
	ok1(c1.list.next == &c2.list);
	ok1(c1.list.prev == &parent.children.n);
	/* Test list_check */
	ok1(list_check(&parent.children, NULL));

	c3.name = "c3";
	list_add_tail(&parent.children, &c3.list);
	/* Test list_add_tail and !list_empty. */
	ok1(!list_empty(&parent.children));
	ok1(parent.children.n.next == &c1.list);
	ok1(parent.children.n.prev == &c3.list);
	ok1(c1.list.next == &c2.list);
	ok1(c1.list.prev == &parent.children.n);
	ok1(c2.list.next == &c3.list);
	ok1(c2.list.prev == &c1.list);
	ok1(c3.list.next == &parent.children.n);
	ok1(c3.list.prev == &c2.list);
	/* Test list_check */
	ok1(list_check(&parent.children, NULL));

	/* Test list_check_node */
	ok1(list_check_node(&c1.list, NULL));
	ok1(list_check_node(&c2.list, NULL));
	ok1(list_check_node(&c3.list, NULL));

	/* Test list_top */
	ok1(list_top(&parent.children, struct child, list) == &c1);

	/* Test list_pop */
	ok1(list_pop(&parent.children, struct child, list) == &c1);
	ok1(list_top(&parent.children, struct child, list) == &c2);
	list_add(&parent.children, &c1.list);

	/* Test list_tail */
	ok1(list_tail(&parent.children, struct child, list) == &c3);

	/* Test list_for_each. */
	i = 0;
	list_for_each(&parent.children, c, list) {
		switch (i++) {
		case 0:
			ok1(c == &c1);
			break;
		case 1:
			ok1(c == &c2);
			break;
		case 2:
			ok1(c == &c3);
			break;
		}
		if (i > 2)
			break;
	}
	ok1(i == 3);

	/* Test list_for_each_rev. */
	i = 0;
	list_for_each_rev(&parent.children, c, list) {
		switch (i++) {
		case 0:
			ok1(c == &c3);
			break;
		case 1:
			ok1(c == &c2);
			break;
		case 2:
			ok1(c == &c1);
			break;
		}
		if (i > 2)
			break;
	}
	ok1(i == 3);

	/* Test list_for_each_safe, list_del and list_del_from. */
	i = 0;
	list_for_each_safe(&parent.children, c, n, list) {
		switch (i++) {
		case 0:
			ok1(c == &c1);	
			list_del(&c->list);
			break;
		case 1:
			ok1(c == &c2);
			list_del_from(&parent.children, &c->list);
			break;
		case 2:
			ok1(c == &c3);
			list_del_from(&parent.children, &c->list);
			break;
		}
		ok1(list_check(&parent.children, NULL));
		if (i > 2)
			break;
	}
	ok1(i == 3);
	ok1(list_empty(&parent.children));

	/* Test list_for_each_off. */
	list_add_tail(&opaque_list,
		      (struct list_node *)create_opaque_blob());
	list_add_tail(&opaque_list,
		      (struct list_node *)create_opaque_blob());
	list_add_tail(&opaque_list,
		      (struct list_node *)create_opaque_blob());

	i = 0;

	list_for_each_off(&opaque_list, q, 0) {
	  i++;
	  ok1(if_blobs_know_the_secret(q));
	}
	ok1(i == 3);

	/* Test list_for_each_safe_off, list_del_off and list_del_from_off. */
	i = 0;
	list_for_each_safe_off(&opaque_list, q, nq, 0) {
		switch (i++) {
		case 0:
			ok1(if_blobs_know_the_secret(q));
			list_del_off(q, 0);
			destroy_opaque_blob(q);
			break;
		case 1:
			ok1(if_blobs_know_the_secret(q));
			list_del_from_off(&opaque_list, q, 0);
			destroy_opaque_blob(q);
			break;
		case 2:
			ok1(c == &c3);
			list_del_from_off(&opaque_list, q, 0);
			destroy_opaque_blob(q);
			break;
		}
		ok1(list_check(&opaque_list, NULL));
		if (i > 2)
			break;
	}
	ok1(i == 3);
	ok1(list_empty(&opaque_list));

	/* Test list_top/list_tail/list_pop on empty list. */
	ok1(list_top(&parent.children, struct child, list) == NULL);
	ok1(list_tail(&parent.children, struct child, list) == NULL);
	ok1(list_pop(&parent.children, struct child, list) == NULL);
	return exit_status();
}
