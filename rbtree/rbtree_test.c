// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include <stdint.h>
#include <rbtree_augmented.h>

static int nnodes = 800; /* "Number of nodes in the rb-tree") */
static int perf_loops = 4000; /* "Number of iterations modifying the rb-tree") */
static int check_loops = 400; /* "Number of iterations modifying and verifying the rb-tree") */

struct test_node {
	uint32_t key;
	struct rb_node rb;

	/* following fields used for testing augmented rbtree functionality */
	uint32_t val;
	uint32_t augmented;
};

static struct rb_root_cached root = RB_ROOT_CACHED;
static struct test_node *nodes = NULL;

static int rnd = -1;

#ifndef WARN_ON_ONCE
#define WARN_ON_ONCE(expr_) warn_on_once(#expr_, expr_, __LINE__)
#endif
static unsigned long long div_u64(unsigned long long a, int b)
{
	if (b <= 0)
		return 0;
	return a / (unsigned long long) b;
}

static void warn_on_once(const char * expr, int _expr, int lino)
{
	if (_expr) {
		fprintf(stderr, "Warning, '%s' at line %d\n", expr, lino);
		fflush(stderr);
	}
}

static unsigned int prandom_u32_state(int rfd)
{
	unsigned int rval = 0;
	if (read(rfd, &rval, sizeof(rval)) != (ssize_t) sizeof(rval)) {
		fprintf(stderr, "Error, failed to read %d: %s\n", rfd, strerror(errno));
		fflush(stderr);
	}
	return rval;
}

static unsigned long long get_cycles(void)
{
	int ret;
	struct timespec spec;
	unsigned long long rval;

	spec.tv_sec = 0;
	spec.tv_nsec = 0;
	ret = clock_gettime(CLOCK_THREAD_CPUTIME_ID, &spec);
	if (ret == -1) {
		abort();
	}

#if 1
	rval = (unsigned long long) spec.tv_sec;
	rval = (rval * 1000000000) + (unsigned long long) spec.tv_nsec;
#else
	rval = (unsigned long long) spec.tv_sec;
	rval = (rval * 1000000) + (unsigned long long) (spec.tv_nsec / 1000);
#endif
	return rval;
}

static void insert(struct test_node *node, struct rb_root_cached *root)
{
	struct rb_node **new = &root->rb_root.rb_node, *parent = NULL;
	uint32_t key = node->key;

	while (*new) {
		parent = *new;
		if (key < rb_entry(parent, struct test_node, rb)->key)
			new = &parent->rb_left;
		else
			new = &parent->rb_right;
	}

	rb_link_node(&node->rb, parent, new);
	rb_insert_color(&node->rb, &root->rb_root);
}

static void insert_cached(struct test_node *node, struct rb_root_cached *root)
{
	struct rb_node **new = &root->rb_root.rb_node, *parent = NULL;
	uint32_t key = node->key;
	bool leftmost = true;

	while (*new) {
		parent = *new;
		if (key < rb_entry(parent, struct test_node, rb)->key)
			new = &parent->rb_left;
		else {
			new = &parent->rb_right;
			leftmost = false;
		}
	}

	rb_link_node(&node->rb, parent, new);
	rb_insert_color_cached(&node->rb, root, leftmost);
}

static inline void erase(struct test_node *node, struct rb_root_cached *root)
{
	rb_erase(&node->rb, &root->rb_root);
}

static inline void erase_cached(struct test_node *node, struct rb_root_cached *root)
{
	rb_erase_cached(&node->rb, root);
}


#define NODE_VAL(node) ((node)->val)

RB_DECLARE_CALLBACKS_MAX(static, augment_callbacks,
			 struct test_node, rb, uint32_t, augmented, NODE_VAL)

static void insert_augmented(struct test_node *node,
			     struct rb_root_cached *root)
{
	struct rb_node **new = &root->rb_root.rb_node, *rb_parent = NULL;
	uint32_t key = node->key;
	uint32_t val = node->val;
	struct test_node *parent;

	while (*new) {
		rb_parent = *new;
		parent = rb_entry(rb_parent, struct test_node, rb);
		if (parent->augmented < val)
			parent->augmented = val;
		if (key < parent->key)
			new = &parent->rb.rb_left;
		else
			new = &parent->rb.rb_right;
	}

	node->augmented = val;
	rb_link_node(&node->rb, rb_parent, new);
	rb_insert_augmented(&node->rb, &root->rb_root, &augment_callbacks);
}

static void insert_augmented_cached(struct test_node *node,
				    struct rb_root_cached *root)
{
	struct rb_node **new = &root->rb_root.rb_node, *rb_parent = NULL;
	uint32_t key = node->key;
	uint32_t val = node->val;
	struct test_node *parent;
	bool leftmost = true;

	while (*new) {
		rb_parent = *new;
		parent = rb_entry(rb_parent, struct test_node, rb);
		if (parent->augmented < val)
			parent->augmented = val;
		if (key < parent->key)
			new = &parent->rb.rb_left;
		else {
			new = &parent->rb.rb_right;
			leftmost = false;
		}
	}

	node->augmented = val;
	rb_link_node(&node->rb, rb_parent, new);
	rb_insert_augmented_cached(&node->rb, root,
				   leftmost, &augment_callbacks);
}


static void erase_augmented(struct test_node *node, struct rb_root_cached *root)
{
	rb_erase_augmented(&node->rb, &root->rb_root, &augment_callbacks);
}

static void erase_augmented_cached(struct test_node *node,
				   struct rb_root_cached *root)
{
	rb_erase_augmented_cached(&node->rb, root, &augment_callbacks);
}

static void init(void)
{
	int i;
	for (i = 0; i < nnodes; i++) {
		nodes[i].key = prandom_u32_state(rnd);
		nodes[i].val = prandom_u32_state(rnd);
	}
}

static bool is_red(struct rb_node *rb)
{
	return !(rb->__rb_parent_color & 1);
}

static int black_path_count(struct rb_node *rb)
{
	int count;
	for (count = 0; rb; rb = rb_parent(rb))
		count += !is_red(rb);
	return count;
}

static void check_postorder_foreach(int nr_nodes)
{
	struct test_node *cur, *n;
	int count = 0;
	rbtree_postorder_for_each_entry_safe(cur, n, &root.rb_root, rb)
		count++;

	WARN_ON_ONCE(count != nr_nodes);
}

static void check_postorder(int nr_nodes)
{
	struct rb_node *rb;
	int count = 0;
	for (rb = rb_first_postorder(&root.rb_root); rb; rb = rb_next_postorder(rb))
		count++;

	WARN_ON_ONCE(count != nr_nodes);
}

static void check(int nr_nodes)
{
	struct rb_node *rb;
	int count = 0, blacks = 0;
	uint32_t prev_key = 0;

	for (rb = rb_first(&root.rb_root); rb; rb = rb_next(rb)) {
		struct test_node *node = rb_entry(rb, struct test_node, rb);
		WARN_ON_ONCE(node->key < prev_key);
		WARN_ON_ONCE(is_red(rb) &&
			     (!rb_parent(rb) || is_red(rb_parent(rb))));
		if (!count)
			blacks = black_path_count(rb);
		else
			WARN_ON_ONCE((!rb->rb_left || !rb->rb_right) &&
				     blacks != black_path_count(rb));
		prev_key = node->key;
		count++;
	}

	WARN_ON_ONCE(count != nr_nodes);
	WARN_ON_ONCE(count < (1 << black_path_count(rb_last(&root.rb_root))) - 1);

	check_postorder(nr_nodes);
	check_postorder_foreach(nr_nodes);
}

static void check_augmented(int nr_nodes)
{
	struct rb_node *rb;

	check(nr_nodes);
	for (rb = rb_first(&root.rb_root); rb; rb = rb_next(rb)) {
		struct test_node *node = rb_entry(rb, struct test_node, rb);
		uint32_t subtree, max = node->val;
		if (node->rb.rb_left) {
			subtree = rb_entry(node->rb.rb_left, struct test_node,
					   rb)->augmented;
			if (max < subtree)
				max = subtree;
		}
		if (node->rb.rb_right) {
			subtree = rb_entry(node->rb.rb_right, struct test_node,
					   rb)->augmented;
			if (max < subtree)
				max = subtree;
		}
		WARN_ON_ONCE(node->augmented != max);
	}
}

int main(void)
{
	int i, j;
	unsigned long long time1, time2, time;
	struct rb_node *node;

	rnd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (rnd == -1) {
		fprintf(stderr, "Error, failed to open random device: %s\n",
			strerror(errno));
		fflush(stderr);
		return 1;
	}

	nodes = (struct test_node *) calloc(nnodes, sizeof(*nodes));
	if (!nodes)
		return -ENOMEM;

	fprintf(stdout, "rbtree testing...\n");

	/* prandom_seed_state(&rnd, 3141592653589793238ULL); */
	init();

	time1 = get_cycles();

	for (i = 0; i < perf_loops; i++) {
		for (j = 0; j < nnodes; j++)
			insert(nodes + j, &root);
		for (j = 0; j < nnodes; j++)
			erase(nodes + j, &root);
	}

	time2 = get_cycles();
	time = time2 - time1;

	time = div_u64(time, perf_loops);
	fprintf(stdout, " -> test 1 (latency of nnodes insert+delete): %llu cycles\n",
	       (unsigned long long)time);

	time1 = get_cycles();

	for (i = 0; i < perf_loops; i++) {
		for (j = 0; j < nnodes; j++)
			insert_cached(nodes + j, &root);
		for (j = 0; j < nnodes; j++)
			erase_cached(nodes + j, &root);
	}

	time2 = get_cycles();
	time = time2 - time1;

	time = div_u64(time, perf_loops);
	fprintf(stdout, " -> test 2 (latency of nnodes cached insert+delete): %llu cycles\n",
	       (unsigned long long)time);

	for (i = 0; i < nnodes; i++)
		insert(nodes + i, &root);

	time1 = get_cycles();

	for (i = 0; i < perf_loops; i++) {
		for (node = rb_first(&root.rb_root); node; node = rb_next(node))
			;
	}

	time2 = get_cycles();
	time = time2 - time1;

	time = div_u64(time, perf_loops);
	fprintf(stdout, " -> test 3 (latency of inorder traversal): %llu cycles\n",
	       (unsigned long long)time);

	time1 = get_cycles();

	for (i = 0; i < perf_loops; i++)
		node = rb_first(&root.rb_root);

	time2 = get_cycles();
	time = time2 - time1;

	time = div_u64(time, perf_loops);
	fprintf(stdout, " -> test 4 (latency to fetch first node)\n");
	fprintf(stdout, "        non-cached: %llu cycles\n", (unsigned long long)time);

	time1 = get_cycles();

	for (i = 0; i < perf_loops; i++)
		node = rb_first_cached(&root);

	time2 = get_cycles();
	time = time2 - time1;

	time = div_u64(time, perf_loops);
	fprintf(stdout, "        cached: %llu cycles\n", (unsigned long long)time);

	for (i = 0; i < nnodes; i++)
		erase(nodes + i, &root);

	/* run checks */
	for (i = 0; i < check_loops; i++) {
		init();
		for (j = 0; j < nnodes; j++) {
			check(j);
			insert(nodes + j, &root);
		}
		for (j = 0; j < nnodes; j++) {
			check(nnodes - j);
			erase(nodes + j, &root);
		}
		check(0);
	}

	fprintf(stdout, "augmented rbtree testing...\n");

	init();

	time1 = get_cycles();

	for (i = 0; i < perf_loops; i++) {
		for (j = 0; j < nnodes; j++)
			insert_augmented(nodes + j, &root);
		for (j = 0; j < nnodes; j++)
			erase_augmented(nodes + j, &root);
	}

	time2 = get_cycles();
	time = time2 - time1;

	time = div_u64(time, perf_loops);
	fprintf(stdout, " -> test 1 (latency of nnodes insert+delete): %llu cycles\n", (unsigned long long)time);

	time1 = get_cycles();

	for (i = 0; i < perf_loops; i++) {
		for (j = 0; j < nnodes; j++)
			insert_augmented_cached(nodes + j, &root);
		for (j = 0; j < nnodes; j++)
			erase_augmented_cached(nodes + j, &root);
	}

	time2 = get_cycles();
	time = time2 - time1;

	time = div_u64(time, perf_loops);
	fprintf(stdout, " -> test 2 (latency of nnodes cached insert+delete): %llu cycles\n", (unsigned long long)time);

	time1 = get_cycles();
	for (i = 0; i < check_loops; i++) {
		init();
		for (j = 0; j < nnodes; j++) {
			check_augmented(j);
			insert_augmented(nodes + j, &root);
		}
		for (j = 0; j < nnodes; j++) {
			check_augmented(nnodes - j);
			erase_augmented(nodes + j, &root);
		}
		check_augmented(0);
	}

	time2 = get_cycles();
	time = time2 - time1;

	time = div_u64(time, check_loops);
	fprintf(stdout, " -> test 3 (latency of nnodes augmented insert+delete): %llu cycles\n", (unsigned long long)time);

	free(nodes);
	close(rnd); rnd = -1;
	return 0;
	/* return -EAGAIN; Fail will directly unload the module */
}

/*
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michel Lespinasse");
MODULE_DESCRIPTION("Red Black Tree test");
*/
