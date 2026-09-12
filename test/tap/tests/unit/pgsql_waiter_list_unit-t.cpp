#include "tap.h"

#include "PgSQL_Waiter_List.h"

int main() {
	plan(25);

	PgSQL_Waiter_Lists lists;
	PgSQL_Waiter_Node a;
	PgSQL_Waiter_Node b;
	PgSQL_Waiter_Node c;
	PgSQL_Waiter_Node d;
	a.hid = 1;
	b.hid = 1;
	c.hid = 2;
	d.hid = 2;
	lists.push_back(a);
	lists.push_back(b);
	lists.push_back(c);
	lists.push_back(d);

	ok(lists.head(1) == &a, "hid 1 head is oldest");
	ok(a.next == &b && b.prev == &a && b.next == nullptr, "hid 1 push order preserved");
	ok(lists.head(2) == &c, "hid 2 head is oldest");
	ok(c.next == &d && d.prev == &c && d.next == nullptr, "hid 2 push order preserved");
	ok(!lists.empty(1) && !lists.empty(2), "both hostgroups nonempty");

	PgSQL_Waiter_Lists lists2;
	PgSQL_Waiter_Node x;
	PgSQL_Waiter_Node y;
	PgSQL_Waiter_Node z;
	x.hid = 10;
	y.hid = 10;
	z.hid = 10;
	lists2.push_back(x);
	lists2.push_back(y);
	lists2.push_back(z);
	lists2.unlink(y);
	ok(x.next == &z && z.prev == &x, "unlink middle relinks neighbors");
	ok(y.prev == nullptr && y.next == nullptr, "unlinked middle node has null neighbors");
	ok(lists2.head(10) == &x, "head unchanged after middle unlink");

	lists2.unlink(x);
	lists2.unlink(z);
	ok(lists2.empty(10), "empty after unlinking last node");
	ok(lists2.head(10) == nullptr, "head is null after last unlink");

	lists2.unlink(y);
	ok(lists2.empty(10), "unlink of node not in list is no-op");

	PgSQL_Waiter_Lists lists3;
	PgSQL_Waiter_Node n1;
	PgSQL_Waiter_Node n2;
	n1.hid = 1;
	n2.hid = 2;
	lists3.push_back(n1);
	lists3.push_back(n2);
	lists3.unlink(n2);
	int seen = 0;
	unsigned seen_hid = 0;
	PgSQL_Waiter_Node *seen_head = nullptr;
	lists3.for_each_hid([&](unsigned hid, PgSQL_Waiter_Node *head) {
		seen++;
		seen_hid = hid;
		seen_head = head;
	});
	ok(seen == 1, "for_each_hid visits only nonempty HGs");
	ok(seen_hid == 1, "for_each_hid visits remaining hid");
	ok(seen_head == &n1, "for_each_hid nonempty head");

	ok(vanilla_pool_checkout(false, nullptr, -1), "vanilla true when ff false, no gtid, max_lag < 0");
	ok(!vanilla_pool_checkout(true, nullptr, -1), "vanilla false when ff");
	ok(!vanilla_pool_checkout(false, "uuid", -1), "vanilla false when gtid_uuid non-null");
	ok(!vanilla_pool_checkout(false, nullptr, 0), "vanilla false when max_lag_ms >= 0");
	ok(!vanilla_pool_checkout(false, nullptr, 10), "vanilla false when max_lag_ms positive");
	ok(vanilla_pool_checkout(false, nullptr, -100), "vanilla true for any negative max_lag_ms");

	PgSQL_Waiter_Lists lists4;
	PgSQL_Waiter_Node e1;
	PgSQL_Waiter_Node e2;
	PgSQL_Waiter_Node e3;
	e1.hid = 1;
	e2.hid = 1;
	e3.hid = 2;
	lists4.push_back(e1);
	lists4.push_back(e2);
	lists4.push_back(e3);
	lists4.for_each_hid([&](unsigned hid, PgSQL_Waiter_Node *h) {
		(void)hid;
		while (h) {
			PgSQL_Waiter_Node *nxt = h->next;
			lists4.unlink(*h);
			h = nxt;
		}
	});
	ok(lists4.empty(1) && lists4.empty(2), "for_each_hid unlink-all leaves empty lists");

	PgSQL_Waiter_Lists lists5;
	PgSQL_Waiter_Node a5;
	PgSQL_Waiter_Node b5;
	PgSQL_Waiter_Node stranger;
	a5.hid = 1;
	b5.hid = 1;
	stranger.hid = 1;
	lists5.push_back(a5);
	lists5.push_back(b5);
	lists5.unlink(stranger);
	ok(lists5.head(1) == &a5 && a5.next == &b5 && b5.prev == &a5, "unlink never-inserted node is no-op");
	lists5.unlink(b5);
	lists5.unlink(b5);
	ok(lists5.head(1) == &a5 && a5.next == nullptr && b5.prev == nullptr && b5.next == nullptr, "double unlink is no-op");

	PgSQL_Waiter_Lists L1;
	PgSQL_Waiter_Lists L2;
	PgSQL_Waiter_Node ln;
	PgSQL_Waiter_Node ln2;
	PgSQL_Waiter_Node o1;
	PgSQL_Waiter_Node o2;
	ln.hid = 1;
	ln2.hid = 1;
	o1.hid = 1;
	o2.hid = 1;
	L1.push_back(ln);
	L1.push_back(ln2);
	L2.push_back(o1);
	L2.push_back(o2);
	L2.unlink(ln);
	ok(L2.head(1) == &o1 && o1.next == &o2 && o2.prev == &o1, "unlink foreign node leaves L2 unchanged");
	ok(L1.head(1) == &ln && ln.next == &ln2 && ln2.prev == &ln, "unlink from L2 leaves n in L1");

	return exit_status();
}
