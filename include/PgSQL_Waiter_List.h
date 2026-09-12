#ifndef __CLASS_PGSQL_WAITER_LIST_H
#define __CLASS_PGSQL_WAITER_LIST_H

#include <cassert>
#include <map>
#include <vector>

struct PgSQL_Waiter_Node {
	PgSQL_Waiter_Node *prev = nullptr, *next = nullptr;
	unsigned hid = 0;
	void *session = nullptr;
};

class PgSQL_Waiter_Lists {
	struct List { PgSQL_Waiter_Node *head = nullptr, *tail = nullptr; };
	std::map<unsigned, List> by_hid;
public:
	void push_back(PgSQL_Waiter_Node& n) {
		List& L = by_hid[n.hid];
		assert(n.prev == nullptr && n.next == nullptr && L.head != &n);
		n.prev = L.tail;
		n.next = nullptr;
		if (L.tail) {
			L.tail->next = &n;
		} else {
			L.head = &n;
		}
		L.tail = &n;
	}

	void unlink(PgSQL_Waiter_Node& n) {
		auto it = by_hid.find(n.hid);
		if (it == by_hid.end()) {
			return;
		}
		List& L = it->second;
		PgSQL_Waiter_Node *p = L.head;
		while (p && p != &n) {
			p = p->next;
		}
		if (p != &n) {
			return;
		}
		if (n.prev) {
			n.prev->next = n.next;
		} else {
			L.head = n.next;
		}
		if (n.next) {
			n.next->prev = n.prev;
		} else {
			L.tail = n.prev;
		}
		n.prev = nullptr;
		n.next = nullptr;
		if (L.head == nullptr) {
			by_hid.erase(it);
		}
	}

	PgSQL_Waiter_Node *head(unsigned hid) const {
		auto it = by_hid.find(hid);
		return it == by_hid.end() ? nullptr : it->second.head;
	}

	bool empty(unsigned hid) const {
		auto it = by_hid.find(hid);
		return it == by_hid.end() || it->second.head == nullptr;
	}

	bool empty() const { return by_hid.empty(); }

	template<class F>
	void for_each_hid(F f) {
		std::vector<unsigned> hids;
		hids.reserve(by_hid.size());
		for (const auto& kv : by_hid) {
			if (kv.second.head) {
				hids.push_back(kv.first);
			}
		}
		for (unsigned hid : hids) {
			auto it = by_hid.find(hid);
			if (it != by_hid.end() && it->second.head) {
				f(hid, it->second.head);
			}
		}
	}
};

inline bool vanilla_pool_checkout(bool ff, const char *gtid_uuid, int max_lag_ms) {
	return !ff && gtid_uuid == nullptr && max_lag_ms < 0;
}

#endif // __CLASS_PGSQL_WAITER_LIST_H
