#ifndef PROXYSQL_DIGEST_TEXT_MERGE_H
#define PROXYSQL_DIGEST_TEXT_MERGE_H

#include <cstdint>
#include <cstdlib>
#include <unordered_map>
#include <vector>

#include "proxysql_typedefs.h"

// Merge the digest-text map `src` into `dst`, keeping exactly one heap copy of
// each digest text.
//
// Both maps are keyed by the plain query digest and hold a strdup()'ed text.
// The same digest can be present in both maps when worker threads call
// update_query_digest() while a stats dump is in flight: the live maps are
// swapped into auxiliary ones, so a digest already seen before the swap gets a
// second text in the map that is being repopulated. Folding the two together
// with unordered_map::insert() would silently drop (and leak) the source
// pointer for an already-present key. This helper keeps `dst`'s pointer for
// such keys and disposes of the incoming duplicate: freed immediately, or
// appended to `duplicates` when the caller must free it later (for instance
// after releasing a lock). `src` is cleared on return.
inline void merge_digest_text_maps(
	umap_query_digest_text& dst,
	umap_query_digest_text& src,
	std::vector<char*>* duplicates = nullptr
) {
	for (auto& entry : src) {
		auto inserted = dst.try_emplace(entry.first, entry.second);
		if (!inserted.second) {
			if (duplicates != nullptr) {
				duplicates->push_back(entry.second);
			} else {
				free(entry.second);
			}
		}
	}
	src.clear();
}

#endif // PROXYSQL_DIGEST_TEXT_MERGE_H
