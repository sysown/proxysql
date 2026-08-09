# Query-cache soft-TTL single-flight design

## Goal

Ensure that exactly one request refreshes a valid query-cache entry after its soft TTL is reached. Other concurrent requests must continue serving the existing entry.

## Scope

The shared `Query_Cache` template is the sole production-code change. It serves both MySQL and PostgreSQL query caches. The existing MySQL soft-TTL TAP test will be tightened to check the documented single-refresh contract.

## Design

`QC_entry_t::refreshing` remains a plain `bool` because cache entries are allocated with `malloc`. In `Query_Cache::get()`, the current non-atomic read followed by assignment will be replaced by `__sync_bool_compare_and_swap(&entry_shared->refreshing, false, true)`. This is an established codebase primitive for atomically claiming a boolean field without changing the entry allocation/destruction model.

At soft TTL, the request that wins the compare-and-swap returns a cache miss and refreshes the backend entry. Requests that lose the claim execute the normal cache-hit path and use the old entry. Values outside the soft-TTL window retain their current behaviour.

Refresh ownership lasts for the lifetime of that cache generation. A successful cacheable backend result replaces the entry with a new generation whose `refreshing` flag is clear. If the refresh fails or produces a result that is not cacheable, the old entry remains the fallback until its hard TTL; the claim is deliberately not reopened for every subsequent request, avoiding repeated backend retries during an upstream failure.

## Testing

The MySQL TAP test will expect the exact outcome for 24 total requests from eight concurrent clients plus the initial cache fill: one slow client, 23 cache hits, and two hostgroup/backend hits. The existing test drives eight clients across the soft-TTL boundary; it fails on the current implementation when multiple clients claim refresh ownership.

The focused MySQL test will be built and run through the documented isolated TAP harness. The matching PostgreSQL test will also be run when its infrastructure is available, because the production code is shared.
