#include "Embedded_Quota.h"
#include "tap.h"
#include <atomic>
#include <limits>
#include <stdexcept>
#include <thread>
#include <vector>
using namespace embedded;
int main() {
    plan(NO_PLAN);
    QuotaLimits limits;
    limits.values = {{2, 10, 10, 10, 10}};
    QuotaPool pool(limits), other(limits);
    ResourceUsage a{{1, 10, 2, 0, 0}}, b{{1, 0, 0, 0, 0}};
    {
        QuotaLease one(pool), two(pool), independent(other);
        ok(one.resize(a) && two.resize(b), "exact limits fit");
        const auto before = pool.snapshot();
        ResourceUsage too{{0, 1, 0, 0, 0}};
        ok(!two.resize(too) && pool.snapshot() == before && two.usage() == b,
           "failed multi-resource resize is atomic");
        ok(independent.resize(a) && other.snapshot() == a,
           "independent pool has separate accounting");
        QuotaLease moved(std::move(one));
        ok(!one.resize(a) && moved.usage() == a, "move transfers ownership");
        moved.reset();
        moved.reset();
        ok(pool.snapshot() == b, "reset releases once");
        ok(two.resize(too), "released capacity can be reused");
    }
    ok(pool.snapshot() == ResourceUsage{} && other.snapshot() == ResourceUsage{},
       "destructors release all pools");
    {
        QuotaLease source(pool), destination(other);
        source.resize(a);
        destination.resize(b);
        destination = std::move(source);
        ok(pool.snapshot() == a && other.snapshot() == ResourceUsage{} &&
               destination.usage() == a && !source.resize(b),
           "move assignment releases the destination's original pool and retains the source pool");
    }
    try {
        QuotaLease temporary(pool);
        if (!temporary.resize(a))
            throw std::logic_error("unexpected quota refusal");
        throw std::runtime_error("injected caller exception");
    } catch (const std::runtime_error &) {
    }
    ok(pool.snapshot() == ResourceUsage{}, "caller exception releases its lease");
    QuotaLimits huge;
    huge.values.fill(std::numeric_limits<size_t>::max());
    QuotaPool big(huge);
    QuotaLease full(big), extra(big);
    ResourceUsage max{};
    max[0] = std::numeric_limits<size_t>::max();
    ResourceUsage one{};
    one[0] = 1;
    ok(full.resize(max) && !extra.resize(one) && big.snapshot() == max,
       "SIZE_MAX limit rejects overflow without mutation");
    full.reset();
    ok(extra.resize(one), "capacity after SIZE_MAX release is reusable");
    QuotaPool threaded(limits);
    std::atomic<int> ready{0}, admitted{0}, attempted{0}, release{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; ++i)
        threads.emplace_back([&] {
            QuotaLease lease(threaded);
            ++ready;
            while (ready.load() < 8)
                std::this_thread::yield();
            if (lease.resize(one))
                ++admitted;
            ++attempted;
            while (!release.load())
                std::this_thread::yield();
        });
    while (ready.load() < 8)
        std::this_thread::yield();
    while (attempted.load() < 8)
        std::this_thread::yield();
    ok(admitted == 2 && threaded.snapshot()[0] == 2, "concurrent leases respect shared maximum");
    release = 1;
    for (auto &t : threads)
        t.join();
    ok(threaded.snapshot() == ResourceUsage{}, "concurrent leases release safely");
    return exit_status();
}
