/*
 * tests/test_h4_cxx17.cc — Phase 7 lane H4 guest test (C++17 runtime).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * C++17 runtime exercise for MIPS64 N64/N32 guests, identical under
 * qemu-mips64el (N64LE) / qemu-mipsn32el (N32LE) / qemu-mips64 (N64BE) /
 * qemu-mipsn32 (N32BE) and under mips64rt --interp / --dbt:
 *
 *  - t_unwind_depth: exception thrown through three nested call frames
 *    with RAII guards verifying LIFO destruction order, caught by
 *    const reference with payload delivery.
 *  - t_unwind_rethrow: nested try, catch-and-rethrow preserving the
 *    dynamic type, catch(...) fallback, unwinding through a
 *    std::function/lambda frame.
 *  - t_rtti: dynamic_cast across a polymorphic hierarchy (downcast,
 *    cross-cast, failing cast -> nullptr, bad_cast on reference,
 *    typeid identity).
 *  - t_threads: std::thread pool with mutex-protected accumulation
 *    and per-thread return values, plus one detached thread whose
 *    completion is observed through an atomic flag.
 *  - t_thread_local: thread_local objects with non-trivial
 *    constructor/destructor (ctor/dtor counts balance per thread)
 *    and errno-style thread_local isolation.
 *
 * Build (static, inside the debian:trixie-slim container like
 * tests/run_p6_perms.sh):
 *   mips64el-linux-gnuabi64-g++ -mabi=64 -O1 -static -pthread -std=c++17 \
 *       -Wall -Wextra -o /tmp/h4-n64le tests/test_h4_cxx17.cc
 *   mips64el-linux-gnuabi64-g++ -mabi=n32 -O1 -static -pthread -std=c++17 \
 *       -Wall -Wextra -o /tmp/h4-n32le tests/test_h4_cxx17.cc
 *   (same with mips64-linux-gnuabi64-g++ for the BE pair)
 */

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <typeinfo>
#include <unistd.h>
#include <vector>

static int g_pass = 0;
static int g_fail = 0;

static void check(const char *name, int ok, const char *detail)
{
    if (ok) {
        g_pass++;
        printf("H4-PASS %s %s\n", name, detail);
    } else {
        g_fail++;
        printf("H4-FAIL %s %s\n", name, detail);
    }
}

/* ================= unwind through three call frames ================= */

struct H4Error {
    int code;
};

static int g_order[16];
static int g_norder;

struct H4Guard {
    int id;
    explicit H4Guard(int i) : id(i) {}
    ~H4Guard()
    {
        if (g_norder < 16) {
            g_order[g_norder++] = id;
        }
    }
};

__attribute__((noinline)) static void h4_level3(int code)
{
    H4Guard g(3);
    throw H4Error{code};
}

__attribute__((noinline)) static void h4_level2(int code)
{
    H4Guard g(2);
    h4_level3(code);
}

__attribute__((noinline)) static void h4_level1(int code)
{
    H4Guard g(1);
    h4_level2(code);
}

static void t_unwind_depth(void)
{
    char db[160];
    int order_ok = 0;
    int code_ok = 0;

    g_norder = 0;
    try {
        h4_level1(42);
    } catch (const H4Error &e) {
        code_ok = (e.code == 42);
        order_ok = (g_norder == 3 && g_order[0] == 3 && g_order[1] == 2 &&
                    g_order[2] == 1);
    } catch (...) {
        code_ok = 0;
    }
    snprintf(db, sizeof db, "code-ok=%d order-ok=%d n=%d", code_ok,
             order_ok, g_norder);
    check("unwind-depth", code_ok && order_ok, db);
}

__attribute__((noinline)) static void h4_throw_runtime(void)
{
    throw std::runtime_error("h4-inner");
}

__attribute__((noinline)) static void h4_middle_rethrow(void)
{
    try {
        h4_throw_runtime();
    } catch (const std::runtime_error &) {
        throw; /* rethrow preserves the dynamic type */
    }
}

static void t_unwind_rethrow(void)
{
    char db[160];
    int what_ok = 0;
    int star_ok = 0;

    try {
        h4_middle_rethrow();
    } catch (const std::runtime_error &e) {
        what_ok = (strcmp(e.what(), "h4-inner") == 0);
    } catch (...) {
        what_ok = 0;
    }
    try {
        throw 7;
    } catch (const H4Error &) {
        star_ok = 0;
    } catch (...) {
        star_ok = 1; /* catch(...) fallback catches the int */
    }
    /* std::function/lambda frames participate in unwinding too. */
    int lambda_code = 0;
    int lambda_order_ok = 0;
    std::function<void()> fn = [&]() {
        H4Guard g(9);
        throw H4Error{11};
    };
    g_norder = 0;
    try {
        fn();
    } catch (const H4Error &e) {
        lambda_code = e.code;
        lambda_order_ok = (g_norder == 1 && g_order[0] == 9);
    }
    snprintf(db, sizeof db, "what-ok=%d star-ok=%d lambda=%d lord=%d",
             what_ok, star_ok, lambda_code, lambda_order_ok);
    check("unwind-rethrow",
          what_ok && star_ok && lambda_code == 11 && lambda_order_ok, db);
}

/* ================= dynamic_cast RTTI ================= */

struct H4Animal {
    virtual ~H4Animal() {}
    virtual int legs() const = 0;
};

struct H4Dog : H4Animal {
    int legs() const override { return 4; }
    virtual void bark() {}
};

struct H4Fish : H4Animal {
    int legs() const override { return 0; }
};

struct H4Flyer {
    virtual ~H4Flyer() {}
    virtual void fly() {}
};

struct H4Duck : H4Animal, H4Flyer {
    int legs() const override { return 2; }
};

static void t_rtti(void)
{
    char db[160];
    H4Dog dog;
    H4Fish fish;
    H4Duck duck;
    H4Animal *as_dog = &dog;
    H4Animal *as_duck = &duck;
    int down_ok = 0;
    int fail_null_ok = 0;
    int cross_ok = 0;
    int badcast_ok = 0;
    int typeid_ok = 0;

    H4Dog *d = dynamic_cast<H4Dog *>(as_dog);
    down_ok = (d != NULL && d->legs() == 4);
    fail_null_ok = (dynamic_cast<H4Fish *>(as_dog) == NULL);
    /* Cross-cast through multiple inheritance: Animal -> Flyer. */
    H4Flyer *f = dynamic_cast<H4Flyer *>(as_duck);
    cross_ok = (f != NULL);
    try {
        H4Fish &fr = dynamic_cast<H4Fish &>(*as_dog);
        (void)fr;
        badcast_ok = 0;
    } catch (const std::bad_cast &) {
        badcast_ok = 1;
    }
    typeid_ok = (typeid(*as_dog) == typeid(H4Dog)) &&
                (typeid(*as_duck) == typeid(H4Duck)) &&
                (typeid(fish) == typeid(H4Fish)) &&
                (strcmp(typeid(H4Dog).name(), typeid(H4Fish).name()) != 0);
    snprintf(db, sizeof db, "down=%d null=%d cross=%d bad=%d tid=%d",
             down_ok, fail_null_ok, cross_ok, badcast_ok, typeid_ok);
    check("rtti-dynamic-cast",
          down_ok && fail_null_ok && cross_ok && badcast_ok && typeid_ok,
          db);
}

/* ================= std::thread launch/join/detach ================= */

static std::mutex g_h4_mu;
static int g_h4_sum;

static int h4_thread_work(int n)
{
    for (int i = 0; i < n; i++) {
        std::lock_guard<std::mutex> lk(g_h4_mu);
        g_h4_sum++;
    }
    return n;
}

static std::atomic<int> g_detached_done{0};

static void t_threads(void)
{
    char db[160];
    const int kThreads = 4;
    const int kIters = 1000;
    std::vector<std::thread> th;
    std::vector<int> got(kThreads, 0);

    g_h4_sum = 0;
    g_detached_done.store(0);
    for (int i = 0; i < kThreads; i++) {
        th.emplace_back([&, i]() { got[i] = h4_thread_work(kIters); });
    }
    /* One detached thread: completion is observed through an atomic
     * flag with a bounded wait so the output stays deterministic. */
    std::thread([]() {
        h4_thread_work(1);
        g_detached_done.store(1);
    }).detach();
    for (int i = 0; i < kThreads; i++) {
        th[i].join();
    }
    int spins = 0;
    while (g_detached_done.load() == 0 && spins < 1000000) {
        std::this_thread::yield();
        spins++;
    }
    int detached_ok = (g_detached_done.load() == 1);
    int ret_ok = 1;
    for (int i = 0; i < kThreads; i++) {
        if (got[i] != kIters) {
            ret_ok = 0;
        }
    }
    snprintf(db, sizeof db, "sum=%d ret-ok=%d detached-ok=%d", g_h4_sum,
             ret_ok, detached_ok);
    check("threads",
          g_h4_sum == kThreads * kIters + 1 && ret_ok && detached_ok, db);
}

/* ================= thread_local: dtor ordering + isolation ================= */

static std::atomic<int> g_tls_ctors{0};
static std::atomic<int> g_tls_dtors{0};
static std::atomic<int> g_tls_sum{0};

/* Non-trivial thread_local payload: the dtor has observable work. */
struct H4TlsGuard {
    int val;
    H4TlsGuard() : val(0) { g_tls_ctors.fetch_add(1); }
    ~H4TlsGuard() { g_tls_dtors.fetch_add(1); }
};

/* Errno-style per-thread slot: each thread must see only its own value. */
static thread_local int h4_tls_errno = 0;

static int h4_tls_counter(void)
{
    thread_local int per_thread = 0;
    return ++per_thread;
}

static std::atomic<int> g_tls_iso_fail{0};

static void h4_tls_work(int id, int n)
{
    thread_local H4TlsGuard g;
    g.val += n;
    g_tls_sum.fetch_add(n, std::memory_order_relaxed);
    /* Function-local thread_local starts at 1 in each fresh thread. */
    int first = h4_tls_counter();
    int second = h4_tls_counter();
    if (first != 1 || second != 2) {
        g_tls_sum.fetch_add(1000000, std::memory_order_relaxed);
    }
    /* Errno-style isolation: plant a per-thread value, do some work,
     * then confirm nobody else clobbered it. */
    h4_tls_errno = 1000 + id;
    std::this_thread::yield();
    h4_tls_counter();
    if (h4_tls_errno != 1000 + id) {
        g_tls_iso_fail.fetch_add(1);
    }
}

static void t_thread_local(void)
{
    char db[160];
    const int kThreads = 4;
    const int kIters = 250;
    std::vector<std::thread> th;

    g_tls_ctors.store(0);
    g_tls_dtors.store(0);
    g_tls_sum.store(0);
    g_tls_iso_fail.store(0);
    h4_tls_errno = 7; /* main thread plants its own value first */
    for (int i = 0; i < kThreads; i++) {
        th.emplace_back([=]() { h4_tls_work(i, kIters); });
    }
    for (int i = 0; i < kThreads; i++) {
        th[i].join();
    }
    /* thread_local Guards in joined threads are destroyed at thread
     * exit, so by the time join returns every worker Guard must be
     * constructed+destroyed. std::string exercises a nontrivial
     * thread_local type as well. */
    thread_local std::string scratch;
    scratch = "h4";
    int nctors = g_tls_ctors.load();
    int ndtors = g_tls_dtors.load();
    int sum = g_tls_sum.load();
    int iso_fail = g_tls_iso_fail.load();
    int main_iso_ok = (h4_tls_errno == 7);
    snprintf(db, sizeof db, "ctors=%d dtors=%d sum=%d iso-fail=%d str=%s",
             nctors, ndtors, sum, iso_fail, scratch.c_str());
    check("thread-local",
          nctors == kThreads && ndtors == kThreads &&
              sum == kThreads * kIters && iso_fail == 0 && main_iso_ok &&
              scratch == "h4",
          db);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    t_unwind_depth();
    t_unwind_rethrow();
    t_rtti();
    t_threads();
    t_thread_local();

    printf("H4 checks: %d pass, %d fail\n", g_pass, g_fail);
    if (g_fail == 0) {
        printf("H4-RESULT: PASS\n");
        return 0;
    }
    printf("H4-RESULT: FAIL\n");
    return 1;
}
