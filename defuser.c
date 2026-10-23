#include "defuser.h"

#include <inttypes.h>
#include <stdio.h>

#define MAX_FIELDS 8

/*
 * 把 values 中的 count 个整数写成一行“空格分隔的无符号十进制整数”，存入 out。
 * 成功返回 0；count 为 0（还没有实现）、snprintf 出错或结果被截断时返回非零。
 */
static int write_answer(char *out, size_t cap, const uint32_t *values, size_t count) {
    size_t used = 0;
    for (size_t i = 0; i < count; ++i) {
        int size = snprintf(out + used, cap - used, "%s%" PRIu32, i ? " " : "", values[i]);
        if (size < 0 || (size_t)size >= cap - used) return 1;
        used += (size_t)size;
    }
    return count == 0;
}

static uint32_t p1_step0(uint32_t a, uint32_t b) {
    return (b + 0x1840u) ^ a;
}

static uint32_t p1_step1(uint32_t a, uint32_t b) {
    return (a - b) * 5u + 0xc3b6u;
}

static uint32_t p1_step2(uint32_t a, uint32_t b) {
    return a * 8u + (b ^ 0xf276u);
}

static uint32_t p1_compute(uint64_t challenge) {
    uint32_t lo  = (uint32_t)challenge;
    uint32_t hi  = (uint32_t)(challenge >> 32);
    uint32_t mid = (uint32_t)(challenge >> 16);
    uint32_t t1 = p1_step1(hi, mid);
    uint32_t t0 = p1_step0(lo, hi);
    return p1_step2(t0, t1);
}

int solve_phase_1(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 1;
    values[0] = p1_compute(challenge);
    return write_answer(out, cap, values, count);
}

int solve_phase_2(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 6;
    values[0] = 3u * ((uint32_t)(challenge >> 20) & 0xfu);
    for (unsigned i = 1; i < 6; ++i) {
        uint32_t part = ((uint32_t)(challenge >> (10 + 5 * (i - 1))) & 0x3fu) ^ i;
        values[i] = values[i - 1] * 4u + part;
    }
    return write_answer(out, cap, values, count);
}

static uint32_t p3_case_0(uint32_t x) { return x * 3u + 0xf7b0u; }
static uint32_t p3_case_1(uint32_t x) { return x * 5u + 0x2f049u; }
static uint32_t p3_case_2(uint32_t x) { return (x ^ 0x14e1u) + (x >> 2); }
static uint32_t p3_case_3(uint32_t x) { return (x * 4u) ^ 0xa2d0u; }
static uint32_t p3_case_4(uint32_t x) { return (x ^ 0x148fu) + (x >> 1); }
static uint32_t p3_case_5(uint32_t x) { return x * 5u + 0x4c68au; }
static uint32_t p3_case_6(uint32_t x) { return (x * 4u) ^ 0x1272u; }
static uint32_t p3_case_7(uint32_t x) { return x * 5u + 0x9852u; }

static uint32_t p3_dispatch(uint32_t index, uint32_t x) {
    switch (index & 7u) {
        case 0:  return p3_case_1(x);
        case 1:  return p3_case_0(x);
        case 2:  return p3_case_3(x);
        case 3:  return p3_case_7(x);
        case 4:  return p3_case_4(x);
        case 5:  return p3_case_2(x);
        case 6:  return p3_case_6(x);
        default: return p3_case_5(x);
    }
}

int solve_phase_3(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 2;
    uint32_t idx = (uint32_t)challenge & 7u;
    uint32_t x   = (uint32_t)(challenge >> 32)^ (uint32_t)(challenge >> 3);
    values[0] = idx;
    values[1] = p3_dispatch(idx, x);
    return write_answer(out, cap, values, count);
}

static uint32_t p4_walk(uint32_t key, uint32_t lo, uint32_t hi, uint32_t salt) {
    uint32_t mid = lo + (hi - lo) / 2;
    if (key == mid) return (mid + 0x7eu) ^ salt;
    uint32_t t = mid + salt;
    if (key > mid) {
        uint32_t r = p4_walk(key, mid + 1u, hi, salt);
        return (r * 3u ^ t) ^ 0x2u;
    }
    uint32_t r = p4_walk(key, lo, mid - 1u, salt);
    return (r * 3u ^ t) ^ 0x15u;
}

int solve_phase_4(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 1;
    uint32_t salt = (uint32_t)(challenge >> 32) ^ (uint32_t)(challenge >> 7);
    values[0] = p4_walk((uint32_t)challenge & 0x7fu, 0u, 0x7fu, salt);
    return write_answer(out, cap, values, count);
}

struct p5_node {
    uint32_t f0;
    uint32_t f1;
    int      next;
};

static const struct p5_node p5_nodes[12] = {
    { 0xef46u, 0x352u, -1 },
    { 0x9973u, 0x164u,  3 },
    { 0x315fu, 0xb61u,  0 },
    { 0x1cfeu, 0x924u,  4 },
    { 0x6352u, 0x731u,  9 },
    { 0x1484u, 0xa71u,  2 },
    { 0x3cdau, 0x85du, 10 },
    { 0x3be3u, 0x53cu, 11 },
    { 0x491eu, 0x20au,  5 },
    { 0xe7a9u, 0x426u,  7 },
    { 0x6893u, 0x012u,  1 },
    { 0xc0e9u, 0x626u,  8 },
};

static const int p5_heads[8] = { 6, 10, 1, 3, 4, 9, 7, 11 };

static uint32_t p5_traverse(uint64_t challenge, uint32_t *last) {
    unsigned idx   = (unsigned)(challenge & 7u);
    unsigned steps = (unsigned)((challenge >> 3) & 3u);
    uint32_t x     = (uint32_t)(challenge >> 6) ^ (uint32_t)(challenge >> 32);

    int n = p5_heads[idx];
    uint32_t acc = (x ^ 0xa140u) * 3u + p5_nodes[n].f0;
    acc ^= p5_nodes[n].f1;
    *last = p5_nodes[n].f1;

    for (unsigned i = 0; i < steps; ++i) {
        n = p5_nodes[n].next;
        acc = acc * 3u + p5_nodes[n].f0;
        acc ^= p5_nodes[n].f1;
        *last = p5_nodes[n].f1;
    }
    return acc;
}

int solve_phase_5(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 2;
    uint32_t last = 0;
    values[0] = p5_traverse(challenge, &last);
    values[1] = last;
    return write_answer(out, cap, values, count);
}

static uint32_t p6_op_0(uint32_t x) { return (x ^ 0x26dfu) + x * 2u; }
static uint32_t p6_op_1(uint32_t x) { return (x >> 2) | (x << 30); }
static uint32_t p6_op_2(uint32_t x) { return ((x << 5) + 0x9b1au) ^ (x * 3u); }
static uint32_t p6_op_3(uint32_t x) { return (x + 0x2757u) ^ (x >> 3); }
static uint32_t p6_op_4(uint32_t x) { return ((x >> 2) ^ x) + 0x2e14u; }
static uint32_t p6_op_5(uint32_t x) { return ((x << 3) | (x >> 29)) ^ 0x2dacu; }

typedef uint32_t (*p6_fn)(uint32_t);

static const p6_fn p6_ops[8] = {
    p6_op_4,
    p6_op_3,
    p6_op_3,
    p6_op_0,
    p6_op_5,
    p6_op_0,
    p6_op_2,
    p6_op_1,
};

static uint32_t p6_dispatch(uint64_t challenge) {
    uint32_t x = (uint32_t)(challenge >> 6) ^ (uint32_t)(challenge >> 32);
    uint32_t first  = p6_ops[(unsigned)(challenge & 7u)](x);
    uint32_t second = p6_ops[(unsigned)((challenge >> 3) & 7u)](first ^ 0x502du);
    return second + 0x42au;
}

int solve_phase_6(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 1;
    values[0] = p6_dispatch(challenge);
    return write_answer(out, cap, values, count);
}

static uint32_t secret_mix(uint32_t x) {
    return ((x >> 3) ^ 0xbe4eu) + (x ^ 0xc249u);
}

int solve_secret(uint64_t challenge, uint64_t context, char *out, size_t cap) {
    uint32_t a = (uint32_t)challenge ^ (uint32_t)(challenge >> 32);
    uint32_t b = (uint32_t)context   ^ (uint32_t)(context   >> 32);
    uint32_t c = (uint32_t)context & 3u;

    uint32_t v0 = c;
    uint32_t v1 = secret_mix(a ^ b) ^ ((c * 0xc249u) ^ (uint32_t)(context >> 16));
    uint32_t v2 = v1 ^ (b + c + 0xbe4eu + (a >> 3));

    static const char gate[] = "0123456789abcdefghijklmnopqrstuvOPEN";

    int size = snprintf(out, cap, "%s %" PRIu32 " %" PRIu32 " %" PRIu32,
                        gate, v0, v1, v2);
    if (size < 0 || (size_t)size >= cap) return 1;
    return 0;
}
