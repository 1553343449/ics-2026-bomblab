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

int solve_phase_1(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 1;
    uint32_t h = (uint32_t)(challenge >> 32);
    uint32_t m = (uint32_t)(challenge >> 16);
    uint32_t l = (uint32_t)challenge;

    // 按已分析的调用顺序计算；uint32_t 保留各步结果的低 32 位。
    uint32_t t1 = (m ^ 0xa5deu) + 2u * h;
    uint32_t t0 = (5u * l) ^ (h + 0xbf84u);
    values[0] = (t1 + 0xd2d7u) ^ t0;
    return write_answer(out, cap, values, count);
}

int solve_phase_2(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 6;

    values[0] = (uint32_t)((((challenge >> 47) * 2u) & 0x7eu) + 4u);
    for (uint32_t i = 1; i < count; ++i) {
        unsigned shift = 4u * i + 22u;
        uint32_t field = (uint32_t)(challenge >> shift) & 0x3fu;
        values[i] = 2u * values[i - 1] + (field ^ i);
    }
    return write_answer(out, cap, values, count);
}

int solve_phase_3(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 2;
    uint32_t a = (uint32_t)challenge & 7u;
    uint32_t x = (uint32_t)(challenge >> 3)
               ^ (uint32_t)(challenge >> 32);

    values[0] = a;
    // 按跳转表索引排列，而非 p3_case 函数名中的编号。
    switch (a) {
        case 0: values[1] = 5u * x + 0x42e4bu; break;
        case 1: values[1] = (x ^ 0x387u) + (x >> 1); break;
        case 2: values[1] = (x ^ 0x5a62u) + (x >> 1); break;
        case 3: values[1] = 3u * x + 0x79cbu; break;
        case 4: values[1] = (4u * x) ^ 0xd2b2u; break;
        case 5: values[1] = 5u * x + 0x152cfu; break;
        case 6: values[1] = (2u * x) ^ 0xe113u; break;
        case 7: values[1] = 5u * x + 0x55fu; break;
    }
    return write_answer(out, cap, values, count);
}

static uint32_t p4_walk(uint32_t x, uint32_t low, uint32_t high, uint32_t k) {
    uint32_t m = low + ((high - low) >> 1);
    if (x == m) return (m + 0x94u) ^ k;

    // 递归返回后，使用当前层的中点合并结果。
    if (x < m) {
        uint32_t r = p4_walk(x, low, m - 1u, k);
        return (3u * r) ^ (m + k) ^ 0x15u;
    }
    uint32_t r = p4_walk(x, m + 1u, high, k);
    return (3u * r) ^ (m + k) ^ 0x1fu;
}

int solve_phase_4(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 1;
    uint32_t x = (uint32_t)challenge & 0x7fu;
    uint32_t k = (uint32_t)(challenge >> 7)
               ^ (uint32_t)(challenge >> 32);

    values[0] = p4_walk(x, 0u, 127u, k);
    return write_answer(out, cap, values, count);
}

int solve_phase_5(uint64_t challenge, char *out, size_t cap) {
    // 节点按原地址从 0x405ba0 起每隔 16 字节编号；next 用索引表示。
    static const struct {
        uint32_t v;
        uint32_t tag;
        unsigned next;
    } nodes[] = {
        {0xd2cdu, 0xa61u, 5},
        {0xfe69u, 0x63du, 0},
        {0xe583u, 0xb52u, 10},
        {0xb699u, 0x734u, 1},
        {0x973bu, 0x953u, 8},
        {0xfb86u, 0x46bu, 4},
        {0x8527u, 0x275u, 2},
        {0x39e8u, 0x14cu, 11},
        {0xecacu, 0x526u, 6},
        {0x3ef2u, 0x313u, 3},
        {0x2e6au, 0x016u, 7},
        {0x4233u, 0x87fu, 12}, // 12 表示空指针，合法遍历不会走到此处的 next。
    };
    static const unsigned heads[] = {9, 3, 1, 0, 5, 4, 8, 6};
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 2;
    unsigned node = heads[(uint32_t)challenge & 7u];
    uint32_t q = (uint32_t)(challenge >> 3) & 3u;
    uint32_t s = (uint32_t)(challenge >> 6)
               ^ (uint32_t)(challenge >> 32) ^ 0x7a7au;

    for (uint32_t i = 0; i <= q; ++i) {
        s = (5u * (s + nodes[node].v)) ^ nodes[node].tag;
        values[1] = nodes[node].tag;
        if (i < q) node = nodes[node].next;
    }
    values[0] = s;
    return write_answer(out, cap, values, count);
}

static uint32_t p6_op_0(uint32_t x) {
    return (x >> 1) | (x << 31);
}

static uint32_t p6_op_1(uint32_t x) {
    return ((x >> 5) ^ x) + 0xef36u;
}

static uint32_t p6_op_2(uint32_t x) {
    return (x ^ 0xcc0bu) + 4u * x;
}

static uint32_t p6_op_3(uint32_t x) {
    return ((x << 5) | (x >> 27)) ^ 0xc33au;
}

static uint32_t p6_op_4(uint32_t x) {
    return ((x << 7) + 0xb7c2u) ^ (7u * x);
}

static uint32_t p6_op_5(uint32_t x) {
    return (x + 0x8c13u) ^ (x >> 5);
}

int solve_phase_6(uint64_t challenge, char *out, size_t cap) {
    static uint32_t (*const ops[])(uint32_t) = {
        p6_op_4, p6_op_3, p6_op_1, p6_op_5,
        p6_op_0, p6_op_2, p6_op_5, p6_op_3,
    };
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 1;
    uint32_t x = (uint32_t)(challenge >> 6)
               ^ (uint32_t)(challenge >> 32);
    uint32_t i = (uint32_t)challenge & 7u;
    uint32_t j = (uint32_t)(challenge >> 3) & 7u;

    uint32_t r = ops[i](x);
    r ^= 0x83fbu;
    r = ops[j](r);
    values[0] = r + 0x6067u;
    return write_answer(out, cap, values, count);
}

static uint32_t secret_mix(uint32_t x) {
    return ((x >> 1) ^ 0x3746u) + (x ^ 0xbfebu);
}

int solve_secret(uint64_t challenge, uint64_t context, char *out, size_t cap) {
    uint32_t p = (uint32_t)challenge ^ (uint32_t)(challenge >> 32);
    uint32_t q = (uint32_t)context ^ (uint32_t)(context >> 32);
    uint32_t a = (uint32_t)context & 3u;
    uint32_t t = (a * 0xbfebu) ^ (uint32_t)(context >> 16);
    uint32_t b = secret_mix(p ^ q) ^ t;
    uint32_t c = b ^ (q + a + 0x3746u + (p >> 1));

    // 偏移 32 写入 OPEN，偏移 36 开始是三个无符号十进制整数。
    int size = snprintf(out, cap,
                        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOPEN"
                        "%" PRIu32 " %" PRIu32 " %" PRIu32,
                        a, b, c);
    return size < 0 || (size_t)size >= cap;
}
