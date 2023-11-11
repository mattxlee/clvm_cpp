#ifndef CHIA_CODITION_OPCODE_H
#define CHIA_CODITION_OPCODE_H

#include <cstdint>

#include "types.h"

namespace chia {

struct ConditionOpcode {
    // AGG_SIG is ascii "1"

    // the conditions below require bls12-381 signatures

    static uint8_t AGG_SIG_UNSAFE[1];
    static uint8_t AGG_SIG_ME[1];

    // the conditions below reserve coin amounts and have to be accounted for in
    // output totals

    static uint8_t CREATE_COIN[1];
    static uint8_t RESERVE_FEE[1];

    // the conditions below deal with announcements, for inter-coin communication

    static uint8_t CREATE_COIN_ANNOUNCEMENT[1];
    static uint8_t ASSERT_COIN_ANNOUNCEMENT[1];
    static uint8_t CREATE_PUZZLE_ANNOUNCEMENT[1];
    static uint8_t ASSERT_PUZZLE_ANNOUNCEMENT[1];

    // the conditions below let coins inquire about themselves

    static uint8_t ASSERT_MY_COIN_ID[1];
    static uint8_t ASSERT_MY_PARENT_ID[1];
    static uint8_t ASSERT_MY_PUZZLEHASH[1];
    static uint8_t ASSERT_MY_AMOUNT[1];

    // the conditions below ensure that we're "far enough" in the future

    // wall-clock time
    static uint8_t ASSERT_SECONDS_RELATIVE[1];
    static uint8_t ASSERT_SECONDS_ABSOLUTE[1];

    // block index
    static uint8_t ASSERT_HEIGHT_RELATIVE[1];
    static uint8_t ASSERT_HEIGHT_ABSOLUTE[1];

    Bytes value;

    template <int N>
    static Bytes ToBytes(uint8_t(&op_code)[N]) {
        Bytes result(N, '\0');
        memcpy(result.data(), op_code, N);
        return result;
    }

    explicit ConditionOpcode(Bytes value)
        : value(std::move(value))
    {
    }

    explicit ConditionOpcode(uint8_t vals[1])
    {
        value.resize(1);
        value[0] = vals[0];
    }

    bool operator<(ConditionOpcode const& rhs) const { return value < rhs.value; }
};

struct ConditionWithArgs {
    ConditionOpcode opcode;
    std::vector<Bytes> vars;
};

} // namespace chia

#endif
