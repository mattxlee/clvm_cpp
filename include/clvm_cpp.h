#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

static const uint32_t STRICT_MODE = 1;

using ConditionOpcode = uint8_t;

using Cost = uint64_t;

static const ConditionOpcode AGG_SIG_UNSAFE = 49;

static const ConditionOpcode AGG_SIG_ME = 50;

static const ConditionOpcode CREATE_COIN = 51;

static const ConditionOpcode RESERVE_FEE = 52;

static const ConditionOpcode CREATE_COIN_ANNOUNCEMENT = 60;

static const ConditionOpcode ASSERT_COIN_ANNOUNCEMENT = 61;

static const ConditionOpcode CREATE_PUZZLE_ANNOUNCEMENT = 62;

static const ConditionOpcode ASSERT_PUZZLE_ANNOUNCEMENT = 63;

static const ConditionOpcode ASSERT_MY_COIN_ID = 70;

static const ConditionOpcode ASSERT_MY_PARENT_ID = 71;

static const ConditionOpcode ASSERT_MY_PUZZLEHASH = 72;

static const ConditionOpcode ASSERT_MY_AMOUNT = 73;

static const ConditionOpcode ASSERT_SECONDS_RELATIVE = 80;

static const ConditionOpcode ASSERT_SECONDS_ABSOLUTE = 81;

static const ConditionOpcode ASSERT_HEIGHT_RELATIVE = 82;

static const ConditionOpcode ASSERT_HEIGHT_ABSOLUTE = 83;

static const Cost CREATE_COIN_COST = 1800000;

static const Cost AGG_SIG_COST = 1200000;

extern "C" {

int32_t hello();

uint64_t run_chia_program(const uint8_t *_prog,
                          uintptr_t _prog_len,
                          const uint8_t *_args,
                          uintptr_t _args_len,
                          uint8_t *_res,
                          uintptr_t *_res_len,
                          uint64_t _max_cost,
                          uint32_t _flags);

} // extern "C"
