#include "condition_opcode.h"

namespace chia {

uint8_t ConditionOpcode::AGG_SIG_UNSAFE[1] = { 49 };
uint8_t ConditionOpcode::AGG_SIG_ME[1] = { 50 };

// the conditions below reserve coin amounts and have to be accounted for in
// output totals

uint8_t ConditionOpcode::CREATE_COIN[1] = { 51 };
uint8_t ConditionOpcode::RESERVE_FEE[1] = { 52 };

// the conditions below deal with announcements, for inter-coin communication

uint8_t ConditionOpcode::CREATE_COIN_ANNOUNCEMENT[1] = { 60 };
uint8_t ConditionOpcode::ASSERT_COIN_ANNOUNCEMENT[1] = { 61 };
uint8_t ConditionOpcode::CREATE_PUZZLE_ANNOUNCEMENT[1] = { 62 };
uint8_t ConditionOpcode::ASSERT_PUZZLE_ANNOUNCEMENT[1] = { 63 };

// the conditions below let coins inquire about themselves

uint8_t ConditionOpcode::ASSERT_MY_COIN_ID[1] = { 70 };
uint8_t ConditionOpcode::ASSERT_MY_PARENT_ID[1] = { 71 };
uint8_t ConditionOpcode::ASSERT_MY_PUZZLEHASH[1] = { 72 };
uint8_t ConditionOpcode::ASSERT_MY_AMOUNT[1] = { 73 };

// the conditions below ensure that we're "far enough" in the future

// wall-clock time
uint8_t ConditionOpcode::ASSERT_SECONDS_RELATIVE[1] = { 80 };
uint8_t ConditionOpcode::ASSERT_SECONDS_ABSOLUTE[1] = { 81 };

// block index
uint8_t ConditionOpcode::ASSERT_HEIGHT_RELATIVE[1] = { 82 };
uint8_t ConditionOpcode::ASSERT_HEIGHT_ABSOLUTE[1] = { 83 };

} // namespace chia
