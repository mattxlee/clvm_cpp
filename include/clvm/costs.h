#ifndef CHIA_COSTS_H
#define CHIA_COSTS_H

#include <cstdint>

namespace chia
{

uint64_t const INFINITE_COST = 0x7FFFFFFFFFFFFFFF;

int const IF_COST = 33;
int const CONS_COST = 50;
int const FIRST_COST = 30;
int const REST_COST = 30;
int const LISTP_COST = 19;

int const MALLOC_COST_PER_BYTE = 10;

int const ARITH_BASE_COST = 99;
int const ARITH_COST_PER_BYTE = 3;
int const ARITH_COST_PER_ARG = 320;

int const LOG_BASE_COST = 100;
int const LOG_COST_PER_BYTE = 3;
int const LOG_COST_PER_ARG = 264;

int const GRS_BASE_COST = 117;
int const GRS_COST_PER_BYTE = 1;

int const EQ_BASE_COST = 117;
int const EQ_COST_PER_BYTE = 1;

int const GR_BASE_COST = 498;
int const GR_COST_PER_BYTE = 2;

int const DIVMOD_BASE_COST = 1116;
int const DIVMOD_COST_PER_BYTE = 6;

int const DIV_BASE_COST = 988;
int const DIV_COST_PER_BYTE = 4;

int const SHA256_BASE_COST = 87;
int const SHA256_COST_PER_ARG = 134;
int const SHA256_COST_PER_BYTE = 2;

int const POINT_ADD_BASE_COST = 101094;
int const POINT_ADD_COST_PER_ARG = 1343980;

int const PUBKEY_BASE_COST = 1325730;
int const PUBKEY_COST_PER_BYTE = 38;

int const MUL_BASE_COST = 92;
int const MUL_COST_PER_OP = 885;
int const MUL_LINEAR_COST_PER_BYTE = 6;
int const MUL_SQUARE_COST_PER_BYTE_DIVIDER = 128;

int const STRLEN_BASE_COST = 173;
int const STRLEN_COST_PER_BYTE = 1;

int const PATH_LOOKUP_BASE_COST = 40;
int const PATH_LOOKUP_COST_PER_LEG = 4;
int const PATH_LOOKUP_COST_PER_ZERO_BYTE = 4;

int const CONCAT_BASE_COST = 142;
int const CONCAT_COST_PER_ARG = 135;
int const CONCAT_COST_PER_BYTE = 3;

int const BOOL_BASE_COST = 200;
int const BOOL_COST_PER_ARG = 300;

int const ASHIFT_BASE_COST = 596;
int const ASHIFT_COST_PER_BYTE = 3;

int const LSHIFT_BASE_COST = 277;
int const LSHIFT_COST_PER_BYTE = 3;

int const LOGNOT_BASE_COST = 331;
int const LOGNOT_COST_PER_BYTE = 3;

int const APPLY_COST = 90;
int const QUOTE_COST = 20;

} // namespace chia

#endif
