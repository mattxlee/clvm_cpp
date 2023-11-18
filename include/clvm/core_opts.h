#ifndef CHIA_CORE_OPS_H
#define CHIA_CORE_OPS_H

#include <tuple>

#include "sexp_prog.h"

namespace chia
{

using OpResult = std::tuple<Cost, CLVMObjectPtr>;

OpResult op_if(CLVMObjectPtr args);

OpResult op_cons(CLVMObjectPtr args);

OpResult op_first(CLVMObjectPtr args);

OpResult op_rest(CLVMObjectPtr args);

OpResult op_listp(CLVMObjectPtr args);

OpResult op_raise(CLVMObjectPtr args);

OpResult op_eq(CLVMObjectPtr args);

} // namespace chia

#endif
