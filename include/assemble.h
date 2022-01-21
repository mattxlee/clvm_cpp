#ifndef CHIA_ASSEMBLE_H
#define CHIA_ASSEMBLE_H

#include <string_view>

#include "program.h"
#include "types.h"

namespace chia {

CLVMObjectPtr AssembleFromIR(std::string_view ir_sexp);

}  // namespace chia

#endif
