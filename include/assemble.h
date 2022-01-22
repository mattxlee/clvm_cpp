#ifndef CHIA_ASSEMBLE_H
#define CHIA_ASSEMBLE_H

#include <string_view>

#include "program.h"
#include "types.h"

namespace chia {

CLVMObjectPtr Assemble(std::string_view str);

}  // namespace chia

#endif
