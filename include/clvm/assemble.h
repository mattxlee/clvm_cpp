#ifndef CHIA_ASSEMBLE_H
#define CHIA_ASSEMBLE_H

#include <string>

#include "sexp_prog.h"

namespace chia
{

CLVMObjectPtr Assemble(std::string str);

} // namespace chia

#endif
