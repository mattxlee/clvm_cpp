#ifndef CHIA_ASSEMBLE_H
#define CHIA_ASSEMBLE_H

#include <string>

#include "program.h"

namespace chia
{

CLVMObjectPtr Assemble(std::string str);

} // namespace chia

#endif
