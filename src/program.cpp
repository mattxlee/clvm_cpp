#include "program.h"

namespace chia {

Program Program::ImportFromBytes(Bytes const& bytes) { return Program(); }

Program Program::LoadFromFile(std::string_view file_path) { return Program(); }

Bytes32 Program::GetTreeHash() { return Bytes32(); }

}  // namespace chia
