#ifndef CHIA_PROGRAM_H
#define CHIA_PROGRAM_H

#include "types.h"

namespace chia {

static std::string_view DEFAULT_HIDDEN_PUZZLE = "ff0980";

class Result {
 public:
};

class Program {
 public:
  static Program ImportFromBytes(Bytes const& bytes);

  static Program LoadFromFile(std::string_view file_path);

  Bytes32 GetTreeHash();

  template <typename... P>
  Result Run(P const&&... p) {}

 private:
  Program() {}
};

}  // namespace chia

#endif
