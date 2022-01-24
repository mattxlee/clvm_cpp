#ifndef CHIA_OPERATOR_LOOKUP_H
#define CHIA_OPERATOR_LOOKUP_H

#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <tuple>

#include "program.h"

namespace chia {

using OpFunc =
    std::function<std::tuple<int, CLVMObjectPtr>(CLVMObjectPtr args)>;

class Ops {
 public:
  static Ops& GetInstance();

  void Assign(std::string_view op_name, OpFunc f);

  OpFunc Query(std::string_view op_name);

 private:
  Ops();

 private:
  std::map<std::string, OpFunc> ops_;
};

class OperatorLookup {
 public:
  Bytes QUOTE_ATOM;
  Bytes APPLY_ATOM;

  OperatorLookup();

  std::tuple<int, CLVMObjectPtr> operator()(Bytes const& op,
                                            CLVMObjectPtr args) const;

  std::string AtomToKeyword(uint8_t a) const;

  uint8_t KeywordToAtom(std::string_view keyword) const;

  int GetCount() const;

 private:
  void InitKeywords();

 private:
  std::map<uint8_t, std::string> atom_to_keyword_;
  std::map<std::string, uint8_t> keyword_to_atom_;
};

}  // namespace chia

#endif
