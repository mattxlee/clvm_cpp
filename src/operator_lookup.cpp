#include "operator_lookup.h"

#include "core_opts.h"

namespace chia {

static std::string_view KEYWORDS =
    // core opcodes 0x01-x08
    ". q a i c f r l x "

    // opcodes on atoms as strings 0x09-0x0f
    "= >s sha256 substr strlen concat . "

    // opcodes on atoms as ints 0x10-0x17
    "+ - * / divmod > ash lsh "

    // opcodes on atoms as vectors of bools 0x18-0x1c
    "logand logior logxor lognot . "

    // opcodes for bls 1381 0x1d-0x1f
    "point_add pubkey_for_exp . "

    // bool opcodes 0x20-0x23
    "not any all . "

    // misc 0x24
    "softfork ";

std::map<std::string, std::string> OP_REWRITE = {
    {"+", "add"},       {"-", "subtract"}, {"*", "multiply"}, {"/", "div"},
    {"i", "if"},        {"c", "cons"},     {"f", "first"},    {"r", "rest"},
    {"l", "listp"},     {"x", "raise"},    {"=", "eq"},       {">", "gr"},
    {">s", "gr_bytes"},
};

Ops& Ops::GetInstance() {
  static Ops instance;
  return instance;
}

void Ops::Assign(std::string_view op_name, OpFunc f) {
  ops_[op_name.data()] = std::move(f);
}

OpFunc Ops::Query(std::string_view op_name) {
  auto i = ops_.find(op_name.data());
  if (i == std::end(ops_)) {
    return OpFunc();  // an empty op indicates the op cannot be found
  }
  return i->second;
}

Ops::Ops() {
  Assign("op_if", op_if);
  Assign("op_cons", op_cons);
  Assign("op_first", op_first);
  Assign("op_rest", op_rest);
  Assign("op_listp", op_listp);
  Assign("op_raise", op_raise);
  Assign("op_eq", op_eq);
}

OperatorLookup::OperatorLookup() {
  std::string::size_type start{0};
  uint8_t byte{0};
  auto next = KEYWORDS.find(" ", start);
  while (next != std::string::npos) {
    std::string keyword = KEYWORDS.substr(start, next - start).data();
    // Replace the keyword with OP_REWRITE
    auto i = OP_REWRITE.find(keyword);
    if (i != std::end(OP_REWRITE)) {
      // Override the keyword
      keyword = i->second;
    }
    atom_to_keyword_[byte++] = keyword;
    start = next + 1;
  }
}

std::tuple<int, CLVMObjectPtr> OperatorLookup::operator()(
    Bytes const& op, CLVMObjectPtr operand_list) const {
  auto i = atom_to_keyword_.find(op[0]);
  if (i == std::end(atom_to_keyword_)) {
    // TODO the op cannot be found
  }
  auto op_f = Ops::GetInstance().Query(i->second);
  if (!op_f) {
    // TODO the op cannot be found
  }
  return op_f(operand_list);
}

}  // namespace chia
