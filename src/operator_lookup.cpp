#include "operator_lookup.h"

#include "core_opts.h"
#include "costs.h"
#include "more_opts.h"
#include "program.h"
#include "utils.h"

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

std::tuple<int, CLVMObjectPtr> default_unknown_op(Bytes const& op,
                                                  CLVMObjectPtr args) {
  if (op.empty() || (op.size() > 2 && op[0] == 0xff && op[1] == 0xff)) {
    throw std::runtime_error("reserved operator");
  }

  Cost cost_function = (*op.rbegin() & 0b11000000) >> 6;

  if (op.size() > 5) {
    throw std::runtime_error("invalid operator");
  }

  Cost cost_multiplier = Int(utils::ByteToBytes(*op.rbegin())).ToInt() + 1;

  Cost cost{0};
  if (cost_function == 0) {
    cost = 1;
  } else if (cost_function == 1) {
    cost = ARITH_BASE_COST;
    int arg_size = ArgsLen(args);
    int num_args = ListLen(args);
    cost += arg_size * ARITH_COST_PER_BYTE + num_args * ARITH_COST_PER_ARG;
  } else if (cost_function == 2) {
    cost = MUL_BASE_COST;
    try {
      auto [ok, b, next] = ArgsNext(args);
      int vs = b.size();
      while (ok) {
        auto [ok, b, n] = ArgsNext(next);
        if (ok) {
          int rs = b.size();
          cost += MUL_COST_PER_OP;
          cost += (rs + vs) * MUL_LINEAR_COST_PER_BYTE;
          cost += (rs * vs) / MUL_SQUARE_COST_PER_BYTE_DIVIDER;
          vs += rs;
          next = n;
        }
      }
    } catch (std::exception const& e) {
      // TODO ignored exception should be caught
    }
  } else if (cost_function == 3) {
    cost = CONCAT_BASE_COST;
    int length = ArgsLen(args);
    cost += CONCAT_COST_PER_BYTE * length + ListLen(args) * CONCAT_COST_PER_ARG;
  }

  cost *= cost_multiplier;
  if (cost >= (1L << 32)) {
    throw std::runtime_error("invalid operator");
  }

  return std::make_tuple(cost, CLVMObjectPtr());
}

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
  // Core operators
  Assign("op_if", op_if);
  Assign("op_cons", op_cons);
  Assign("op_first", op_first);
  Assign("op_rest", op_rest);
  Assign("op_listp", op_listp);
  Assign("op_raise", op_raise);
  Assign("op_eq", op_eq);
  // More operators
  Assign("op_sha256", op_sha256);
  Assign("op_add", op_add);
  Assign("op_subtract", op_subtract);
  Assign("op_multiply", op_multiply);
  Assign("op_divmod", op_divmod);
  Assign("op_div", op_div);
  Assign("op_gr", op_gr);
  Assign("op_gr_bytes", op_gr_bytes);
  Assign("op_pubkey_for_exp", op_pubkey_for_exp);
  Assign("op_point_add", op_point_add);
  Assign("op_strlen", op_strlen);
  Assign("op_substr", op_substr);
  Assign("op_concat", op_concat);
  Assign("op_ash", op_ash);
  Assign("op_lsh", op_lsh);
  Assign("op_logand", op_logand);
  Assign("op_logior", op_logior);
  Assign("op_logxor", op_logxor);
  Assign("op_lognot", op_lognot);
  Assign("op_not", op_not);
  Assign("op_any", op_any);
  Assign("op_all", op_all);
  Assign("op_softfork", op_softfork);
}

OperatorLookup::OperatorLookup() {
  InitKeywords();
  QUOTE_ATOM = utils::ByteToBytes(keyword_to_atom_["q"]);
  APPLY_ATOM = utils::ByteToBytes(keyword_to_atom_["a"]);
}

std::tuple<int, CLVMObjectPtr> OperatorLookup::operator()(
    Bytes const& op, CLVMObjectPtr args) const {
  auto i = atom_to_keyword_.find(op[0]);
  if (i != std::end(atom_to_keyword_)) {
    auto op_f = Ops::GetInstance().Query(i->second);
    if (op_f) {
      return op_f(args);
    }
  }
  return default_unknown_op(op, args);
}

std::string OperatorLookup::AtomToKeyword(uint8_t a) const {
  auto i = atom_to_keyword_.find(a);
  if (i != std::end(atom_to_keyword_)) {
    return i->second;
  }
  throw std::runtime_error("keyword cannot be found by the atom");
}

uint8_t OperatorLookup::KeywordToAtom(std::string_view keyword) const {
  auto i = keyword_to_atom_.find(keyword.data());
  if (i != std::end(keyword_to_atom_)) {
    return i->second;
  }
  throw std::runtime_error("atom cannot be found by the keyword");
}

void OperatorLookup::InitKeywords() {
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
    atom_to_keyword_[byte] = keyword;
    keyword_to_atom_[keyword] = byte;
    // Ready for next
    ++byte;
    start = next + 1;
    next = KEYWORDS.find(" ", start);
  }
}

}  // namespace chia
