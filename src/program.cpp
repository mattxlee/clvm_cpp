#include "program.h"

#include <memory>
#include <stdexcept>

#include "costs.h"
#include "crypto_utils.h"
#include "operator_lookup.h"
#include "utils.h"

namespace chia {

uint8_t const MAX_SINGLE_BYTE = 0x7F;
uint8_t const CONS_BOX_MARKER = 0xFF;

/**
 * =============================================================================
 * CLVMObject
 * =============================================================================
 */

CLVMObject::CLVMObject(NodeType type) : type_(type) {}

CLVMObject_Atom::CLVMObject_Atom(Bytes bytes)
    : CLVMObject(NodeType::Atom), bytes_(std::move(bytes)) {}

Bytes CLVMObject_Atom::GetBytes() const { return bytes_; }

CLVMObject_Pair::CLVMObject_Pair(CLVMObjectPtr first, CLVMObjectPtr second)
    : CLVMObject(NodeType::Pair), first_(first), second_(second) {}

CLVMObjectPtr CLVMObject_Pair::GetFirstNode() const { return first_; }

CLVMObjectPtr CLVMObject_Pair::GetSecondNode() const { return second_; }

Bytes Atom(CLVMObjectPtr obj) {
  if (obj->GetNodeType() != NodeType::Atom) {
    throw std::runtime_error("it's not an ATOM");
  }
  auto atom = static_cast<CLVMObject_Atom*>(obj.get());
  return atom->GetBytes();
}

std::tuple<CLVMObjectPtr, CLVMObjectPtr> Pair(CLVMObjectPtr obj) {
  if (obj->GetNodeType() != NodeType::Pair) {
    throw std::runtime_error("it's not a PAIR");
  }
  auto pair = static_cast<CLVMObject_Pair*>(obj.get());
  return std::make_tuple(pair->GetFirstNode(), pair->GetSecondNode());
}

CLVMObjectPtr First(CLVMObjectPtr obj) {
  if (obj->GetNodeType() != NodeType::Pair) {
    throw std::runtime_error("it's not a PAIR");
  }
  auto pair = static_cast<CLVMObject_Pair*>(obj.get());
  return pair->GetFirstNode();
}

CLVMObjectPtr Rest(CLVMObjectPtr obj) {
  if (obj->GetNodeType() != NodeType::Pair) {
    throw std::runtime_error("it's not a PAIR");
  }
  auto pair = static_cast<CLVMObject_Pair*>(obj.get());
  return pair->GetSecondNode();
}

bool IsNull(CLVMObjectPtr obj) {
  if (obj->GetNodeType() != NodeType::Atom) {
    return false;
  }
  CLVMObject_Atom* atom = static_cast<CLVMObject_Atom*>(obj.get());
  Bytes bytes = atom->GetBytes();
  return bytes.empty();
}

int ListLen(CLVMObjectPtr list) {
  int count{0};
  while (list->GetNodeType() == NodeType::Pair) {
    ++count;
    std::tie(std::ignore, list) = Pair(list);
  }
  return count;
}

/**
 * =============================================================================
 * Op: SExp
 * =============================================================================
 */

CLVMObjectPtr ToSExp(Bytes bytes) {
  return CLVMObjectPtr(new CLVMObject_Atom(std::move(bytes)));
}

CLVMObjectPtr ToSExp(CLVMObjectPtr first, CLVMObjectPtr second) {
  return CLVMObjectPtr(new CLVMObject_Pair(first, second));
}

CLVMObjectPtr ToTrue() { return ToSExp(utils::ByteToBytes('\1')); }

CLVMObjectPtr ToFalse() { return ToSExp(Bytes()); }

bool ListP(CLVMObjectPtr obj) { return obj->GetNodeType() == NodeType::Pair; }

/**
 * =============================================================================
 * SExp Stream
 * =============================================================================
 */

namespace stream {

class OpStack;

using Op = std::function<void(OpStack&, ValStack&, StreamReadFunc&)>;

class OpStack : public Stack<Op> {};

class StreamReader {
 public:
  explicit StreamReader(Bytes const& bytes) : bytes_(bytes) {}

  Bytes operator()(int size) const {
    Bytes res;
    int read_size = std::min<std::size_t>(size, bytes_.size() - pos_);
    if (read_size == 0) {
      return res;
    }
    res.resize(read_size);
    memcpy(res.data(), bytes_.data() + pos_, read_size);
    pos_ += read_size;
    return res;
  }

 private:
  Bytes const& bytes_;
  mutable int pos_{0};
};

CLVMObjectPtr AtomFromStream(StreamReadFunc f, uint8_t b) {
  if (b == 0x80) {
    return ToSExp(Bytes());
  }
  if (b <= MAX_SINGLE_BYTE) {
    return ToSExp(utils::ByteToBytes(b));
  }
  int bit_count{0};
  int bit_mask{0x80};
  while (b & bit_mask) {
    bit_count += 1;
    b &= 0xff ^ bit_mask;
    bit_mask >>= 1;
  }
  Bytes size_blob = utils::ByteToBytes(b);
  if (bit_count > 1) {
    Bytes b = f(bit_count - 1);
    if (b.size() != bit_count - 1) {
      throw std::runtime_error("bad encoding");
    }
    size_blob = utils::ConnectBuffers(size_blob, b);
  }
  auto size = utils::IntFromBytesBE<uint64_t>(size_blob);
  if (size >= 0x400000000) {
    throw std::runtime_error("blob too large");
  }
  Bytes blob = f(size);
  if (blob.size() != size) {
    throw std::runtime_error("bad encoding");
  }
  return ToSExp(blob);
}

void OpCons(OpStack& op_stack, ValStack& val_stack, StreamReadFunc& f) {
  auto right = val_stack.Pop();
  auto left = val_stack.Pop();
  val_stack.Push(ToSExp(left, right));
}

void OpReadSExp(OpStack& op_stack, ValStack& val_stack, StreamReadFunc& f) {
  Bytes blob = f(1);
  if (blob.empty()) {
    throw std::runtime_error("bad encoding");
  }
  uint8_t b = blob[0];
  if (b == CONS_BOX_MARKER) {
    op_stack.Push(OpCons);
    op_stack.Push(OpReadSExp);
    op_stack.Push(OpReadSExp);
    return;
  }
  val_stack.Push(AtomFromStream(f, b));
}

CLVMObjectPtr SExpFromStream(ReadStreamFunc f) {
  OpStack op_stack;
  op_stack.Push(OpReadSExp);
  ValStack val_stack;

  while (!op_stack.IsEmpty()) {
    auto func = op_stack.Pop();
    func(op_stack, val_stack, f);
  }
  return val_stack.Pop();
}

}  // namespace stream

/**
 * =============================================================================
 * Tree hash
 * =============================================================================
 */

namespace tree_hash {

class OpStack;
using Op = std::function<void(Stack<CLVMObjectPtr>&, OpStack&)>;

class OpStack : public Stack<Op> {};

Bytes32 SHA256TreeHash(
    CLVMObjectPtr sexp,
    std::vector<Bytes> const& precalculated = std::vector<Bytes>()) {
  Op handle_pair = [](ValStack& sexp_stack, OpStack& op_stack) {
    auto p0 = sexp_stack.Pop();
    auto p1 = sexp_stack.Pop();
    Bytes prefix = utils::ByteToBytes('\2');
    sexp_stack.Push(ToSExp(utils::bytes_cast<32>(crypto_utils::MakeSHA256(
        utils::ConnectBuffers(prefix, Atom(p0), Atom(p1))))));
  };

  Op roll = [](ValStack& sexp_stack, OpStack& op_stack) {
    auto p0 = sexp_stack.Pop();
    auto p1 = sexp_stack.Pop();
    sexp_stack.Push(p0);
    sexp_stack.Push(p1);
  };

  Op handle_sexp = [&handle_sexp, &handle_pair, &roll, &precalculated](
                       ValStack& sexp_stack, OpStack& op_stack) {
    auto sexp = sexp_stack.Pop();
    if (sexp->GetNodeType() == NodeType::Pair) {
      auto [p0, p1] = Pair(sexp);
      sexp_stack.Push(p0);
      sexp_stack.Push(p1);
      op_stack.Push(handle_pair);
      op_stack.Push(handle_sexp);
      op_stack.Push(roll);
      op_stack.Push(handle_sexp);
    } else {
      Bytes atom = Atom(sexp);
      auto i =
          std::find(std::begin(precalculated), std::end(precalculated), atom);
      Bytes r;
      if (i != std::end(precalculated)) {
        r = atom;
      } else {
        Bytes prefix = utils::ByteToBytes('\1');
        r = utils::bytes_cast<32>(
            crypto_utils::MakeSHA256(utils::ConnectBuffers(prefix, atom)));
      }
      sexp_stack.Push(ToSExp(r));
    }
  };

  ValStack sexp_stack;
  sexp_stack.Push(sexp);
  OpStack op_stack;
  op_stack.Push(handle_sexp);

  while (!op_stack.IsEmpty()) {
    auto op = op_stack.Pop();
    op(sexp_stack, op_stack);
  }

  assert(!sexp_stack.IsEmpty());
  auto res = sexp_stack.Pop();
  assert(sexp_stack.IsEmpty());
  assert(res->GetNodeType() == NodeType::Atom);

  return utils::bytes_cast<32>(Atom(res));
}

}  // namespace tree_hash

/**
 * =============================================================================
 * Program
 * =============================================================================
 */

Program Program::ImportFromBytes(Bytes const& bytes) {
  Program prog;
  prog.sexp_ = stream::SExpFromStream(stream::StreamReader(bytes));
  return prog;
}

Program Program::LoadFromFile(std::string_view file_path) {
  std::string prog_hex = utils::LoadHexFromFile(file_path);
  Bytes prog_bytes = utils::BytesFromHex(prog_hex);
  return ImportFromBytes(prog_bytes);
}

Bytes32 Program::GetTreeHash() { return tree_hash::SHA256TreeHash(sexp_); }

uint8_t MSBMask(uint8_t byte) {
  byte |= byte >> 1;
  byte |= byte >> 2;
  byte |= byte >> 4;
  return (byte + 1) >> 1;
}

namespace run {

class OpStack;
using Op = std::function<int(OpStack&, ValStack&)>;

class OpStack : public Stack<Op> {};

std::tuple<int, CLVMObjectPtr> RunProgram(CLVMObjectPtr program,
                                          CLVMObjectPtr args,
                                          OperatorLookup const& operator_lookup,
                                          Cost max_cost) {
  auto traverse_path = [](CLVMObjectPtr sexp,
                          CLVMObjectPtr env) -> std::tuple<int, CLVMObjectPtr> {
    Cost cost{PATH_LOOKUP_BASE_COST};
    cost += PATH_LOOKUP_COST_PER_LEG;
    if (IsNull(sexp)) {
      return std::make_tuple(cost, CLVMObjectPtr());
    }

    Bytes b = Atom(sexp);

    int end_byte_cursor{0};
    while (end_byte_cursor < b.size() && b[end_byte_cursor] == 0) {
      ++end_byte_cursor;
    }

    cost += end_byte_cursor * PATH_LOOKUP_COST_PER_ZERO_BYTE;
    if (end_byte_cursor == b.size()) {
      return std::make_tuple(cost, CLVMObjectPtr());
    }

    int end_bitmask = MSBMask(b[end_byte_cursor]);

    int byte_cursor = b.size() - 1;
    int bitmask = 0x01;
    while (byte_cursor > end_byte_cursor || bitmask < end_bitmask) {
      if (env->GetNodeType() != NodeType::Pair) {
        throw std::runtime_error("path into atom {env}");
      }
      auto [first, rest] = Pair(env);
      env = (b[byte_cursor] & bitmask) ? rest : first;
      cost += PATH_LOOKUP_COST_PER_LEG;
      bitmask <<= 1;
      if (bitmask == 0x100) {
        --byte_cursor;
        bitmask = 0x01;
      }
    }
    return std::make_tuple(cost, env);
  };

  Op swap_op, cons_op, eval_op, apply_op;

  swap_op = [&apply_op](OpStack& op_stack, ValStack& val_stack) -> int {
    auto v2 = val_stack.Pop();
    auto v1 = val_stack.Pop();
    val_stack.Push(v2);
    val_stack.Push(v1);
    return 0;
  };

  cons_op = [](OpStack& op_stack, ValStack& val_stack) -> int {
    auto v1 = val_stack.Pop();
    auto v2 = val_stack.Pop();
    val_stack.Push(ToSExp(v1, v2));
    return 0;
  };

  eval_op = [traverse_path, &operator_lookup, &apply_op, &cons_op, &eval_op,
             &swap_op](OpStack& op_stack, ValStack& val_stack) -> int {
    auto [sexp, args] = Pair(val_stack.Pop());
    if (sexp->GetNodeType() != NodeType::Pair) {
      auto [cost, r] = traverse_path(sexp, args);
      val_stack.Push(r);
      return cost;
    }

    auto [opt, sexp_rest] = Pair(sexp);
    if (opt->GetNodeType() == NodeType::Pair) {
      auto [new_opt, must_be_nil] = Pair(opt);
      if (new_opt->GetNodeType() == NodeType::Pair || !IsNull(must_be_nil)) {
        throw std::runtime_error("syntax X must be lone atom");
      }
      auto new_operand_list = sexp_rest;
      val_stack.Push(new_opt);
      val_stack.Push(new_operand_list);
      op_stack.Push(apply_op);
      return APPLY_COST;
    }

    Bytes op = Atom(opt);
    auto operand_list = sexp_rest;
    if (op == operator_lookup.QUOTE_ATOM) {
      val_stack.Push(operand_list);
      return QUOTE_COST;
    }

    op_stack.Push(apply_op);
    val_stack.Push(opt);
    while (!IsNull(operand_list)) {
      auto [_, r] = Pair(operand_list);
      val_stack.Push(ToSExp(_, args));
      op_stack.Push(cons_op);
      op_stack.Push(eval_op);
      op_stack.Push(swap_op);
      operand_list = r;
    }

    val_stack.Push(CLVMObjectPtr());
    return 1;
  };

  apply_op = [&operator_lookup, &eval_op](OpStack& op_stack,
                                          ValStack& val_stack) -> int {
    auto operand_list = val_stack.Pop();
    auto opt = val_stack.Pop();
    if (opt->GetNodeType() == NodeType::Pair) {
      throw std::runtime_error("internal error");
    }

    Bytes op = Atom(opt);
    if (op == operator_lookup.APPLY_ATOM) {
      if (ListLen(operand_list) != 2) {
        throw std::runtime_error("apply requires exactly 2 parameters");
      }
      auto [new_program, r] = Pair(operand_list);
      CLVMObjectPtr new_args;
      std::tie(new_args, std::ignore) = Pair(r);
      val_stack.Push(ToSExp(new_program, new_args));
      op_stack.Push(eval_op);
      return APPLY_COST;
    }

    auto [additional_cost, r] = operator_lookup(op, operand_list);
    val_stack.Push(r);
    return additional_cost;
  };

  OpStack op_stack;
  op_stack.Push(eval_op);

  ValStack val_stack;
  val_stack.Push(ToSExp(program, args));
  Cost cost{0};

  while (!op_stack.IsEmpty()) {
    auto f = op_stack.Pop();
    cost += f(op_stack, val_stack);
    if (max_cost && cost > max_cost) {
      throw std::runtime_error("cost exceeded");
    }
  }

  return std::make_tuple(cost, val_stack.GetLast());
}

}  // namespace run

std::tuple<int, CLVMObjectPtr> Program::Run(
    CLVMObjectPtr args, OperatorLookup const& operator_lookup, Cost max_cost) {
  return run::RunProgram(sexp_, args, operator_lookup, max_cost);
}

}  // namespace chia
