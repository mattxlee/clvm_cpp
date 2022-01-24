#include "program.h"

#include <memory>
#include <stdexcept>

#include "assemble.h"
#include "costs.h"
#include "crypto_utils.h"
#include "key.h"
#include "operator_lookup.h"
#include "types.h"
#include "utils.h"
#include "wallet.h"

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
    : CLVMObject(NodeType::Atom_Bytes), bytes_(std::move(bytes)) {}

CLVMObject_Atom::CLVMObject_Atom(std::string_view str)
    : CLVMObject(NodeType::Atom_Str) {
  bytes_.resize(str.size());
  memcpy(bytes_.data(), str.data(), str.size());
}

CLVMObject_Atom::CLVMObject_Atom(long i) : CLVMObject_Atom(Int(i)) {}

CLVMObject_Atom::CLVMObject_Atom(Int const& i)
    : CLVMObject(NodeType::Atom_Int) {
  bytes_ = i.ToBytes();
}

CLVMObject_Atom::CLVMObject_Atom(PublicKey const& g1_element)
    : CLVMObject(NodeType::Atom_G1Element) {
  bytes_ = utils::bytes_cast<wallet::Key::PUB_KEY_LEN>(g1_element);
}

Bytes CLVMObject_Atom::GetBytes() const { return bytes_; }

std::string CLVMObject_Atom::AsString() const {
  return std::string(std::begin(bytes_), std::end(bytes_));
}

long CLVMObject_Atom::AsLong() const { return Int(bytes_).ToInt(); }

Int CLVMObject_Atom::AsInt() const { return Int(bytes_); }

PublicKey CLVMObject_Atom::AsG1Element() const {
  return utils::bytes_cast<wallet::Key::PUB_KEY_LEN>(bytes_);
}

CLVMObject_Pair::CLVMObject_Pair(CLVMObjectPtr first, CLVMObjectPtr second,
                                 NodeType type)
    : CLVMObject(type), first_(first), second_(second) {}

CLVMObjectPtr CLVMObject_Pair::GetFirstNode() const { return first_; }

CLVMObjectPtr CLVMObject_Pair::GetSecondNode() const { return second_; }

void CLVMObject_Pair::SetSecondNode(CLVMObjectPtr rest) { second_ = rest; }

bool IsAtom(CLVMObjectPtr obj) {
  return obj->GetNodeType() == NodeType::Atom_Bytes ||
         obj->GetNodeType() == NodeType::Atom_G1Element ||
         obj->GetNodeType() == NodeType::Atom_Int ||
         obj->GetNodeType() == NodeType::Atom_Str;
}

bool IsPair(CLVMObjectPtr obj) {
  return obj->GetNodeType() == NodeType::List ||
         obj->GetNodeType() == NodeType::Tuple;
}

Bytes Atom(CLVMObjectPtr obj) {
  if (!IsAtom(obj)) {
    throw std::runtime_error("it's not an ATOM");
  }
  auto atom = static_cast<CLVMObject_Atom*>(obj.get());
  return atom->GetBytes();
}

std::tuple<CLVMObjectPtr, CLVMObjectPtr> Pair(CLVMObjectPtr obj) {
  if (!IsPair(obj)) {
    throw std::runtime_error("it's not a PAIR");
  }
  auto pair = static_cast<CLVMObject_Pair*>(obj.get());
  return std::make_tuple(pair->GetFirstNode(), pair->GetSecondNode());
}

CLVMObjectPtr First(CLVMObjectPtr obj) {
  if (!IsPair(obj)) {
    throw std::runtime_error("it's not a PAIR");
  }
  auto pair = static_cast<CLVMObject_Pair*>(obj.get());
  return pair->GetFirstNode();
}

CLVMObjectPtr Rest(CLVMObjectPtr obj) {
  if (!IsPair(obj)) {
    throw std::runtime_error("it's not a PAIR");
  }
  auto pair = static_cast<CLVMObject_Pair*>(obj.get());
  return pair->GetSecondNode();
}

CLVMObjectPtr MakeNull() { return std::make_shared<CLVMObject>(); }

bool IsNull(CLVMObjectPtr obj) { return obj->GetNodeType() == NodeType::None; }

int ListLen(CLVMObjectPtr list) {
  int count{0};
  while (IsPair(list)) {
    ++count;
    std::tie(std::ignore, list) = Pair(list);
  }
  return count;
}

CLVMObjectPtr ToSExp(CLVMObjectPtr obj) { return obj; }

/**
 * =============================================================================
 * Op: SExp
 * =============================================================================
 */

CLVMObjectPtr ToTrue() { return ToSExp(utils::ByteToBytes('\1')); }

CLVMObjectPtr ToFalse() { return ToSExp(Bytes()); }

bool ListP(CLVMObjectPtr obj) { return obj->GetNodeType() == NodeType::List; }

int ArgsLen(CLVMObjectPtr obj) {
  int len{0};
  while (obj->GetNodeType() == NodeType::List) {
    auto [a, r] = Pair(obj);
    if (!IsAtom(a)) {
      throw std::runtime_error("requires in args");
    }
    // Next
    len += Atom(a).size();
    obj = r;
  }
  return len;
}

std::tuple<bool, Bytes, CLVMObjectPtr> ArgsNext(CLVMObjectPtr obj) {
  if (obj->GetNodeType() != NodeType::List) {
    return std::make_tuple(false, Bytes(), CLVMObjectPtr());
  }
  auto [b, next] = Pair(obj);
  Bytes bytes = Atom(b);
  return std::make_tuple(true, bytes, next);
}

std::tuple<Cost, CLVMObjectPtr> MallocCost(Cost cost, CLVMObjectPtr atom) {
  return std::make_tuple(cost + Atom(atom).size() * MALLOC_COST_PER_BYTE, atom);
}

std::vector<std::tuple<Int, int>> ListInts(CLVMObjectPtr args) {
  ArgsIter iter(args);
  std::vector<std::tuple<Int, int>> res;
  while (!iter.IsEof()) {
    int l;
    Int r = iter.NextInt(&l);
    res.push_back(std::make_tuple(r, l));
  }
  return res;
}

std::vector<Bytes> ListBytes(CLVMObjectPtr args) {
  std::vector<Bytes> res;
  ArgsIter iter(args);
  while (!iter.IsEof()) {
    res.push_back(iter.Next());
  }
  return res;
}

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
  uint64_t size = Int(size_blob).ToUInt();  // TODO The size might overflow
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
  val_stack.Push(ToSExpPair(left, right));
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
    if (IsPair(sexp)) {
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
  assert(IsAtom(res));

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

Program Program::ImportFromHex(std::string_view hex) {
  Bytes prog_bytes = utils::BytesFromHex(hex);
  return ImportFromBytes(prog_bytes);
}

Program Program::ImportFromCompiledFile(std::string_view file_path) {
  std::string hex = utils::LoadHexFromFile(file_path);
  return ImportFromHex(hex);
}

Program Program::ImportFromAssemble(std::string_view str) {
  Program prog;
  prog.sexp_ = Assemble(str);
  return prog;
}

Program::Program(CLVMObjectPtr sexp) : sexp_(sexp) {}

Bytes32 Program::GetTreeHash() const {
  return tree_hash::SHA256TreeHash(sexp_);
}

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

std::tuple<int, CLVMObjectPtr> RunProgram(
    CLVMObjectPtr program, CLVMObjectPtr args,
    OperatorLookup const& operator_lookup = OperatorLookup(),
    Cost max_cost = 0) {
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
      if (!IsPair(env)) {
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
    val_stack.Push(ToSExpPair(v1, v2));
    return 0;
  };

  eval_op = [traverse_path, &operator_lookup, &apply_op, &cons_op, &eval_op,
             &swap_op](OpStack& op_stack, ValStack& val_stack) -> int {
    auto [sexp, args] = Pair(val_stack.Pop());
    if (!IsPair(sexp)) {
      auto [cost, r] = traverse_path(sexp, args);
      val_stack.Push(r);
      return cost;
    }

    auto [opt, sexp_rest] = Pair(sexp);
    if (IsPair(opt)) {
      auto [new_opt, must_be_nil] = Pair(opt);
      if (IsPair(new_opt) || !IsNull(must_be_nil)) {
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
      val_stack.Push(ToSExpPair(_, args));
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
    if (IsPair(opt)) {
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
      val_stack.Push(ToSExpPair(new_program, new_args));
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
  val_stack.Push(ToSExpPair(program, args));
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

std::tuple<int, CLVMObjectPtr> Program::Run(CLVMObjectPtr args) {
  return run::RunProgram(sexp_, args);
}

std::string_view CURRY_OBJ_CODE =
    "(a (q #a 4 (c 2 (c 5 (c 7 0)))) (c (q (c (q . 2) (c (c (q . 1) 5) (c (a 6 "
    "(c 2 (c 11 (q 1)))) 0))) #a (i 5 (q 4 (q . 4) (c (c (q . 1) 9) (c (a 6 (c "
    "2 (c 13 (c 11 0)))) 0))) (q . 11)) 1) 1))";

Program Program::Curry(CLVMObjectPtr args) {
  auto curry_program = Assemble(CURRY_OBJ_CODE);
  auto bind_args = ToSExpPair(sexp_, args);
  auto [cost, sexp] = run::RunProgram(curry_program, bind_args);
  return Program(sexp);
}

}  // namespace chia
