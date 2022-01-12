#include "program.h"

#include <memory>

#include "crypto_utils.h"
#include "utils.h"

namespace chia {

uint8_t const MAX_SINGLE_BYTE = 0x7F;
uint8_t const CONS_BOX_MARKER = 0xFF;

/**
 * =============================================================================
 * CLVMObject
 * =============================================================================
 */

CLVMObject::CLVMObject(NodeType type) {}

CLVMObject_Atom::CLVMObject_Atom(Bytes bytes)
    : CLVMObject(NodeType::Atom), bytes_(std::move(bytes)) {}

CLVMObject_Pair::CLVMObject_Pair(CLVMObjectPtr first, CLVMObjectPtr second)
    : CLVMObject(NodeType::Pair), first_(first), second_(second) {}

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

template <typename T>
T IntFromBytesBE(Bytes const& bytes) {
  Bytes be;
  std::copy(std::rbegin(bytes), std::rend(bytes), std::back_inserter(be));
  int padding_bytes{0};
  if (bytes.size() < sizeof(T)) {
    padding_bytes = sizeof(T) - bytes.size();
  }
  for (int i = 0; i < padding_bytes; ++i) {
    be.push_back(0);
  }
  T res;
  memcpy(&res, be.data(), sizeof(T));
  return res;
}

CLVMObjectPtr AtomFromStream(StreamReadFunc f, uint8_t b) {
  if (b == 0x80) {
    return ToSExp(Bytes());
  }
  if (b <= MAX_SINGLE_BYTE) {
    Bytes bytes(1);
    bytes[0] = b;
    return ToSExp(std::move(bytes));
  }
  int bit_count{0};
  int bit_mask{0x80};
  while (b & bit_mask) {
    bit_count += 1;
    b &= 0xff ^ bit_mask;
    bit_mask >>= 1;
  }
  Bytes size_blob{b};
  if (bit_count > 1) {
    Bytes b = f(bit_count - 1);
    if (b.size() != bit_count - 1) {
      throw std::runtime_error("bad encoding");
    }
    size_blob = utils::ConnectContainers(size_blob, b);
  }
  auto size = IntFromBytesBE<uint64_t>(size_blob);
  if (size >= 0x400000000) {
    throw std::runtime_error("blob too large");
  }
  Bytes blob = f(size);
  if (blob.size() != size) {
    throw std::runtime_error("bad encoding");
  }
  return ToSExp(blob);
}

void OpCons(OpStack& op_stack, ValStack& val_stack, StreamReadFunc f) {
  auto right = val_stack.Pop();
  auto left = val_stack.Pop();
  val_stack.Push(ToSExp(left, right));
}

void OpReadSExp(OpStack& op_stack, ValStack& val_stack, StreamReadFunc f) {
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

namespace tree_hash {

class OpStack;
using Op = std::function<void(Stack<CLVMObjectPtr>&, OpStack&)>;

class OpStack : public Stack<Op> {};

Bytes32 SHA256TreeHash(
    CLVMObjectPtr sexp,
    std::vector<Bytes32> const& precalculated = std::vector<Bytes32>()) {
  Op handle_pair = [](ValStack& sexp_stack, OpStack& op_stack) {
    auto p0 = sexp_stack.Pop();
    auto p1 = sexp_stack.Pop();
    Bytes prefix(1);
    sexp_stack.Push(ToSExp(utils::bytes_cast<32>(
        crypto_utils::MakeSHA256(utils::ConnectBuffers(prefix, p0, p1)))));
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
      auto sexp_pair = std::dynamic_pointer_cast<CLVMObject_Pair>(sexp);
      auto p0 = sexp_pair->GetFirstNode();
      auto p1 = sexp_pair->GetSecondNode();
      sexp_stack.Push(p0);
      sexp_stack.Push(p1);
      op_stack.Push(handle_pair);
      op_stack.Push(handle_sexp);
      op_stack.Push(roll);
      op_stack.Push(handle_sexp);
    } else {
      auto sexp_atom = std::dynamic_pointer_cast<CLVMObject_Atom>(sexp);
      auto i = std::find(std::begin(precalculated), std::end(precalculated),
                         sexp_atom->GetBytes());
      Bytes r;
      if (i != std::end(precalculated)) {
        r = sexp_atom->GetBytes();
      } else {
        Bytes prefix(1);
        prefix[0] = '\1';
        r = utils::bytes_cast<32>(crypto_utils::MakeSHA256(
            utils::ConnectBuffers(prefix, sexp_atom->GetBytes())));
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

  auto sexp_atom = std::dynamic_pointer_cast<CLVMObject_Atom>(sexp);
  return utils::bytes_cast<32>(sexp_atom->GetBytes());
}

}  // namespace tree_hash

/**
 * =============================================================================
 * Program
 * =============================================================================
 */

Program Program::ImportFromBytes(Bytes const& bytes) { return Program(); }

Program Program::LoadFromFile(std::string_view file_path) { return Program(); }

Bytes32 Program::GetTreeHash() { return tree_hash::SHA256TreeHash(sexp_); }

}  // namespace chia
