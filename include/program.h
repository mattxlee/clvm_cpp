#ifndef CHIA_PROGRAM_H
#define CHIA_PROGRAM_H

#include <functional>
#include <memory>
#include <optional>
#include <stack>

#include "int.h"
#include "types.h"
#include "utils.h"

namespace chia {

class OperatorLookup;

using Cost = uint64_t;
static std::string_view DEFAULT_HIDDEN_PUZZLE = "ff0980";

enum class NodeType : int {
  None,
  Atom_Bytes,
  Atom_Str,
  Atom_Int,
  Atom_G1Element,
  List,
  Tuple
};

class CLVMObject;
using CLVMObjectPtr = std::shared_ptr<CLVMObject>;

class CLVMObject {
 public:
  explicit CLVMObject(NodeType type = NodeType::None);

  virtual ~CLVMObject() {}

  NodeType GetNodeType() const { return type_; }

 private:
  NodeType type_;
};

class CLVMObject_Atom : public CLVMObject {
 public:
  explicit CLVMObject_Atom(Bytes bytes);

  explicit CLVMObject_Atom(std::string_view str);

  explicit CLVMObject_Atom(long i);

  explicit CLVMObject_Atom(Int const& i);

  explicit CLVMObject_Atom(PublicKey const& g1_element);

  Bytes GetBytes() const;

  std::string AsString() const;

  long AsLong() const;

  Int AsInt() const;

  PublicKey AsG1Element() const;

 private:
  Bytes bytes_;
};

class CLVMObject_Pair : public CLVMObject {
 public:
  CLVMObject_Pair(CLVMObjectPtr first, CLVMObjectPtr second, NodeType type);

  CLVMObjectPtr GetFirstNode() const;

  CLVMObjectPtr GetSecondNode() const;

  void SetSecondNode(CLVMObjectPtr rest);

 private:
  CLVMObjectPtr first_;
  CLVMObjectPtr second_;
};

bool IsAtom(CLVMObjectPtr obj);

bool IsPair(CLVMObjectPtr obj);

Bytes Atom(CLVMObjectPtr obj);

std::tuple<CLVMObjectPtr, CLVMObjectPtr> Pair(CLVMObjectPtr obj);

CLVMObjectPtr First(CLVMObjectPtr obj);

CLVMObjectPtr Rest(CLVMObjectPtr obj);

CLVMObjectPtr MakeNull();

bool IsNull(CLVMObjectPtr obj);

int ListLen(CLVMObjectPtr list);

CLVMObjectPtr ToSExp(CLVMObjectPtr obj);

template <typename T>
CLVMObjectPtr ToSExp(T&& val) {
  return std::make_shared<CLVMObject_Atom>(std::forward<T>(val));
}

class ListBuilder {
 public:
  void Add(CLVMObjectPtr obj) {
    if (!next_) {
      // Prepare root_
      root_ = next_ =
          std::make_shared<CLVMObject_Pair>(obj, MakeNull(), NodeType::List);
      return;
    }
    auto next_pair = std::static_pointer_cast<CLVMObject_Pair>(next_);
    next_pair->SetSecondNode(
        std::make_shared<CLVMObject_Pair>(obj, MakeNull(), NodeType::List));
  }

  CLVMObjectPtr GetRoot() const { return root_; }

 private:
  CLVMObjectPtr root_;
  CLVMObjectPtr next_;
};

template <typename... T>
CLVMObjectPtr ToSExpList(T&&... vals) {
  ListBuilder build;
  (build.Add(ToSExp(std::forward<T>(vals))), ...);
  return build.GetRoot();
}

template <typename T1, typename T2>
CLVMObjectPtr ToSExpPair(T1&& val1, T2&& val2) {
  return std::make_shared<CLVMObject_Pair>(ToSExp(val1), ToSExp(val2),
                                           NodeType::Tuple);
}

CLVMObjectPtr ToTrue();

CLVMObjectPtr ToFalse();

bool ListP(CLVMObjectPtr obj);

int ArgsLen(CLVMObjectPtr obj);

std::tuple<bool, Bytes, CLVMObjectPtr> ArgsNext(CLVMObjectPtr obj);

std::tuple<Cost, CLVMObjectPtr> MallocCost(Cost cost, CLVMObjectPtr atom);

class ArgsIter {
 public:
  explicit ArgsIter(CLVMObjectPtr args) : args_(args) {}

  Int NextInt(int* num_bytes) {
    Bytes b = Next();
    if (num_bytes) {
      *num_bytes = b.size();
    }
    return Int(b);
  }

  Bytes Next() {
    auto [a, n] = Pair(args_);
    args_ = n;
    return Atom(a);
  }

  bool IsEof() const { return args_->GetNodeType() != NodeType::None; }

 private:
  CLVMObjectPtr args_;
};

std::vector<std::tuple<Int, int>> ListInts(CLVMObjectPtr args);

std::vector<Bytes> ListBytes(CLVMObjectPtr args);

using StreamReadFunc = std::function<Bytes(int size)>;

template <typename T>
class Stack {
 public:
  void Push(T op) { stack_.push(std::move(op)); }

  T Pop() {
    if (stack_.empty()) {
      throw std::runtime_error("stack is empty");
    }
    T res = stack_.top();
    stack_.pop();
    return res;
  }

  T GetLast() const {
    if (stack_.empty()) {
      throw std::runtime_error("no last item");
    }
    return stack_.top();
  }

  bool IsEmpty() const { return stack_.empty(); }

  bool Exists(T const& op) {
    for (auto const& op_in_stack : stack_) {
      if (op == op_in_stack) {
        return true;
      }
    }
    return false;
  }

 private:
  std::stack<T> stack_;
};

using ValStack = Stack<CLVMObjectPtr>;

using ReadStreamFunc = std::function<Bytes(int size)>;

CLVMObjectPtr SExpFromStream(ReadStreamFunc f);

class Program {
 public:
  static Program ImportFromBytes(Bytes const& bytes);

  static Program LoadFromFile(std::string_view file_path);

  Bytes32 GetTreeHash();

  std::tuple<int, CLVMObjectPtr> Run(CLVMObjectPtr args,
                                     OperatorLookup const& operator_lookup,
                                     Cost max_cost);

 private:
  Program() {}

 private:
  CLVMObjectPtr sexp_;
};

uint8_t MSBMask(uint8_t byte);

}  // namespace chia

#endif
