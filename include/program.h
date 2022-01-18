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

enum class NodeType : int { Atom, Pair };

class CLVMObject;
using CLVMObjectPtr = std::shared_ptr<CLVMObject>;

class CLVMObject {
 public:
  explicit CLVMObject(NodeType type);

  virtual ~CLVMObject() {}

  NodeType GetNodeType() const { return type_; }

 private:
  NodeType type_;
};

class CLVMObject_Atom : public CLVMObject {
 public:
  explicit CLVMObject_Atom(Bytes bytes);

  Bytes GetBytes() const;

 private:
  Bytes bytes_;
};

class CLVMObject_Pair : public CLVMObject {
 public:
  CLVMObject_Pair(CLVMObjectPtr first, CLVMObjectPtr second);

  CLVMObjectPtr GetFirstNode() const;

  CLVMObjectPtr GetSecondNode() const;

 private:
  CLVMObjectPtr first_;
  CLVMObjectPtr second_;
};

Bytes Atom(CLVMObjectPtr obj);

std::tuple<CLVMObjectPtr, CLVMObjectPtr> Pair(CLVMObjectPtr obj);

CLVMObjectPtr First(CLVMObjectPtr obj);

CLVMObjectPtr Rest(CLVMObjectPtr obj);

bool IsNull(CLVMObjectPtr obj);

int ListLen(CLVMObjectPtr list);

CLVMObjectPtr ToSExp(Bytes bytes);

CLVMObjectPtr ToSExp(CLVMObjectPtr first, CLVMObjectPtr second);

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

  bool IsEof() const { return args_->GetNodeType() != NodeType::Pair; }

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

}  // namespace chia

#endif
