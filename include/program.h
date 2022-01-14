#ifndef CHIA_PROGRAM_H
#define CHIA_PROGRAM_H

#include <functional>
#include <memory>
#include <stack>

#include "types.h"

namespace chia {

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

class OpStack;

using Op = std::function<void(OpStack&, ValStack&, StreamReadFunc)>;

class OpStack : public Stack<Op> {};

using ReadStreamFunc = std::function<Bytes(int size)>;

CLVMObjectPtr SExpFromStream(ReadStreamFunc f);

class Result {
 public:
};

class Program {
 public:
  static Program ImportFromBytes(Bytes const& bytes);

  static Program LoadFromFile(std::string_view file_path);

  Bytes32 GetTreeHash();

  template <typename... P>
  Result Run(P&&... p) {}

 private:
  Program() {}

 private:
  CLVMObjectPtr sexp_;
};

}  // namespace chia

#endif
