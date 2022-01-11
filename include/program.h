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

using StreamReadFunc = std::function<Bytes(int size)>;

template <typename T>
class Stack {
 public:
  void Push(T op) { stack_.push(std::move(op)); }

  T Pop() {
    T res = stack_.top();
    stack_.pop();
    return res;
  }

  bool IsEmpty() const { return stack_.empty(); }

 private:
  std::stack<T> stack_;
};

using ValStack = Stack<CLVMObjectPtr>;

class OpStack;

using Op = std::function<void(OpStack&, ValStack&, StreamReadFunc)>;

class OpStack : public Stack<Op> {};

using ReadStreamFunc = std::function<Bytes(int size)>;

CLVMObjectPtr SExpFromStream(ReadStreamFunc&& f);

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
