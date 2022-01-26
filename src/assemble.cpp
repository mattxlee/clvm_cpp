#include "assemble.h"

#include <optional>
#include <string>
#include <tuple>

#include "operator_lookup.h"
#include "program.h"
#include "utils.h"

#define CONS chia::types::Type::GetInstance().ToType("CONS")
#define NIL chia::types::Type::GetInstance().ToType("NULL")
#define INT chia::types::Type::GetInstance().ToType("INT")
#define HEX chia::types::Type::GetInstance().ToType("HEX")
#define QUOTES chia::types::Type::GetInstance().ToType("QUOTES")
#define DOUBLE_QUOTE chia::types::Type::GetInstance().ToType("DOUBLE_QUOTE")
#define SINGLE_QUOTE chia::types::Type::GetInstance().ToType("SINGLE_QUOTE")
#define SYMBOL chia::types::Type::GetInstance().ToType("SYMBOL")
#define OPERATOR chia::types::Type::GetInstance().ToType("OPERATOR")
#define CODE chia::types::Type::GetInstance().ToType("CODE")
#define NODE chia::types::Type::GetInstance().ToType("NODE")

namespace chia
{

namespace stream
{

bool CharIn(char ch, std::string_view s)
{
  for (char c : s) {
    if (c == ch) {
      return true;
    }
  }
  return false;
}

std::string CharToStr(char ch)
{
  std::string res;
  res.resize(1);
  res[0] = ch;
  return res;
}

class TokenStream
{
public:
  explicit TokenStream(std::string_view s)
      : str_(s)
  {
  }

  std::tuple<std::string, int> Next()
  {
    offset_ = ConsumeWhiteSpace(str_, offset_);
    if (offset_ >= str_.size()) {
      return std::make_tuple("", str_.size());
    }
    char c = str_[offset_];
    if (CharIn(c, "(.)")) {
      int off { offset_ };
      ++offset_;
      return std::make_tuple(CharToStr(c), off);
    }
    if (CharIn(c, "\"'")) {
      int start { offset_ };
      char initial_c = str_[start];
      ++offset_;
      while (offset_ < str_.size() && str_[offset_] != initial_c) {
        ++offset_;
      }
      if (offset_ < str_.size()) {
        int off { offset_ };
        ++offset_;
        return std::make_tuple(
            std::string(str_.substr(start, offset_ - start)), start);
      } else {
        throw std::runtime_error("unterminated string starting");
      }
    }
    auto [token, end_offset] = ConsumeUntilWhiteSpace(str_, offset_);
    int off { offset_ };
    offset_ = end_offset;
    return std::make_tuple(token, off);
  }

private:
  static int ConsumeWhiteSpace(std::string_view s, int offset)
  {
    while (1) {
      while (offset < s.size() && std::isspace(s[offset])) {
        ++offset;
      }
      if (offset >= s.size() || s[offset] != ';') {
        break;
      }
      while (offset < s.size() && !CharIn(s[offset], "\n\r")) {
        ++offset;
      }
    }
    return offset;
  }

  static std::tuple<std::string, int> ConsumeUntilWhiteSpace(
      std::string_view s, int offset)
  {
    int start { offset };
    while (offset < s.size() && !std::isspace(s[offset]) && s[offset] != ')') {
      ++offset;
    }
    return std::make_tuple(
        std::string(s.substr(start, offset - start)), offset);
  }

private:
  int offset_ { 0 };
  std::string_view str_;
};

} // namespace stream

namespace types
{

class Type
{
public:
  static Type& GetInstance()
  {
    static Type instance("CONS", "NULL", "INT", "HEX", "QUOTES", "DOUBLE_QUOTE",
        "SINGLE_QUOTE", "SYMBOL", "OPERATOR", "CODE", "NODE");
    return instance;
  }

  static Int ToType(std::string_view type_name)
  {
    return Int(utils::StrToBytes(type_name));
  }

  void Add(std::string_view type_name) { types_.push_back(ToType(type_name)); }

  template <typename... T> Type(T&&... vals)
  {
    (Add(std::forward<T>(vals)), ...);
  }

  bool Available(Int const& type) const
  {
    auto i = std::find(std::begin(types_), std::end(types_), type);
    return i != std::end(types_);
  }

  Int GetType(std::string_view type_name) const { return ToType(type_name); }

private:
  std::vector<Int> types_;
};

} // namespace types

CLVMObjectPtr ir_as_atom(CLVMObjectPtr ir_sexp);

template <typename Type, typename Val>
CLVMObjectPtr ir_new(Type&& type, Val&& val, std::optional<int> offset = {})
{
  CLVMObjectPtr first;
  if (offset) {
    first = ToSExpPair(std::forward<Type>(type), *offset);
  } else {
    first = ToSExp(std::forward<Type>(type));
  }
  return ToSExpPair(first, std::forward<Val>(val));
}

CLVMObjectPtr ir_cons(
    CLVMObjectPtr first, CLVMObjectPtr rest, std::optional<int> offset)
{
  if (!first) {
    throw std::runtime_error("cons null on first place");
  }
  if (!rest) {
    throw std::runtime_error("cons null on rest place");
  }
  return ir_new(CONS, ir_new(first, rest), offset);
}

CLVMObjectPtr ir_null() { return ir_new(NIL, MakeNull()); }

CLVMObjectPtr ir_list() { return ir_null(); }

template <typename T, typename... N>
CLVMObjectPtr ir_list(T&& first, N&&... items)
{
  return ir_cons(std::forward<T>(first), ir_cons(std::forward<N>(items)...));
}

Int ir_type(CLVMObjectPtr ir_sexp)
{
  auto the_type = First(ir_sexp);
  if (ListP(the_type)) {
    the_type = First(the_type);
  }
  return Int(Atom(the_type));
}

Int ir_as_int(CLVMObjectPtr ir_sexp)
{
  auto atom_p = std::static_pointer_cast<CLVMObject_Atom>(ir_as_atom(ir_sexp));
  return atom_p->AsInt();
}

Int ir_offset(CLVMObjectPtr ir_sexp)
{
  auto the_offset = First(ir_sexp);
  if (ListP(the_offset)) {
    return Int(Atom(Rest(the_offset)));
  } else {
    return Int(utils::ByteToBytes('\xff'));
  }
}

CLVMObjectPtr ir_val(CLVMObjectPtr ir_sexp) { return Rest(ir_sexp); }

bool ir_nullp(CLVMObjectPtr ir_sexp) { return ir_type(ir_sexp) == NIL; }

bool ir_listp(CLVMObjectPtr ir_sexp) { return ir_type(ir_sexp) == CONS; }

CLVMObjectPtr ir_first(CLVMObjectPtr ir_sexp) { return First(Rest(ir_sexp)); }

CLVMObjectPtr ir_rest(CLVMObjectPtr ir_sexp) { return Rest(Rest(ir_sexp)); }

CLVMObjectPtr ir_as_sexp(CLVMObjectPtr ir_sexp)
{
  if (ir_nullp(ir_sexp)) {
    return ToSExpList();
  }
  if (ir_type(ir_sexp) == CONS) {
    return ToSExpPair(
        ir_as_sexp(ir_first(ir_sexp)), ir_as_sexp(ir_rest(ir_sexp)));
  }
  return Rest(ir_sexp);
}

bool ir_is_atom(CLVMObjectPtr ir_sexp) { return !ir_listp(ir_sexp); }

CLVMObjectPtr ir_as_atom(CLVMObjectPtr ir_sexp)
{
  if (!ir_is_atom(ir_sexp)) {
    throw std::runtime_error("ir is not an atom");
  }
  return Rest(ir_sexp);
}

CLVMObjectPtr ir_symbol(std::string_view symbol)
{
  return ToSExpPair(SYMBOL, symbol);
}

std::optional<std::string> ir_as_symbol(CLVMObjectPtr ir_sexp)
{
  if (ListP(ir_sexp) && ir_type(ir_sexp) == SYMBOL) {
    auto atom = std::static_pointer_cast<CLVMObject_Atom>(ir_as_sexp(ir_sexp));
    return atom->AsString();
  }
  return {};
}

bool is_ir(CLVMObjectPtr sexp)
{
  if (IsAtom(sexp)) {
    return false;
  }

  auto [type_sexp, val_sexp] = Pair(sexp);
  auto the_type = Int(Atom(type_sexp));
  if (!types::Type::GetInstance().Available(the_type)) {
    return false;
  }

  if (the_type == CONS) {
    if (IsNull(val_sexp)) {
      return true;
    }
    if (IsPair(val_sexp)) {
      return is_ir(First(val_sexp)) && is_ir(Rest(val_sexp));
    }
    return false;
  }

  return IsAtom(val_sexp);
}

std::tuple<std::string, int> next_cons_token(stream::TokenStream& stream)
{
  auto [token, offset] = stream.Next();
  if (token.empty()) {
    throw std::runtime_error("missing )");
  }
  return std::make_tuple(token, offset);
}

CLVMObjectPtr tokenize_int(std::string_view token, int offset)
{
  if (Int::IsValidNumberStr(token)) {
    return ir_new(INT, Int(token, 0), offset);
  }
  return {};
}

CLVMObjectPtr tokenize_hex(std::string_view token, int offset)
{
  if (utils::ToUpper(token.substr(0, 2)) == "0X") {
    std::string hex { token.substr(2) };
    if (hex.size() % 2 == 1) {
      hex.insert(std::begin(hex), '0');
    }
    try {
      return ir_new(HEX, utils::BytesFromHex(hex), offset);
    } catch (std::exception const&) {
      // The token cannot be parsed into bytes
    }
  }
  return {};
}

CLVMObjectPtr tokenize_quotes(std::string_view token, int offset)
{
  if (token.size() < 2) {
    return {};
  }
  char c = token[0];
  if (c != '\'' && c != '"') {
    return {};
  }
  auto q_type = c == '"' ? DOUBLE_QUOTE : SINGLE_QUOTE;
  return ir_new(q_type, token.substr(1, token.size() - 2), offset);
}

CLVMObjectPtr tokenize_symbol(std::string_view token, int offset)
{
  return ir_new(SYMBOL, token, offset);
}

CLVMObjectPtr tokenize_sexp(
    std::string_view token, int offset, stream::TokenStream& stream);

CLVMObjectPtr tokenize_cons(
    std::string_view token, int offset, stream::TokenStream& stream)
{
  if (token == ")") {
    return ir_new(NIL, MakeNull(), offset);
  }

  int initial_offset = offset;

  auto first_sexp = tokenize_sexp(token, offset, stream);
  CLVMObjectPtr rest_sexp;

  std::tie(token, offset) = next_cons_token(stream);
  if (token == ".") {
    int dot_offset = offset;
    // grab the last item
    std::tie(token, offset) = next_cons_token(stream);
    rest_sexp = tokenize_sexp(token, offset, stream);
    if (!rest_sexp) {
      throw std::runtime_error("receive a null from tokenize_sexp");
    }
    std::tie(token, offset) = next_cons_token(stream);
    if (token != ")") {
      throw std::runtime_error("illegal dot expression");
    }
  } else {
    rest_sexp = tokenize_cons(token, offset, stream);
    if (!rest_sexp) {
      throw std::runtime_error("tokenize_cons returns a null");
    }
  }
  return ir_cons(first_sexp, rest_sexp, initial_offset);
}

CLVMObjectPtr tokenize_sexp(
    std::string_view token, int offset, stream::TokenStream& stream)
{
  if (token == "(") {
    auto [token, offset] = next_cons_token(stream);
    return tokenize_cons(token, offset, stream);
  }

  auto funcs = { tokenize_int, tokenize_hex, tokenize_quotes, tokenize_symbol };
  for (auto& f : funcs) {
    auto r = f(token, offset);
    if (r) {
      return r;
    }
  }

  throw std::runtime_error("cannot be tokenized");
}

CLVMObjectPtr assemble_from_ir(CLVMObjectPtr ir_sexp)
{
  auto keyword_opt = ir_as_symbol(ir_sexp);
  if (keyword_opt) {
    std::string keyword = *keyword_opt;
    if (keyword[0] == '#') {
      keyword = keyword.substr(1);
    }
    OperatorLookup lookup;
    try {
      uint8_t atom = lookup.KeywordToAtom(keyword);
      return ToSExp(utils::ByteToBytes(atom));
    } catch (std::exception const& e) {
      return ir_val(ir_sexp);
    }
  }

  if (!ir_listp(ir_sexp)) {
    return ir_val(ir_sexp);
  }

  if (ir_nullp(ir_sexp)) {
    return ToSExpList();
  }

  auto first = ir_first(ir_sexp);
  keyword_opt = ir_as_symbol(first);
  if (keyword_opt) {
    if (auto keyword = *keyword_opt; keyword == "q") {
      // TODO note that any symbol is legal after this point
    }
  }

  auto sexp_1 = assemble_from_ir(first);
  auto sexp_2 = assemble_from_ir(ir_rest(ir_sexp));
  return ToSExpPair(sexp_1, sexp_2);
}

CLVMObjectPtr read_ir(std::string_view str)
{
  stream::TokenStream s(str);
  auto [token, offset] = s.Next();
  while (!token.empty()) {
    return tokenize_sexp(token, offset, s);
  }
  throw std::runtime_error("unexpected end of stream");
}

CLVMObjectPtr Assemble(std::string_view str)
{
  auto symbols = read_ir(str);
  return assemble_from_ir(symbols);
}

} // namespace chia
