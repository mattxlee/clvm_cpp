#include "assemble.h"

#include <string>
#include <tuple>

namespace chia {

namespace stream {

bool CharIn(char ch, std::string_view s) {
  for (char c : s) {
    if (c == ch) {
      return true;
    }
  }
  return false;
}

std::string CharToStr(char ch) {
  std::string res;
  res.resize(1);
  res[0] = ch;
  return res;
}

class TokenStreams {
 public:
  explicit TokenStreams(std::string_view s) : str_(s) {}

  std::tuple<std::string, int> Next() {
    offset_ = ConsumeWhiteSpace(str_, offset_);
    if (offset_ >= str_.size()) {
      return std::make_tuple("", str_.size());
    }
    char c = str_[offset_];
    if (CharIn(c, "(.)")) {
      int off{offset_};
      ++offset_;
      return std::make_tuple(CharToStr(c), off);
    }
    if (CharIn(c, "\"'")) {
      int start{offset_};
      char initial_c = str_[start];
      ++offset_;
      while (offset_ < str_.size() && str_[offset_] != initial_c) {
        ++offset_;
      }
      if (offset_ < str_.size()) {
        int off{offset_};
        ++offset_;
        return std::make_tuple(str_.substr(start, offset_ - start).data(),
                               start);
      } else {
        throw std::runtime_error("unterminated string starting");
      }
    }
    auto [token, end_offset] = ConsumeUntilWhiteSpace(str_, offset_);
    int off{offset_};
    offset_ = end_offset;
    return std::make_tuple(token, off);
  }

 private:
  static int ConsumeWhiteSpace(std::string_view s, int offset) {
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

  static std::tuple<std::string, int> ConsumeUntilWhiteSpace(std::string_view s,
                                                             int offset) {
    int start{offset};
    while (offset < s.size() && !std::isspace(s[offset]) && s[offset] != ')') {
      ++offset;
    }
    return std::make_tuple(s.substr(start, offset - start).data(), offset);
  }

 private:
  int offset_{0};
  std::string_view str_;
};

}  // namespace stream

CLVMObjectPtr AssembleFromIR(std::string_view ir_sexp) {}

}  // namespace chia
