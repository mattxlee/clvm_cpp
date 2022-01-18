#ifndef CHIA_INT_H
#define CHIA_INT_H

#include <memory>
#include <string_view>

#include "types.h"

namespace chia {

struct Impl;

class Int {
 public:
  explicit Int(Bytes const& s);

  explicit Int(Impl* impl);

  explicit Int(long val);
  explicit Int(unsigned long val);

  Bytes ToBytes() const;

  Int& operator=(Int const& rhs);

  Int operator-(Int const& rhs);
  Int operator+(Int const& rhs);
  Int operator*(Int const& rhs);
  Int operator/(Int const& rhs);

  friend bool operator==(Int const& lhs, Int const& rhs);
  friend bool operator<(Int const& lhs, Int const& rhs);
  friend bool operator<=(Int const& lhs, Int const& rhs);
  friend bool operator>(Int const& lhs, Int const& rhs);
  friend bool operator>=(Int const& lhs, Int const& rhs);

 private:
  std::unique_ptr<Impl> impl_;
};

bool operator==(Int const& lhs, Int const& rhs);
bool operator<(Int const& lhs, Int const& rhs);
bool operator<=(Int const& lhs, Int const& rhs);
bool operator>(Int const& lhs, Int const& rhs);
bool operator>=(Int const& lhs, Int const& rhs);

}  // namespace chia

#endif
