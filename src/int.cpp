#include "int.h"

#include <gmpxx.h>

#include <sstream>

#include "utils.h"

namespace chia {

struct Impl {
  mpz_class mpz;
};

Int::Int(Bytes const& s) {
  std::stringstream ss;
  ss << "0x" << utils::BytesToHex(s);
  impl_.reset(new Impl{mpz_class(ss.str())});
}

Int::Int(Impl* impl) : impl_(impl) {}

Int::Int(long val) {
  mpz_class mpz(val);
  impl_.reset(new Impl{mpz});
}

Int::Int(unsigned long val) {
  mpz_class mpz(val);
  impl_.reset(new Impl{mpz});
}

Bytes Int::ToBytes() const {
  std::string hex = impl_->mpz.get_str(16);
  return utils::BytesFromHex(hex);
}

Int& Int::operator=(Int const& rhs) {
  if (this != &rhs) {
    impl_.reset(new Impl{rhs.impl_->mpz});
  }
  return *this;
}

Int Int::operator-(Int const& rhs) {
  mpz_class mpz = impl_->mpz - rhs.impl_->mpz;
  return Int(new Impl{mpz});
}

Int Int::operator+(Int const& rhs) {
  mpz_class mpz = impl_->mpz + rhs.impl_->mpz;
  return Int(new Impl{mpz});
}

Int Int::operator*(Int const& rhs) {
  mpz_class mpz = impl_->mpz * rhs.impl_->mpz;
  return Int(new Impl{mpz});
}

Int Int::operator/(Int const& rhs) {
  mpz_class mpz = impl_->mpz / rhs.impl_->mpz;
  return Int(new Impl{mpz});
}

bool operator==(Int const& lhs, Int const& rhs) {
  return lhs.impl_->mpz == rhs.impl_->mpz;
}

bool operator<(Int const& lhs, Int const& rhs) {
  return lhs.impl_->mpz < rhs.impl_->mpz;
}

bool operator<=(Int const& lhs, Int const& rhs) {
  return lhs.impl_->mpz <= rhs.impl_->mpz;
}

bool operator>(Int const& lhs, Int const& rhs) {
  return lhs.impl_->mpz > rhs.impl_->mpz;
}

bool operator>=(Int const& lhs, Int const& rhs) {
  return lhs.impl_->mpz >= rhs.impl_->mpz;
}

}  // namespace chia
