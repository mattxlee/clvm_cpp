#include "int.h"

#include <gmpxx.h>

#include <sstream>

#include "utils.h"

namespace chia
{

bool is_valid_int_char(char ch) { return ch >= '0' && ch <= '9'; }

bool is_valid_hex_char(char ch)
{
  return ch >= 'a' && ch <= 'f' || ch >= 'A' && ch <= 'F';
}

bool check_valid_hex_string(std::string_view s)
{
  if (s.empty()) {
    return false;
  }
  for (char ch : s) {
    if (!is_valid_int_char(ch) && !is_valid_hex_char(ch)) {
      return false;
    }
  }
  return true;
}

bool check_valid_int_string(std::string_view s) {
  if (s.empty()) {
    return false;
  }
  for (char ch: s) {
    if (!is_valid_int_char(ch)) {
      return false;
    }
  }
  return true;
}

bool check_valid_int(std::string_view s)
{
  if (s.empty()) {
    return false;
  }
  if (s.size() >= 1) {
    if (s[0] == '+' || s[0] == '-') {
      return check_valid_int(s.substr(1));
    }
  }
  if (s.size() >= 2) {
    // check hex prefix
    std::string prefix { s.substr(0, 2) };
    if (prefix == "0x" || prefix == "0X") {
      return check_valid_hex_string(s.substr(2));
    }
  }
  return check_valid_int_string(s);
}

struct Impl {
  mpz_class mpz;
};

Int Int::Create(Impl* impl)
{
  Int res { 0 };
  res.impl_ = impl;
  return res;
}

bool Int::IsValidNumberStr(std::string_view s) { return check_valid_int(s); }

Int::Int(Int const& rhs)
    : impl_(new Impl { rhs.impl_->mpz })
{
}

Int::~Int() { delete impl_; }

Int::Int(std::string_view s, int base)
{
  impl_ = new Impl { mpz_class(std::string(s), base) };
}

Int::Int(Bytes const& s)
{
  std::stringstream ss;
  ss << "0x" << utils::BytesToHex(s);
  impl_ = new Impl { mpz_class(ss.str()) };
}

Int::Int(long val)
{
  mpz_class mpz(val);
  impl_ = new Impl { mpz };
}

Bytes Int::ToBytes() const
{
  std::string hex = impl_->mpz.get_str(16);
  return utils::BytesFromHex(hex);
}

int Int::NumBytes() const { return ToBytes().size(); }

long Int::ToInt() const { return impl_->mpz.get_si(); }

unsigned long Int::ToUInt() const { return impl_->mpz.get_ui(); }

Int Int::Abs() const
{
  mpz_class mpz = abs(impl_->mpz);
  return Create(new Impl { mpz });
}

Int& Int::operator=(Int const& rhs)
{
  if (this != &rhs) {
    impl_ = new Impl { rhs.impl_->mpz };
  }
  return *this;
}

Int Int::operator-(Int const& rhs) const
{
  mpz_class mpz = impl_->mpz - rhs.impl_->mpz;
  return Create(new Impl { mpz });
}

Int Int::operator+(Int const& rhs) const
{
  mpz_class mpz = impl_->mpz + rhs.impl_->mpz;
  return Create(new Impl { mpz });
}

Int Int::operator*(Int const& rhs) const
{
  mpz_class mpz = impl_->mpz * rhs.impl_->mpz;
  return Create(new Impl { mpz });
}

Int Int::operator/(Int const& rhs) const
{
  mpz_class mpz = impl_->mpz / rhs.impl_->mpz;
  return Create(new Impl { mpz });
}

Int Int::operator%(Int const& rhs) const
{
  mpz_class mpz = impl_->mpz % rhs.impl_->mpz;
  return Create(new Impl { mpz });
}

Int Int::operator^(Int const& rhs) const
{
  mpz_class mpz = impl_->mpz ^ rhs.impl_->mpz;
  return Create(new Impl { mpz });
}

Int& Int::operator+=(Int const& rhs)
{
  *this = *this + rhs;
  return *this;
}

Int& Int::operator-=(Int const& rhs)
{
  *this = *this - rhs;
  return *this;
}

Int& Int::operator*=(Int const& rhs)
{
  *this = *this * rhs;
  return *this;
}

Int& Int::operator/=(Int const& rhs)
{
  *this = *this / rhs;
  return *this;
}

Int& Int::operator%=(Int const& rhs)
{
  *this = *this % rhs;
  return *this;
}

Int& Int::operator^=(Int const& rhs)
{
  *this = *this ^ rhs;
  return *this;
}

Int Int::operator++(int)
{
  Int res { *this };
  *this = *this + Int(1);
  return res;
}

Int& Int::operator++()
{
  *this = *this + Int(1);
  return *this;
}

Int Int::operator--(int)
{
  Int res { *this };
  *this = *this - Int(1);
  return res;
}

Int& Int::operator--()
{
  *this = *this - Int(1);
  return *this;
}

bool operator==(Int const& lhs, Int const& rhs)
{
  return lhs.impl_->mpz == rhs.impl_->mpz;
}

bool operator!=(Int const& lhs, Int const& rhs) { return !(lhs == rhs); }

bool operator<(Int const& lhs, Int const& rhs)
{
  return lhs.impl_->mpz < rhs.impl_->mpz;
}

bool operator<=(Int const& lhs, Int const& rhs)
{
  return lhs.impl_->mpz <= rhs.impl_->mpz;
}

bool operator>(Int const& lhs, Int const& rhs)
{
  return lhs.impl_->mpz > rhs.impl_->mpz;
}

bool operator>=(Int const& lhs, Int const& rhs)
{
  return lhs.impl_->mpz >= rhs.impl_->mpz;
}

} // namespace chia
