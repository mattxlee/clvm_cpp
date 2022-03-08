#include "int.h"

#include <gmpxx.h>

#include <sstream>

#include "utils.h"

namespace chia
{

bool is_valid_int_char(char ch) { return ch >= '0' && ch <= '9'; }

bool is_valid_hex_char(char ch) { return ch >= 'a' && ch <= 'f' || ch >= 'A' && ch <= 'F'; }

bool check_valid_hex_string(std::string s)
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

bool check_valid_int_string(std::string s)
{
    if (s.empty()) {
        return false;
    }
    for (char ch : s) {
        if (!is_valid_int_char(ch)) {
            return false;
        }
    }
    return true;
}

bool check_valid_int(std::string s)
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

std::tuple<std::string, bool> strip_sign(std::string s)
{
    if (s.empty()) {
        return std::make_tuple("", false);
    }

    if (s[0] == '+' || s[0] == '-') {
        return std::make_tuple(std::string(s.substr(1)), s[0] == '-');
    }

    return std::make_tuple(std::string(s), false);
}

struct Impl {
    mpz_class mpz;
};

bool Int::IsValidNumberStr(std::string s) { return check_valid_int(s); }

std::unique_ptr<Impl> create_impl_from_mpz(mpz_class mpz) { return std::unique_ptr<Impl>(new Impl({ mpz })); }

Int::Int() { }

Int::~Int() { }

Int::Int(Int const& rhs)
    : impl_(new Impl({ rhs.impl_->mpz }))
{
}

Int::Int(std::string s, int base) { impl_.reset(new Impl { mpz_class(std::string(s), base) }); }

Int::Int(Bytes const& s, bool neg)
{
    std::stringstream ss;
    ss << "0x" << utils::BytesToHex(s);
    mpz_class mpz(ss.str());
    if (neg) {
        mpz *= -1;
    }
    impl_ = create_impl_from_mpz(std::move(mpz));
}

Int::Int(long val)
{
    mpz_class mpz(val);
    impl_ = create_impl_from_mpz(std::move(mpz));
}

Bytes Int::ToBytes(bool* neg) const
{
    std::string hex = impl_->mpz.get_str(16);
    std::string r;
    bool neg2;
    std::tie(r, neg2) = strip_sign(hex);
    if (neg) {
        *neg = neg2;
    }
    return utils::BytesFromHex(r);
}

int Int::NumBytes() const { return ToBytes().size(); }

long Int::ToInt() const { return impl_->mpz.get_si(); }

unsigned long Int::ToUInt() const { return impl_->mpz.get_ui(); }

Int Int::Abs() const
{
    mpz_class mpz = abs(impl_->mpz);
    Int i;
    i.impl_ = create_impl_from_mpz(std::move(mpz));
    return i;
}

Int& Int::operator=(Int const& rhs)
{
    if (this != &rhs) {
        impl_ = create_impl_from_mpz(rhs.impl_->mpz);
    }
    return *this;
}

Int Int::operator-(Int const& rhs) const
{
    mpz_class mpz = impl_->mpz - rhs.impl_->mpz;
    Int i;
    i.impl_ = create_impl_from_mpz(std::move(mpz));
    return i;
}

Int Int::operator+(Int const& rhs) const
{
    mpz_class mpz = impl_->mpz + rhs.impl_->mpz;
    Int i;
    i.impl_ = create_impl_from_mpz(std::move(mpz));
    return i;
}

Int Int::operator*(Int const& rhs) const
{
    mpz_class mpz = impl_->mpz * rhs.impl_->mpz;
    Int i;
    i.impl_ = create_impl_from_mpz(std::move(mpz));
    return i;
}

Int Int::operator/(Int const& rhs) const
{
    mpz_class mpz = impl_->mpz / rhs.impl_->mpz;
    Int i;
    i.impl_ = create_impl_from_mpz(std::move(mpz));
    return i;
}

Int Int::operator%(Int const& rhs) const
{
    mpz_class mpz = impl_->mpz % rhs.impl_->mpz;
    Int i;
    i.impl_ = create_impl_from_mpz(std::move(mpz));
    return i;
}

Int Int::operator^(Int const& rhs) const
{
    mpz_class mpz = impl_->mpz ^ rhs.impl_->mpz;
    Int i;
    i.impl_ = create_impl_from_mpz(std::move(mpz));
    return i;
}

Int Int::operator&(Int const& rhs) const
{
    mpz_class mpz = impl_->mpz & rhs.impl_->mpz;
    Int i;
    i.impl_ = create_impl_from_mpz(std::move(mpz));
    return i;
}

Int Int::operator|(Int const& rhs) const
{
    mpz_class mpz = impl_->mpz | rhs.impl_->mpz;
    Int i;
    i.impl_ = create_impl_from_mpz(std::move(mpz));
    return i;
}

Int Int::operator<<(int rhs) const
{
    mpz_class mpz = impl_->mpz << rhs;
    Int i;
    i.impl_ = create_impl_from_mpz(std::move(mpz));
    return i;
}

Int Int::operator>>(int rhs) const
{
    mpz_class mpz = impl_->mpz >> rhs;
    Int i;
    i.impl_ = create_impl_from_mpz(std::move(mpz));
    return i;
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

Int& Int::operator&=(Int const& rhs)
{
    *this = *this & rhs;
    return *this;
}

Int& Int::operator|=(Int const& rhs)
{
    *this = *this | rhs;
    return *this;
}

Int& Int::operator<<=(int rhs)
{
    *this = *this << rhs;
    return *this;
}

Int& Int::operator>>=(int rhs)
{
    *this = *this >> rhs;
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

Int Int::operator~() const
{
    auto new_mpz = ~impl_->mpz;
    Int i;
    i.impl_ = create_impl_from_mpz(std::move(new_mpz));
    return i;
}

bool operator==(Int const& lhs, Int const& rhs) { return lhs.impl_->mpz == rhs.impl_->mpz; }

bool operator!=(Int const& lhs, Int const& rhs) { return !(lhs == rhs); }

bool operator<(Int const& lhs, Int const& rhs) { return lhs.impl_->mpz < rhs.impl_->mpz; }

bool operator<=(Int const& lhs, Int const& rhs) { return lhs.impl_->mpz <= rhs.impl_->mpz; }

bool operator>(Int const& lhs, Int const& rhs) { return lhs.impl_->mpz > rhs.impl_->mpz; }

bool operator>=(Int const& lhs, Int const& rhs) { return lhs.impl_->mpz >= rhs.impl_->mpz; }

} // namespace chia
