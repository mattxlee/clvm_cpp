#ifndef CHIA_INT_H
#define CHIA_INT_H

#include <memory>
#include <string_view>

#include "types.h"

namespace chia
{

struct Impl;

class Int
{
public:
    static bool IsValidNumberStr(std::string_view s);

    Int();

    ~Int();

    Int(Int const& rhs);

    /// Parse an integer from a string
    Int(std::string_view s, int base);

    explicit Int(Bytes const& s, bool neg = false);

    explicit Int(long val);

    Bytes ToBytes(bool* neg = nullptr) const;

    int NumBytes() const;

    long ToInt() const;

    unsigned long ToUInt() const;

    Int Abs() const;

    Int& operator=(Int const& rhs);

    Int operator-(Int const& rhs) const;
    Int operator+(Int const& rhs) const;
    Int operator*(Int const& rhs) const;
    Int operator/(Int const& rhs) const;
    Int operator%(Int const& rhs) const;
    Int operator^(Int const& rhs) const;
    Int operator&(Int const& rhs) const;
    Int operator|(Int const& rhs) const;
    Int operator<<(int rhs) const;
    Int operator>>(int rhs) const;

    Int& operator+=(Int const& rhs);
    Int& operator-=(Int const& rhs);
    Int& operator*=(Int const& rhs);
    Int& operator/=(Int const& rhs);
    Int& operator%=(Int const& rhs);
    Int& operator^=(Int const& rhs);
    Int& operator&=(Int const& rhs);
    Int& operator|=(Int const& rhs);
    Int& operator<<=(int rhs);
    Int& operator>>=(int rhs);

    Int operator++(int);
    Int& operator++();

    Int operator--(int);
    Int& operator--();

    Int operator~() const;

    friend bool operator==(Int const& lhs, Int const& rhs);
    friend bool operator!=(Int const& lhs, Int const& rhs);
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

} // namespace chia

#endif
