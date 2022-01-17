#include "more_opts.h"

#include "costs.h"
#include "crypto_utils.h"
#include "key.h"
#include "program.h"

namespace chia {

OpResult op_sha256(CLVMObjectPtr args) {
  crypto_utils::SHA256 sha256;
  Cost cost{SHA256_BASE_COST};
  int arg_len{0};
  ArgsIter iter(args);
  while (!iter.IsEof()) {
    Bytes b = iter.Next();
    sha256.Add(b);
    arg_len += b.size();
    cost += SHA256_COST_PER_ARG;
  }
  cost += arg_len * SHA256_COST_PER_ARG;
  return MallocCost(cost, ToSExp(utils::bytes_cast<32>(sha256.Finish())));
}

OpResult op_add(CLVMObjectPtr args) {
  int total{0};
  Cost cost{ARITH_BASE_COST};
  int arg_size{0};
  int len;
  ArgsIter iter(args);
  while (!iter.IsEof()) {
    total += iter.NextInt<int>(&len);
    arg_size += len;
    cost += ARITH_COST_PER_ARG;
  }
  cost += arg_size * ARITH_COST_PER_BYTE;
  return MallocCost(cost, ToSExp(utils::IntToBytesBE(total)));
}

OpResult op_subtract(CLVMObjectPtr args) {
  Cost cost{ARITH_BASE_COST};
  ArgsIter iter(args);
  if (iter.IsEof()) {
    return MallocCost(cost, ToSExp(utils::IntToBytesBE(0)));
  }
  int sign{1}, total{0}, arg_size{0};
  while (!iter.IsEof()) {
    int l;
    int r = iter.NextInt<int>(&l);
    total += sign * r;
    sign = -1;
    arg_size += l;
    cost += ARITH_COST_PER_ARG;
  }
  cost += arg_size * ARITH_COST_PER_BYTE;
  return MallocCost(cost, ToSExp(utils::IntToBytesBE(total)));
}

OpResult op_multiply(CLVMObjectPtr args) {
  Cost cost{MUL_BASE_COST};
  ArgsIter iter(args);
  if (iter.IsEof()) {
    return MallocCost(cost, ToSExp(utils::IntToBytesBE(1)));
  }
  int vs;
  int v = iter.NextInt<int>(&vs);
  while (!iter.IsEof()) {
    int rs;
    int r = iter.NextInt<int>(&rs);
    cost += MUL_COST_PER_OP;
    cost += (rs + vs) * MUL_LINEAR_COST_PER_BYTE;
    cost += (rs * vs) / MUL_SQUARE_COST_PER_BYTE_DIVIDER;
    v *= r;
    vs = 4;  // TODO fix the length of the integer, it might be larger than 4
             // bytes
  }
  return MallocCost(cost, ToSExp(utils::IntToBytesBE(v)));
}

OpResult op_divmod(CLVMObjectPtr args) {
  Cost cost{DIVMOD_BASE_COST};
  auto ints = ListInts<int>(args);
  if (ints.size() != 2) {
    throw std::runtime_error("invalid length of args");
  }
  auto [i0, l0] = ints[0];
  auto [i1, l1] = ints[1];
  cost += (l0 + l1) * DIVMOD_COST_PER_BYTE;
  auto q = i0 / i1;
  auto r = i0 % i1;
  auto q1 = ToSExp(utils::IntToBytesBE(q));
  auto r1 = ToSExp(utils::IntToBytesBE(r));
  cost += (Atom(q1).size() + Atom(r1).size()) * MALLOC_COST_PER_BYTE;
  return std::make_tuple(cost, ToSExp(q1, r1));
}

OpResult op_div(CLVMObjectPtr args) {
  Cost cost{DIV_BASE_COST};
  auto ints = ListInts<int>(args);
  if (ints.size() != 2) {
    throw std::runtime_error("the number of arguments must equals to 2");
  }
  auto [i0, l0] = ints[0];
  auto [i1, l1] = ints[1];
  if (i1 == 0) {
    throw std::runtime_error("div with 0");
  }
  cost += (l0 + l1) * DIV_COST_PER_BYTE;
  auto q = i0 / i1;
  auto r = i0 % i1;
  if (q == -1 && r != 0) {
    q += 1;
  }
  return MallocCost(cost, ToSExp(utils::IntToBytesBE(q)));
}

OpResult op_gr(CLVMObjectPtr args) {
  auto ints = ListInts<int>(args);
  auto [i0, l0] = ints[0];
  auto [i1, l1] = ints[1];
  if (ints.size() != 2) {
    throw std::runtime_error("the number of args must equals to 2");
  }
  Cost cost{GR_BASE_COST};
  cost += (l0 + l1) * GR_COST_PER_BYTE;
  return std::make_tuple(cost, i0 > i1 ? ToTrue() : ToFalse());
}

OpResult op_gr_bytes(CLVMObjectPtr args) {
  auto bytes_list = ListBytes(args);
  if (bytes_list.size() != 2) {
    throw std::runtime_error(">s takes exactly 2 arguments");
  }
  auto b0 = bytes_list[0];
  auto b1 = bytes_list[1];
  Cost cost{GRS_BASE_COST};
  cost += (b0.size() + b1.size()) * GRS_COST_PER_BYTE;
  return std::make_tuple(
      cost, utils::IntFromBytesBE<int>(b0) > utils::IntFromBytesBE<int>(b1)
                ? ToTrue()
                : ToFalse());
}

OpResult op_pubkey_for_exp(CLVMObjectPtr args) {}

OpResult op_point_add(CLVMObjectPtr args) {
  Cost cost{POINT_ADD_BASE_COST};
  wallet::PubKey p;
  ArgsIter iter(args);
  while (!iter.IsEof()) {
    Bytes b = iter.Next();
    p = p + wallet::PubKey(utils::bytes_cast<wallet::Key::PUB_KEY_LEN>(b));
    cost += POINT_ADD_COST_PER_ARG;
  }
  return MallocCost(
      cost,
      ToSExp(utils::bytes_cast<wallet::Key::PUB_KEY_LEN>(p.ToPublicKey())));
}

OpResult op_strlen(CLVMObjectPtr args) {
  if (ListLen(args) != 1) {
    throw std::runtime_error("strlen takes exactly 1 argument");
  }
  auto a0 = Atom(First(args));
  int size = a0.size();
  Cost cost = STRLEN_BASE_COST + size * STRLEN_COST_PER_BYTE;
  return MallocCost(cost, ToSExp(utils::IntToBytesBE(size)));
}

OpResult op_substr(CLVMObjectPtr args) {
  auto arg_list = ListBytes(args);
  int arg_count = arg_list.size();
  if (arg_count != 2 && arg_count != 3) {
    throw std::runtime_error("substr takes exactly 2 or 3 arguments");
  }
  auto s0 = arg_list[0];
  int i1 = utils::IntFromBytesBE<int>(arg_list[1]);
  int i2{0};
  if (arg_count == 2) {
    i2 = s0.size();
  } else {
    i2 = utils::IntFromBytesBE<int>(arg_list[2]);
  }
  if (i2 > s0.size() || i2 < i1 || i2 < 0 || i1 < 0) {
    throw std::runtime_error("invalid indices for substr");
  }
  Bytes s = utils::SubBytes(s0, i1, i2 - i1);
  Cost cost = 1;
  return std::make_tuple(cost, ToSExp(s));
}

OpResult op_concat(CLVMObjectPtr args) {
  Cost cost{CONCAT_BASE_COST};
  utils::BufferConnector conn;
  ArgsIter iter(args);
  while (!iter.IsEof()) {
    conn.Append(iter.Next());
    cost += CONCAT_COST_PER_ARG;
  }
  auto r = conn.GetResult();
  cost += r.size() * CONCAT_COST_PER_BYTE;
  return MallocCost(cost, ToSExp(r));
}

OpResult op_ash(CLVMObjectPtr args) {
  auto arg_list = ListInts<int>(args);
  auto [i0, l0] = arg_list[0];
  auto [i1, l1] = arg_list[1];
  if (l1 > 4) {
    throw std::runtime_error("ash requires int32 args (with no leading zeros)");
  }
  if (abs(i1) > 65535) {
    throw std::runtime_error("shift too large");
  }
  int r;
  if (i1 >= 0) {
    r = i0 << i1;
  } else {
    r = i0 >> -i1;
  }
  Cost cost{ASHIFT_BASE_COST};
  cost += (l0 + sizeof(int)) * ASHIFT_COST_PER_BYTE;
  return MallocCost(cost, ToSExp(utils::IntToBytesBE(r)));
}

OpResult op_lsh(CLVMObjectPtr args) {
  auto arg_list = ListInts<int>(args);
  // auto [i0, l0] = arg_list[0];
  auto [i1, l1] = arg_list[1];
  if (l1 > 4) {
    throw std::runtime_error("ash requires int32 args (with no leading zeros)");
  }
  if (abs(i1) > 65535) {
    throw std::runtime_error("shift too large");
  }
  uint32_t i0 = utils::IntFromBytesBE<uint32_t>(Atom(First(args)));
  uint32_t r;
  if (i1 >= 0) {
    r = i0 << i1;
  } else {
    r = i0 >> -i1;
  }
  Cost cost{LSHIFT_BASE_COST};
  cost += (sizeof(i0) + sizeof(r)) * LSHIFT_COST_PER_BYTE;
  return MallocCost(cost, ToSExp(utils::IntToBytesBE(r)));
}

using BinOpFunc = std::function<int(int, int)>;

OpResult binop_reduction(std::string_view op_name, int initial_value,
                         CLVMObjectPtr args, BinOpFunc op_f) {
  int total{initial_value};
  int arg_size{0};
  Cost cost{LOG_BASE_COST};
  ArgsIter iter(args);
  while (!iter.IsEof()) {
    int l;
    int r = iter.NextInt<int>(&l);
    total = op_f(total, r);
    arg_size += l;
    cost += LOG_COST_PER_ARG;
  }
  cost += arg_size * LOG_COST_PER_BYTE;
  return MallocCost(cost, ToSExp(utils::IntToBytesBE(total)));
}

OpResult op_logand(CLVMObjectPtr args) {
  auto binop = [](int a, int b) -> int {
    a &= b;
    return a;
  };
  return binop_reduction("logand", -1, args, binop);
}

OpResult op_logior(CLVMObjectPtr args) {
  auto binop = [](int a, int b) -> int {
    a |= b;
    return a;
  };
  return binop_reduction("logior", 0, args, binop);
}

OpResult op_logxor(CLVMObjectPtr args) {
  auto binop = [](int a, int b) -> int {
    a ^= b;
    return a;
  };
  return binop_reduction("logxor", 0, args, binop);
}

OpResult op_lognot(CLVMObjectPtr args) {
  if (ListLen(args) != 1) {
    throw std::runtime_error("op_not takes exactly 1 argument");
  }
  auto b0 = Atom(First(args));
  auto i0 = utils::IntFromBytesBE<int>(b0);
  int l0 = b0.size();
  Cost cost = LOGNOT_BASE_COST + l0 * LOGNOT_COST_PER_BYTE;
  return MallocCost(cost, ToSExp(utils::IntToBytesBE(~i0)));
}

OpResult op_not(CLVMObjectPtr args) {
  if (ListLen(args) != 1) {
    throw std::runtime_error("not takes exactly 1 argument");
  }
  Cost cost = BOOL_BASE_COST;
  return std::make_tuple(cost, IsNull(First(args)) ? ToTrue() : ToFalse());
}

OpResult op_any(CLVMObjectPtr args) {
  int num_items = ListLen(args);
  Cost cost = BOOL_BASE_COST + num_items * BOOL_COST_PER_ARG;
  auto r = ToFalse();
  ArgsIter iter(args);
  while (!iter.IsEof()) {
    auto b = iter.Next();
    if (!b.empty()) {
      r = ToTrue();
      break;
    }
  }
  return std::make_tuple(cost, r);
}

OpResult op_all(CLVMObjectPtr args) {
  int num_items = ListLen(args);
  Cost cost = BOOL_BASE_COST + num_items * BOOL_COST_PER_ARG;
  auto r = ToTrue();
  ArgsIter iter(args);
  while (!iter.IsEof()) {
    auto b = iter.Next();
    if (b.empty()) {
      r = ToFalse();
      break;
    }
  }
  return std::make_tuple(cost, r);
}

OpResult op_softfork(CLVMObjectPtr args) {
  int num_items = ListLen(args);
  if (num_items < 1) {
    throw std::runtime_error("softfork takes at least 1 argument");
  }
  auto a = Atom(First(args));
  Cost cost = utils::IntFromBytesBE<int>(a);
  if (cost < 1) {
    throw std::runtime_error("cost must be > 0");
  }
  return std::make_tuple(cost, ToFalse());
}

}  // namespace chia
