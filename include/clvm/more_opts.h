#ifndef CHIA_MORE_OPTS_H
#define CHIA_MORE_OPTS_H

#include "core_opts.h"
#include "sexp_prog.h"

namespace chia
{

OpResult op_sha256(CLVMObjectPtr args);

OpResult op_add(CLVMObjectPtr args);

OpResult op_subtract(CLVMObjectPtr args);

OpResult op_multiply(CLVMObjectPtr args);

OpResult op_divmod(CLVMObjectPtr args);

OpResult op_div(CLVMObjectPtr args);

OpResult op_gr(CLVMObjectPtr args);

OpResult op_gr_bytes(CLVMObjectPtr args);

OpResult op_pubkey_for_exp(CLVMObjectPtr args);

OpResult op_point_add(CLVMObjectPtr args);

OpResult op_strlen(CLVMObjectPtr args);

OpResult op_substr(CLVMObjectPtr args);

OpResult op_concat(CLVMObjectPtr args);

OpResult op_ash(CLVMObjectPtr args);

OpResult op_lsh(CLVMObjectPtr args);

OpResult op_logand(CLVMObjectPtr args);

OpResult op_logior(CLVMObjectPtr args);

OpResult op_logxor(CLVMObjectPtr args);

OpResult op_lognot(CLVMObjectPtr args);

OpResult op_not(CLVMObjectPtr args);

OpResult op_any(CLVMObjectPtr args);

OpResult op_all(CLVMObjectPtr args);

OpResult op_softfork(CLVMObjectPtr args);

} // namespace chia

#endif
