#include "operator_lookup.h"

#include <iostream>

#include "core_opts.h"
#include "costs.h"
#include "more_opts.h"
#include "program.h"
#include "utils.h"

namespace chia
{

static std::string_view KEYWORDS =
    // core opcodes 0x01-x08
    ". q a i c f r l x "

    // opcodes on atoms as strings 0x09-0x0f
    "= >s sha256 substr strlen concat . "

    // opcodes on atoms as ints 0x10-0x17
    "+ - * / divmod > ash lsh "

    // opcodes on atoms as vectors of bools 0x18-0x1c
    "logand logior logxor lognot . "

    // opcodes for bls 1381 0x1d-0x1f
    "point_add pubkey_for_exp . "

    // bool opcodes 0x20-0x23
    "not any all . "

    // misc 0x24
    "softfork ";

std::map<std::string, std::string> OP_REWRITE = {
    { "+", "add" },
    { "-", "subtract" },
    { "*", "multiply" },
    { "/", "div" },
    { "i", "if" },
    { "c", "cons" },
    { "f", "first" },
    { "r", "rest" },
    { "l", "listp" },
    { "x", "raise" },
    { "=", "eq" },
    { ">", "gr" },
    { ">s", "gr_bytes" },
};

std::tuple<Cost, CLVMObjectPtr> default_unknown_op(Bytes const& op, CLVMObjectPtr args)
{
    if (op.empty() || (op.size() > 2 && op[0] == 0xff && op[1] == 0xff)) {
        throw std::runtime_error("reserved operator");
    }

    Cost cost_function = (*op.rbegin() & 0b11000000) >> 6;

    if (op.size() > 5) {
        throw std::runtime_error("invalid operator");
    }

    Cost cost_multiplier = Int(utils::ByteToBytes(*op.rbegin())).ToInt() + 1;

    Cost cost { 0 };
    if (cost_function == 0) {
        cost = 1;
    } else if (cost_function == 1) {
        cost = ARITH_BASE_COST;
        int arg_size = ArgsLen(args);
        int num_args = ListLen(args);
        cost += arg_size * ARITH_COST_PER_BYTE + num_args * ARITH_COST_PER_ARG;
    } else if (cost_function == 2) {
        cost = MUL_BASE_COST;
        try {
            auto [ok, b, next] = ArgsNext(args);
            int vs = static_cast<int>(b.size());
            while (ok) {
                auto [ok, b, n] = ArgsNext(next);
                if (ok) {
                    int rs = static_cast<int>(b.size());
                    cost += MUL_COST_PER_OP;
                    cost += (rs + vs) * MUL_LINEAR_COST_PER_BYTE;
                    cost += (rs * vs) / MUL_SQUARE_COST_PER_BYTE_DIVIDER;
                    vs += rs;
                    next = n;
                }
            }
        } catch (std::exception const&) {
            // TODO ignored exception should be caught
        }
    } else if (cost_function == 3) {
        cost = CONCAT_BASE_COST;
        int length = ArgsLen(args);
        cost += CONCAT_COST_PER_BYTE * length + ListLen(args) * CONCAT_COST_PER_ARG;
    }

    cost *= cost_multiplier;
    if (cost >= (static_cast<uint64_t>(1) << 32)) {
        throw std::runtime_error("invalid operator");
    }

    return std::make_tuple(cost, MakeNull());
}

Ops& Ops::GetInstance()
{
    static Ops instance;
    return instance;
}

void Ops::Assign(std::string_view op_name, OpFunc f) { ops_[op_name.data()] = std::move(f); }

OpFunc Ops::Query(std::string_view op_name)
{
    auto i = ops_.find(op_name.data());
    if (i == std::end(ops_)) {
        return OpFunc(); // an empty op indicates the op cannot be found
    }
    return i->second;
}

Ops::Ops()
{
    // Core operators
    Assign("if", op_if);
    Assign("cons", op_cons);
    Assign("first", op_first);
    Assign("rest", op_rest);
    Assign("listp", op_listp);
    Assign("raise", op_raise);
    Assign("eq", op_eq);
    // More operators
    Assign("sha256", op_sha256);
    Assign("add", op_add);
    Assign("subtract", op_subtract);
    Assign("multiply", op_multiply);
    Assign("divmod", op_divmod);
    Assign("div", op_div);
    Assign("gr", op_gr);
    Assign("gr_bytes", op_gr_bytes);
    Assign("pubkey_for_exp", op_pubkey_for_exp);
    Assign("point_add", op_point_add);
    Assign("strlen", op_strlen);
    Assign("substr", op_substr);
    Assign("concat", op_concat);
    Assign("ash", op_ash);
    Assign("lsh", op_lsh);
    Assign("logand", op_logand);
    Assign("logior", op_logior);
    Assign("logxor", op_logxor);
    Assign("lognot", op_lognot);
    Assign("not", op_not);
    Assign("any", op_any);
    Assign("all", op_all);
    Assign("softfork", op_softfork);
}

OperatorLookup::OperatorLookup()
{
    InitKeywords();
    QUOTE_ATOM = utils::ByteToBytes(KeywordToAtom("q"));
    APPLY_ATOM = utils::ByteToBytes(KeywordToAtom("a"));
}

std::tuple<Cost, CLVMObjectPtr> OperatorLookup::operator()(Bytes const& op, CLVMObjectPtr args) const
{
    try {
        Keywords keywords = AtomToKeywords(op[0]);
        for (std::string const& keyword : keywords) {
            auto op_f = Ops::GetInstance().Query(keyword);
            if (op_f) {
                return op_f(args);
            }
        }
    } catch (std::exception const& e) {
        std::cerr << e.what() << std::endl;
    }
    std::cerr << "unknown op 0x" << utils::BytesToHex(op) << std::endl;
    return default_unknown_op(op, args);
}

std::string OperatorLookup::AtomToKeyword(uint8_t a) const
{
    auto i = atom_to_keywords_.find(a);
    if (i != std::end(atom_to_keywords_)) {
        return i->second[0];
    }
    throw std::runtime_error("keyword cannot be found by the atom");
}

OperatorLookup::Keywords OperatorLookup::AtomToKeywords(uint8_t a) const
{
    auto i = atom_to_keywords_.find(a);
    if (i != std::end(atom_to_keywords_)) {
        return i->second;
    }
    throw std::runtime_error("keyword cannot be found by the atom");
}

uint8_t OperatorLookup::KeywordToAtom(std::string_view keyword) const
{
    auto i
        = std::find_if(std::begin(atom_to_keywords_), std::end(atom_to_keywords_), [keyword](auto const& val) -> bool {
              auto i = std::find(std::begin(val.second), std::end(val.second), keyword);
              return i != std::end(val.second);
          });
    if (i != std::end(atom_to_keywords_)) {
        return i->first;
    }
    throw std::runtime_error("atom cannot be found by the keyword");
}

int OperatorLookup::GetCount() const { return static_cast<int>(atom_to_keywords_.size()); }

void OperatorLookup::AddKeyword(uint8_t atom, std::string_view keyword)
{
    auto i = atom_to_keywords_.find(atom);
    if (i != std::end(atom_to_keywords_)) {
        i->second.push_back(std::string(keyword));
        return;
    }
    Keywords keywords { std::string(keyword) };
    atom_to_keywords_.emplace(std::make_pair(atom, keywords));
}

void OperatorLookup::InitKeywords()
{
    std::string::size_type start { 0 };
    uint8_t byte { 0 };
    auto next = KEYWORDS.find(" ", start);
    while (next != std::string::npos) {
        std::string keyword { KEYWORDS.substr(start, next - start) };
        // Replace the keyword with OP_REWRITE
        auto i = OP_REWRITE.find(keyword);
        if (i != std::end(OP_REWRITE)) {
            // Override the keyword
            AddKeyword(byte, i->second);
        }
        AddKeyword(byte, keyword);
        // Ready for next
        ++byte;
        start = next + 1;
        next = KEYWORDS.find(" ", start);
    }
}

} // namespace chia
