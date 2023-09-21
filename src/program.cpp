#include "program.h"

#include <iostream>
#include <memory>
#include <stdexcept>
#include <algorithm>

#include "assemble.h"
#include "costs.h"
#include "crypto_utils.h"
#include "key.h"
#include "operator_lookup.h"
#include "utils.h"

namespace chia
{

uint8_t const MAX_SINGLE_BYTE = 0x7F;
uint8_t const CONS_BOX_MARKER = 0xFF;

std::string NodeTypeToString(NodeType type)
{
    switch (type) {
    case NodeType::None:
        return "None";
    case NodeType::List:
        return "List";
    case NodeType::Tuple:
        return "Tuple";
    case NodeType::Atom_Bytes:
        return "Atom_Bytes";
    case NodeType::Atom_G1Element:
        return "Atom_G1Element";
    case NodeType::Atom_Int:
        return "Atom_Int";
    case NodeType::Atom_Str:
        return "Atom_Str";
    }
    return "None";
}

/**
 * =============================================================================
 * CLVMObject
 * =============================================================================
 */

CLVMObject::CLVMObject(NodeType type)
    : type_(type)
{
}

CLVMObject_Atom::CLVMObject_Atom()
    : CLVMObject(NodeType::None)
{
}

CLVMObject_Atom::CLVMObject_Atom(Bytes bytes)
    : CLVMObject(NodeType::Atom_Bytes)
    , bytes_(std::move(bytes))
{
}

CLVMObject_Atom::CLVMObject_Atom(std::string str)
    : CLVMObject(NodeType::Atom_Str)
{
    bytes_.resize(str.size());
    memcpy(bytes_.data(), str.data(), str.size());
}

CLVMObject_Atom::CLVMObject_Atom(long i)
    : CLVMObject_Atom(Int(i))
{
}

CLVMObject_Atom::CLVMObject_Atom(Int const& i)
    : CLVMObject(NodeType::Atom_Int)
{
    bytes_ = i.ToBytes(&neg_);
}

CLVMObject_Atom::CLVMObject_Atom(PublicKey const& g1_element)
    : CLVMObject(NodeType::Atom_G1Element)
{
    bytes_ = utils::bytes_cast<wallet::Key::PUB_KEY_LEN>(g1_element);
}

bool CLVMObject_Atom::IsFalse() const
{
    if (GetNodeType() == NodeType::None) {
        return true;
    }
    if (GetNodeType() == NodeType::Atom_Int) {
        Int i(bytes_, neg_);
        return i == Int(0);
    }
    return false;
}

bool CLVMObject_Atom::EqualsTo(CLVMObjectPtr rhs) const
{
    if (IsFalse() && rhs->IsFalse()) {
        return true;
    }
    if (GetNodeType() != rhs->GetNodeType()) {
        return false;
    }
    auto rhs_p = std::static_pointer_cast<CLVMObject_Atom>(rhs);
    return neg_ == rhs_p->neg_ && bytes_ == rhs_p->bytes_;
}

Bytes CLVMObject_Atom::GetBytes() const { return bytes_; }

std::string CLVMObject_Atom::AsString() const { return std::string(std::begin(bytes_), std::end(bytes_)); }

long CLVMObject_Atom::AsLong() const { return Int(bytes_, neg_).ToInt(); }

Int CLVMObject_Atom::AsInt() const { return Int(bytes_, neg_); }

PublicKey CLVMObject_Atom::AsG1Element() const { return utils::bytes_cast<wallet::Key::PUB_KEY_LEN>(bytes_); }

CLVMObject_Pair::CLVMObject_Pair(CLVMObjectPtr first, CLVMObjectPtr rest, NodeType type)
    : CLVMObject(type)
    , first_(first)
    , rest_(rest)
{
}

CLVMObjectPtr CLVMObject_Pair::GetFirstNode() const { return first_; }

CLVMObjectPtr CLVMObject_Pair::GetRestNode() const { return rest_; }

void CLVMObject_Pair::SetRestNode(CLVMObjectPtr rest) { rest_ = rest; }

bool CLVMObject_Pair::EqualsTo(CLVMObjectPtr rhs) const { throw std::runtime_error("cannot compare pairs"); }

bool IsAtom(CLVMObjectPtr obj)
{
    if (!obj) {
        throw std::runtime_error("can't find the type from a null element");
    }
    return obj->GetNodeType() == NodeType::Atom_Bytes || obj->GetNodeType() == NodeType::Atom_G1Element
        || obj->GetNodeType() == NodeType::Atom_Int || obj->GetNodeType() == NodeType::Atom_Str
        || obj->GetNodeType() == NodeType::None;
}

bool IsPair(CLVMObjectPtr obj)
{
    if (!obj) {
        throw std::runtime_error("can't find the type from a null element");
    }
    return obj->GetNodeType() == NodeType::List || obj->GetNodeType() == NodeType::Tuple;
}

bool IsNull(CLVMObjectPtr obj) { return obj->GetNodeType() == NodeType::None; }

Bytes Atom(CLVMObjectPtr obj)
{
    if (!obj) {
        throw std::runtime_error("can't convert null to atom");
    }
    if (!IsAtom(obj)) {
        throw std::runtime_error("it's not an ATOM");
    }
    auto atom = static_cast<CLVMObject_Atom*>(obj.get());
    return atom->GetBytes();
}

Int ToInt(CLVMObjectPtr obj)
{
    if (IsNull(obj)) {
        return Int(0);
    }
    if (obj->GetNodeType() != NodeType::Atom_Int) {
        throw std::runtime_error("it's not an INT");
    }
    auto int_p = std::static_pointer_cast<CLVMObject_Atom>(obj);
    return int_p->AsInt();
}

std::string ToString(CLVMObjectPtr obj)
{
    if (obj->GetNodeType() != NodeType::Atom_Str) {
        return "";
    }
    auto b = Atom(obj);
    return std::string(std::begin(b), std::end(b));
}

std::tuple<CLVMObjectPtr, CLVMObjectPtr> Pair(CLVMObjectPtr obj)
{
    if (!obj) {
        throw std::runtime_error("can't convert null to pair");
    }
    if (!IsPair(obj)) {
        throw std::runtime_error("Pair() it's not a PAIR");
    }
    auto pair = static_cast<CLVMObject_Pair*>(obj.get());
    return std::make_tuple(pair->GetFirstNode(), pair->GetRestNode());
}

CLVMObjectPtr First(CLVMObjectPtr obj)
{
    if (!IsPair(obj)) {
        throw std::runtime_error("First() it's not a PAIR");
    }
    auto pair = static_cast<CLVMObject_Pair*>(obj.get());
    return pair->GetFirstNode();
}

CLVMObjectPtr Rest(CLVMObjectPtr obj)
{
    if (!IsPair(obj)) {
        throw std::runtime_error("Rest() it's not a PAIR");
    }
    auto pair = static_cast<CLVMObject_Pair*>(obj.get());
    return pair->GetRestNode();
}

CLVMObjectPtr MakeNull() { return std::make_shared<CLVMObject_Atom>(); }

int ListLen(CLVMObjectPtr list)
{
    int count { 0 };
    while (IsPair(list)) {
        ++count;
        std::tie(std::ignore, list) = Pair(list);
    }
    return count;
}

CLVMObjectPtr ToSExp(CLVMObjectPtr obj) { return obj; }

/**
 * =============================================================================
 * Op: SExp
 * =============================================================================
 */

CLVMObjectPtr ToTrue() { return ToSExp(1); }

CLVMObjectPtr ToFalse() { return CLVMObjectPtr(new CLVMObject_Atom()); }

bool ListP(CLVMObjectPtr obj) { return IsPair(obj); }

int ArgsLen(CLVMObjectPtr obj)
{
    int len { 0 };
    while (obj->GetNodeType() == NodeType::List) {
        CLVMObjectPtr a, r;
        std::tie(a, r) = Pair(obj);
        if (!IsAtom(a)) {
            throw std::runtime_error("requires in args");
        }
        // Next
        len += static_cast<int>(Atom(a).size());
        obj = r;
    }
    return len;
}

std::tuple<bool, Bytes, CLVMObjectPtr> ArgsNext(CLVMObjectPtr obj)
{
    if (obj->GetNodeType() != NodeType::List) {
        return std::make_tuple(false, Bytes(), CLVMObjectPtr());
    }
    CLVMObjectPtr b, next;
    std::tie(b, next) = Pair(obj);
    Bytes bytes = Atom(b);
    return std::make_tuple(true, bytes, next);
}

std::tuple<Cost, CLVMObjectPtr> MallocCost(Cost cost, CLVMObjectPtr atom)
{
    return std::make_tuple(cost + Atom(atom).size() * MALLOC_COST_PER_BYTE, atom);
}

std::vector<std::tuple<Int, int>> ListInts(CLVMObjectPtr args)
{
    ArgsIter iter(args);
    std::vector<std::tuple<Int, int>> res;
    while (!iter.IsEof()) {
        int l;
        Int r = iter.NextInt(&l);
        res.push_back(std::make_tuple(r, l));
    }
    return res;
}

std::vector<Bytes> ListBytes(CLVMObjectPtr args)
{
    std::vector<Bytes> res;
    ArgsIter iter(args);
    while (!iter.IsEof()) {
        res.push_back(iter.Next());
    }
    return res;
}

/**
 * =============================================================================
 * SExp Stream
 * =============================================================================
 */

namespace stream
{

class OpStack;

using Op = std::function<void(OpStack&, ValStack&, StreamReadFunc&)>;

class OpStack : public Stack<Op>
{
};

class StreamReader
{
public:
    explicit StreamReader(Bytes const& bytes)
        : bytes_(bytes)
    {
    }

    Bytes operator()(int size) const
    {
        Bytes res;
        int read_size = std::min<int>(size, static_cast<int>(bytes_.size() - pos_));
        if (read_size == 0) {
            return res;
        }
        res.resize(read_size);
        memcpy(res.data(), bytes_.data() + pos_, read_size);
        pos_ += read_size;
        return res;
    }

private:
    Bytes const& bytes_;
    mutable int pos_ { 0 };
};

CLVMObjectPtr AtomFromStream(StreamReadFunc f, uint8_t b)
{
    if (b == 0x80) {
        return ToSExp(MakeNull());
    }
    if (b <= MAX_SINGLE_BYTE) {
        return ToSExp(utils::ByteToBytes(b));
    }
    int bit_count { 0 };
    int bit_mask { 0x80 };
    while (b & bit_mask) {
        bit_count += 1;
        b &= 0xff ^ bit_mask;
        bit_mask >>= 1;
    }
    Bytes size_blob = utils::ByteToBytes(b);
    if (bit_count > 1) {
        Bytes b = f(bit_count - 1);
        if (b.size() != bit_count - 1) {
            throw std::runtime_error("bad encoding");
        }
        size_blob = utils::ConnectBuffers(size_blob, b);
    }
    uint64_t size = Int(size_blob).ToUInt(); // TODO The size might overflow
    if (size >= 0x400000000) {
        throw std::runtime_error("blob too large");
    }
    Bytes blob = f(static_cast<int>(size));
    if (blob.size() != size) {
        throw std::runtime_error("bad encoding");
    }
    return ToSExp(blob);
}

void OpCons(OpStack& op_stack, ValStack& val_stack, StreamReadFunc& f)
{
    auto right = val_stack.Pop();
    auto left = val_stack.Pop();
    val_stack.Push(ToSExpPair(left, right));
}

void OpReadSExp(OpStack& op_stack, ValStack& val_stack, StreamReadFunc& f)
{
    Bytes blob = f(1);
    if (blob.empty()) {
        throw std::runtime_error("bad encoding");
    }
    uint8_t b = blob[0];
    if (b == CONS_BOX_MARKER) {
        op_stack.Push(OpCons);
        op_stack.Push(OpReadSExp);
        op_stack.Push(OpReadSExp);
        return;
    }
    val_stack.Push(AtomFromStream(f, b));
}

CLVMObjectPtr SExpFromStream(ReadStreamFunc f)
{
    OpStack op_stack;
    op_stack.Push(OpReadSExp);
    ValStack val_stack;

    while (!op_stack.IsEmpty()) {
        auto func = op_stack.Pop();
        func(op_stack, val_stack, f);
    }
    return val_stack.Pop();
}

Bytes AtomToBytes(Bytes const& as_atom)
{
    uint64_t size = as_atom.size();
    if (size == 0) {
        return utils::ByteToBytes('\x80');
    }
    if (size == 1) {
        if (as_atom[0] <= MAX_SINGLE_BYTE) {
            return as_atom;
        }
    }
    Bytes size_blob;
    if (size < 0x40) {
        size_blob = utils::ByteToBytes(static_cast<uint8_t>(0x80 | size));
    } else if (size < 0x2000) {
        size_blob.push_back(static_cast<uint8_t>(0xC0 | (size >> 8)));
        size_blob.push_back(static_cast<uint8_t>((size >> 8) & 0xff));
    } else if (size < 0x100000) {
        size_blob.push_back(static_cast<uint8_t>(0xe0 | (size >> 16)));
        size_blob.push_back(static_cast<uint8_t>((size >> 8) & 0xff));
        size_blob.push_back(static_cast<uint8_t>((size >> 0) & 0xff));
    } else if (size < 0x8000000) {
        size_blob.push_back(static_cast<uint8_t>(0xF0 | (size >> 24)));
        size_blob.push_back(static_cast<uint8_t>((size >> 16) & 0xFF));
        size_blob.push_back(static_cast<uint8_t>((size >> 8) & 0xFF));
        size_blob.push_back(static_cast<uint8_t>((size >> 0) & 0xFF));
    } else if (size < 0x400000000) {
        size_blob.push_back(static_cast<uint8_t>(0xF8 | (size >> 32)));
        size_blob.push_back(static_cast<uint8_t>((size >> 24) & 0xFF));
        size_blob.push_back(static_cast<uint8_t>((size >> 16) & 0xFF));
        size_blob.push_back(static_cast<uint8_t>((size >> 8) & 0xFF));
        size_blob.push_back(static_cast<uint8_t>((size >> 0) & 0xFF));
    } else {
        throw std::runtime_error("sexp too long");
    }
    return utils::ConnectBuffers(size_blob, as_atom);
}

Bytes SExpToStream(CLVMObjectPtr sexp)
{
    Bytes res;
    ValStack todo_stack;
    todo_stack.Push(sexp);

    while (!todo_stack.IsEmpty()) {
        CLVMObjectPtr sexp = todo_stack.Pop();
        if (IsPair(sexp)) {
            res.push_back(CONS_BOX_MARKER);
            CLVMObjectPtr first, rest;
            std::tie(first, rest) = Pair(sexp);
            todo_stack.Push(rest);
            todo_stack.Push(first);
        } else {
            res = utils::ConnectBuffers(res, AtomToBytes(Atom(sexp)));
        }
    }
    return res;
}

} // namespace stream

/**
 * =============================================================================
 * Tree hash
 * =============================================================================
 */

namespace tree_hash
{

class OpStack;
using Op = std::function<void(ValStack&, OpStack&)>;

class OpStack : public Stack<Op>
{
};

Bytes32 SHA256TreeHash(CLVMObjectPtr sexp, std::vector<Bytes> const& precalculated = std::vector<Bytes>())
{
    Op handle_pair = [](ValStack& sexp_stack, OpStack& op_stack) {
        auto p0 = sexp_stack.Pop();
        auto p1 = sexp_stack.Pop();
        Bytes prefix = utils::ByteToBytes('\2');
        sexp_stack.Push(
            ToSExp(utils::bytes_cast<32>(crypto_utils::MakeSHA256(utils::ConnectBuffers(prefix, Atom(p0), Atom(p1))))));
    };

    Op roll = [](ValStack& sexp_stack, OpStack& op_stack) {
        auto p0 = sexp_stack.Pop();
        auto p1 = sexp_stack.Pop();
        sexp_stack.Push(p0);
        sexp_stack.Push(p1);
    };

    Op handle_sexp = [&handle_sexp, &handle_pair, &roll, &precalculated](ValStack& sexp_stack, OpStack& op_stack) {
        auto sexp = sexp_stack.Pop();
        if (IsPair(sexp)) {
            CLVMObjectPtr p0, p1;
            std::tie(p0, p1) = Pair(sexp);
            sexp_stack.Push(p0);
            sexp_stack.Push(p1);
            op_stack.Push(handle_pair);
            op_stack.Push(handle_sexp);
            op_stack.Push(roll);
            op_stack.Push(handle_sexp);
        } else {
            Bytes atom = Atom(sexp);
            auto i = std::find(std::begin(precalculated), std::end(precalculated), atom);
            Bytes r;
            if (i != std::end(precalculated)) {
                r = atom;
            } else {
                Bytes prefix = utils::ByteToBytes('\1');
                r = utils::bytes_cast<32>(crypto_utils::MakeSHA256(utils::ConnectBuffers(prefix, atom)));
            }
            sexp_stack.Push(ToSExp(r));
        }
    };

    ValStack sexp_stack;
    sexp_stack.Push(sexp);
    OpStack op_stack;
    op_stack.Push(handle_sexp);

    while (!op_stack.IsEmpty()) {
        auto op = op_stack.Pop();
        op(sexp_stack, op_stack);
    }

    assert(!sexp_stack.IsEmpty());
    auto res = sexp_stack.Pop();
    assert(sexp_stack.IsEmpty());
    assert(IsAtom(res));

    return utils::bytes_cast<32>(Atom(res));
}

} // namespace tree_hash

/**
 * =============================================================================
 * Program
 * =============================================================================
 */

Program Program::ImportFromBytes(Bytes const& bytes)
{
    Program prog;
    prog.sexp_ = stream::SExpFromStream(stream::StreamReader(bytes));
    return prog;
}

Program Program::ImportFromHex(std::string hex)
{
    Bytes prog_bytes = utils::BytesFromHex(hex);
    return ImportFromBytes(prog_bytes);
}

Program Program::ImportFromCompiledFile(std::string file_path)
{
    std::string hex = utils::LoadHexFromFile(file_path);
    return ImportFromHex(hex);
}

Program Program::ImportFromAssemble(std::string str)
{
    Program prog;
    prog.sexp_ = Assemble(str);
    return prog;
}

Program::Program(CLVMObjectPtr sexp)
    : sexp_(sexp)
{
}

Bytes32 Program::GetTreeHash() const { return tree_hash::SHA256TreeHash(sexp_); }

Bytes Program::Serialize() const { return stream::SExpToStream(sexp_); }

uint8_t msb_mask(uint8_t byte)
{
    byte |= byte >> 1;
    byte |= byte >> 2;
    byte |= byte >> 4;
    return (byte + 1) >> 1;
}

namespace run
{

class OpStack;
using Op = std::function<Cost(OpStack&, ValStack&)>;

class OpStack : public Stack<Op>
{
};

void debug_atom(std::string prefix, OperatorLookup const& operator_lookup, uint8_t atom)
{
    try {
        std::string keyword = operator_lookup.AtomToKeyword(atom);
        std::cerr << prefix << ": " << keyword << std::endl;
    } catch (std::exception const&) {
        std::cerr << prefix << ": unknown keyword -> 0x" << std::hex << (int)atom << std::endl;
    }
}

std::tuple<Cost, CLVMObjectPtr> traverse_path(CLVMObjectPtr sexp, CLVMObjectPtr env)
{
    Cost cost { PATH_LOOKUP_BASE_COST };
    cost += PATH_LOOKUP_COST_PER_LEG;
    if (IsNull(sexp)) {
        return std::make_tuple(cost, MakeNull());
    }

    Bytes b = Atom(sexp);

    int end_byte_cursor { 0 };
    while (end_byte_cursor < b.size() && b[end_byte_cursor] == 0) {
        ++end_byte_cursor;
    }

    cost += end_byte_cursor * PATH_LOOKUP_COST_PER_ZERO_BYTE;
    if (end_byte_cursor == b.size()) {
        return std::make_tuple(cost, MakeNull());
    }

    int end_bitmask = msb_mask(b[end_byte_cursor]);

    int byte_cursor = static_cast<int>(b.size()) - 1;
    int bitmask = 0x01;
    while (byte_cursor > end_byte_cursor || bitmask < end_bitmask) {
        if (!IsPair(env)) {
            throw std::runtime_error("path into atom {env}");
        }
        CLVMObjectPtr first, rest;
        std::tie(first, rest) = Pair(env);
        env = (b[byte_cursor] & bitmask) ? rest : first;
        cost += PATH_LOOKUP_COST_PER_LEG;
        bitmask <<= 1;
        if (bitmask == 0x100) {
            --byte_cursor;
            bitmask = 0x01;
        }
    }

    return std::make_tuple(cost, env);
};

std::tuple<Cost, CLVMObjectPtr> run_program(CLVMObjectPtr program, CLVMObjectPtr args,
    OperatorLookup const& operator_lookup = OperatorLookup(), Cost max_cost = 0)
{

    Op swap_op, cons_op, eval_op, apply_op;

    swap_op = [&apply_op](OpStack& op_stack, ValStack& val_stack) -> Cost {
        auto v2 = val_stack.Pop();
        auto v1 = val_stack.Pop();
        val_stack.Push(v2);
        val_stack.Push(v1);
        return 0;
    };

    cons_op = [](OpStack& op_stack, ValStack& val_stack) -> Cost {
        auto v2 = val_stack.Pop();
        auto v1 = val_stack.Pop();
        val_stack.Push(ToSExpPair(v2, v1));
        return 0;
    };

    eval_op
        = [&operator_lookup, &apply_op, &cons_op, &eval_op, &swap_op](OpStack& op_stack, ValStack& val_stack) -> Cost {
        auto pair = val_stack.Pop();
        CLVMObjectPtr sexp, args;
        std::tie(sexp, args) = Pair(pair);
        if (!IsPair(sexp)) {
            Cost cost;
            CLVMObjectPtr r;
            std::tie(cost, r) = traverse_path(sexp, args);
            val_stack.Push(r);
            return cost;
        }

        CLVMObjectPtr opt, sexp_rest;
        std::tie(opt, sexp_rest) = Pair(sexp);
        if (IsPair(opt)) {
            CLVMObjectPtr new_opt, must_be_nil;
            std::tie(new_opt, must_be_nil) = Pair(opt);
            if (IsPair(new_opt) || !IsNull(must_be_nil)) {
                throw std::runtime_error("syntax X must be lone atom");
            }
            auto new_operand_list = sexp_rest;
            val_stack.Push(new_opt);
            val_stack.Push(new_operand_list);
            op_stack.Push(apply_op);
            return APPLY_COST;
        }

        Bytes op = Atom(opt);
        auto operand_list = sexp_rest;
        if (op == operator_lookup.QUOTE_ATOM) {
            val_stack.Push(operand_list);
            return QUOTE_COST;
        }

        op_stack.Push(apply_op);
        val_stack.Push(opt);
        while (!IsNull(operand_list)) {
            CLVMObjectPtr _, r;
            std::tie(_, r) = Pair(operand_list);
            val_stack.Push(ToSExpPair(_, args));
            op_stack.Push(cons_op);
            op_stack.Push(eval_op);
            op_stack.Push(swap_op);
            operand_list = r;
        }

        val_stack.Push(MakeNull());
        return 1;
    };

    apply_op = [&operator_lookup, &eval_op](OpStack& op_stack, ValStack& val_stack) -> Cost {
        auto operand_list = val_stack.Pop();
        auto opt = val_stack.Pop();
        if (IsPair(opt)) {
            throw std::runtime_error("internal error");
        }

        Bytes op = Atom(opt);
        if (op == operator_lookup.APPLY_ATOM) {
            if (ListLen(operand_list) != 2) {
                throw std::runtime_error("apply requires exactly 2 parameters");
            }
            CLVMObjectPtr new_program, r;
            std::tie(new_program, r) = Pair(operand_list);
            auto r_first = First(r);
            if (!IsPair(r_first)) {
                throw std::runtime_error("argument of eval_op is not a pair");
            }
            val_stack.Push(ToSExpPair(new_program, r_first));
            op_stack.Push(eval_op);
            return APPLY_COST;
        }

        Cost additional_cost;
        CLVMObjectPtr r;
        std::tie(additional_cost, r) = operator_lookup(op, operand_list);
        val_stack.Push(r);
        return additional_cost;
    };

    OpStack op_stack;
    op_stack.Push(eval_op);

    ValStack val_stack;
    val_stack.Push(ToSExpPair(program, args));
    Cost cost { 0 };

    while (!op_stack.IsEmpty()) {
        auto f = op_stack.Pop();
        cost += f(op_stack, val_stack);
        if (max_cost && cost > max_cost) {
            throw std::runtime_error("cost exceeded");
        }
    }

    return std::make_tuple(cost, val_stack.GetLast());
}

} // namespace run

std::tuple<Cost, CLVMObjectPtr> Program::Run(CLVMObjectPtr args) { return run::run_program(sexp_, args); }

std::string CURRY_OBJ_CODE = "(a (q #a 4 (c 2 (c 5 (c 7 0)))) (c (q (c (q "
                             ". 2) (c (c (q . 1) 5) (c (a 6 "
                             "(c 2 (c 11 (q 1)))) 0))) #a (i 5 (q 4 (q . "
                             "4) (c (c (q . 1) 9) (c (a 6 (c "
                             "2 (c 13 (c 11 0)))) 0))) (q . 11)) 1) 1))";

Program Program::Curry(CLVMObjectPtr args)
{
    auto curry_program = Assemble(CURRY_OBJ_CODE);
    auto bind_args = ToSExpPair(sexp_, ToSExpList(args));
    Cost cost;
    CLVMObjectPtr sexp;
    std::tie(cost, sexp) = run::run_program(curry_program, bind_args);
    return Program(sexp);
}

} // namespace chia
