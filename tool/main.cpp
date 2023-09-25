#include <iostream>

#include <fstream>
#include <sstream>

#include <string>
#include <string_view>

#include <vector>
#include <map>
#include <memory>

#include <filesystem>
namespace fs = std::filesystem;

#include <cxxopts.hpp>

#include <json/json.h>

#include <curl/curl.h>

#include <mnemonic.h>
#include <random.h>
#include <toolbox.h>

#include "utils.h"
#include "wallet.h"
#include "bech32.h"

struct Args {
    // wallet
    bool wallet_new;
    std::string wallet_path;
    int wallet_num_sentences;
    bool wallet_overwrite;
    // query
    std::string query_address;
    std::string query_rpc_url;
    uint16_t query_rpc_port;
    std::string query_key_path;
    std::string query_cert_path;
};

class AbstractCommandHandler {
public:
    virtual ~AbstractCommandHandler()
    {
    }

    virtual Args ParseArgs(cxxopts::ParseResult const& result) const = 0;

    virtual int Run(Args const& args) const = 0;
};

class CommandExecutor {
public:
    std::vector<std::string> GetRegisteredCommands() const
    {
        std::vector<std::string> command_names;
        for (auto const& handler : handlers_) {
            command_names.push_back(handler.first);
        }
        return command_names;
    }

    template <typename T>
    void RegisterCommand(std::string command_name)
    {
        handlers_.insert_or_assign(std::move(command_name), std::make_unique<T>());
    }

    int RunWithCommand(std::string const& command_name, cxxopts::ParseResult const& result) const
    {
        auto it = handlers_.find(command_name);
        if (it == std::cend(handlers_)) {
            throw std::runtime_error(std::string("invalid command `") + command_name + "`");
        }
        return it->second->Run(it->second->ParseArgs(result));
    }

private:
    std::map<std::string, std::unique_ptr<AbstractCommandHandler>> handlers_;
};

namespace utils {

std::string ReadFromFile(std::string_view filepath)
{
    std::ifstream in(filepath);
    if (!in.is_open()) {
        throw std::runtime_error("Cannot open file to read");
    }
    in.seekg(0, std::ios::end);
    auto len = in.tellg();
    in.seekg(0, std::ios::beg);
    auto p = std::shared_ptr<char>(new char[len], [](char* p) {
        delete[] p;
    });
    in.read(p.get(), len);
    return std::string(p.get(), p.get() + len);
}

void WriteToFile(std::string_view filepath, std::string_view data)
{
    std::ofstream out(filepath);
    if (!out.is_open()) {
        throw std::runtime_error("Cannot open file to write");
    }
    out.write(data.data(), data.size());
}

};

class WalletFile {
public:
    explicit WalletFile(std::string filepath)
        : filepath_(std::move(filepath))
    {
    }

    ~WalletFile()
    {
    }

    void ReadFromFile()
    {
        FromJsonString(utils::ReadFromFile(filepath_));
    }

    void WriteToFile(std::string const& lang)
    {
        utils::WriteToFile(filepath_, ToJsonString(lang));
    }

    std::string ToJsonString(std::string const& lang) const
    {
        Json::Value value;
        if (mnemonic_) {
            value["mnemonic"] = GetMnemonicSentences();
            value["n"] = static_cast<Json::UInt64>(mnemonic_->GetWordList(lang).size());
            value["entropy"] = chia::utils::BytesToHex(mnemonic_->GetEntropyData());
            value["seed"] = chia::utils::BytesToHex(mnemonic_->CreateSeed(""));
            // Create account, public-key and private-key
            chia::wallet::Wallet wallet(*mnemonic_, "");
            value["primaryAddress"] = wallet.GetAddress(0, true);
        }
        return value.toStyledString();
    }

    void FromJsonString(std::string_view str)
    {
        Json::CharReaderBuilder builder;
        std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
        Json::Value value;
        std::string errs;
        if (!reader->parse(std::cbegin(str), std::cend(str), &value, &errs)) {
            throw std::runtime_error("Cannot parse the string into json");
        }
        if (!value.isMember("mnemonic")) {
            throw std::runtime_error("Field `mnemonic` is required from `wallet.json`");
        }
        SetMnemonicSentences(value["mnemonic"].asString(), "english");
    }

    void GenerateNew(int num_sentences, std::string_view lang = "english")
    {
        if (!bip39::Mnemonic::IsValidNumMnemonicSentences(num_sentences)) {
            throw std::runtime_error("Invalid number of sentences");
        }
        int num_bytes = bip39::Mnemonic::GetEntBitsByNumMnemonicSentences(num_sentences) / 8;
        bip39::RandomBytes r(num_bytes);
        mnemonic_ = std::make_unique<bip39::Mnemonic>(r.Random());
    }

    void SetMnemonicSentences(std::string sentences, std::string_view lang = "english")
    {
        mnemonic_ = std::make_unique<bip39::Mnemonic>(bip39::ParseWords(sentences, bip39::GetDelimiterByLang(lang)), std::string(lang));
    }

    std::string GetMnemonicSentences(std::string_view lang = "english") const
    {
        if (mnemonic_ == nullptr) {
            throw std::runtime_error("Wallet has no secret key generated, mnemonic sentences won't be returned");
        }
        return bip39::GenerateWords(mnemonic_->GetWordList(std::string(lang)), bip39::GetDelimiterByLang(lang));
    }

private:
    std::string filepath_;
    std::unique_ptr<bip39::Mnemonic> mnemonic_;
};

class CommandHandler_Wallet : public AbstractCommandHandler {
public:
    Args ParseArgs(cxxopts::ParseResult const& result) const override
    {
        Args args;
        args.wallet_new = result.count("new") > 0;
        args.wallet_path = result["path"].as<std::string>();
        args.wallet_num_sentences = result["num-sentences"].as<int>();
        args.wallet_overwrite = result.count("overwrite");
        return args;
    }

    int Run(Args const& args) const override
    {
        WalletFile wallet_file(args.wallet_path);
        if (args.wallet_new) {
            if (fs::is_regular_file(args.wallet_path) && fs::exists(args.wallet_path) && !args.wallet_overwrite) {
                throw std::runtime_error("To generate a new wallet, please ensure the output file doesn't exist");
            }
            wallet_file.GenerateNew(args.wallet_num_sentences);
            wallet_file.WriteToFile("english");
        } else {
            wallet_file.ReadFromFile();
        }
        return 0;
    }
};

class RPCClient {
public:
    RPCClient(std::string url, uint16_t port, std::string cert_path, std::string key_path)
        : url_(std::move(url))
        , cert_path_(std::move(cert_path))
        , key_path_(std::move(key_path))
    {
        curl_ = curl_easy_init();
        curl_easy_setopt(curl_, CURLOPT_PORT, port);
        curl_easy_setopt(curl_, CURLOPT_CAINFO, cert_path_.c_str());
        curl_easy_setopt(curl_, CURLOPT_SSH_PRIVATE_KEYFILE, key_path_.c_str());
    }

    ~RPCClient()
    {
        curl_easy_cleanup(curl_);
    }

    std::string Invoke(std::string_view method, std::string_view upload_data)
    {
        std::string url(url_);
        url += "/";
        url += method;
        curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
        uploading_data_ = upload_data.data();
        uploading_total_ = upload_data.size();
        uploading_offset_ = 0;
        curl_easy_setopt(curl_, CURLOPT_READDATA, this);
        curl_easy_setopt(curl_, CURLOPT_READFUNCTION, &RPCClient::read_callback);
        downloading_ss_.str("");
        downloading_ss_.clear();
        curl_easy_setopt(curl_, CURLOPT_WRITEDATA, this);
        curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, &RPCClient::write_callback);
        // prepare headers
        curl_slist* headers = curl_slist_append(nullptr, "Content-Type: application/json");
        curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers);
        CURLcode code = curl_easy_perform(curl_);
        curl_slist_free_all(headers);
        if (code != CURLE_OK) {
            char const* errs = curl_easy_strerror(code);
            throw std::runtime_error(errs);
        }
        return downloading_ss_.str();
    }

private:
    static size_t read_callback(char* buffer, size_t size, size_t nitems, void* userdata)
    {
        RPCClient* self = reinterpret_cast<RPCClient*>(userdata);
        int n = std::min<int>(size * nitems, self->uploading_total_ - self->uploading_offset_);
        memcpy(buffer, self->uploading_data_ + self->uploading_offset_, n);
        self->uploading_offset_ += n;
        return n;
    }

    static size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata)
    {
        RPCClient* self = reinterpret_cast<RPCClient*>(userdata);
        self->downloading_ss_ << std::string_view(ptr, size * nmemb);
        return size * nmemb;
    }

    CURL* curl_;
    std::string url_;
    std::string cert_path_;
    std::string key_path_;
    char const* uploading_data_;
    int uploading_total_;
    int uploading_offset_;
    std::stringstream downloading_ss_;
};

class CommandHandler_Query : public AbstractCommandHandler {
public:
    Args ParseArgs(cxxopts::ParseResult const& result) const override
    {
        Args args;
        args.query_address = result["address"].as<std::string>();
        args.query_rpc_url = result["rpc-url"].as<std::string>();
        args.query_rpc_port = result["rpc-port"].as<uint16_t>();
        args.query_cert_path = result["cert"].as<std::string>();
        args.query_key_path = result["key"].as<std::string>();
        return args;
    }

    int Run(Args const& args) const override
    {
        // Convert address to puzzle_hash
        auto puzzle_hash = chia::bech32::DecodePuzzleHash(args.query_address);
        Json::Value val;
        val["puzzle_hash"] = chia::utils::BytesToHex(chia::utils::IntsToBytes(puzzle_hash));
        val["include_spent_coins"] = false;
        // Start RPC call
        RPCClient client(args.query_rpc_url, args.query_rpc_port, args.query_cert_path, args.query_key_path);
        std::string res = client.Invoke("get_coin_records_by_puzzle_hash", val.toStyledString());
        // Analyze the json from RPC server
        Json::Value res_val;
        std::string errs;
        Json::CharReaderBuilder builder;
        std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
        if (!reader->parse(res.c_str(), res.c_str() + res.size(), &res_val, &errs)) {
            throw std::runtime_error("Invalid json string is received from RPC service");
        }
        if (!res_val.isMember("success") || !res_val["success"].asBool()) {
            throw std::runtime_error("RPC service is not succeed");
        }
        if (!res_val.isMember("coin_records") || !res_val.isArray()) {
            throw std::runtime_error("Cannot find key `coin_records` or its type isn't array");
        }
        Json::Value records = res_val["coin_records"];
        uint64_t amount{0};
        for (auto const& rec : records) {
            if (!rec.isMember("coin") || !rec.isMember("spent")) {
                throw std::runtime_error("Coin record: `coin` cannot be found");
            }
            if (!rec["spent"].asBool()) {
                auto const& coin = rec["coin"];
                amount += coin.asUInt64();
            }
        }
        std::cout << "Balance: " << amount << std::endl;
        return 0;
    }
};

int main(int argc, char const* argv[])
{
    CommandExecutor cmd_exec;
    cmd_exec.RegisterCommand<CommandHandler_Wallet>("wallet");
    cmd_exec.RegisterCommand<CommandHandler_Query>("query");

    auto cmd_names = cmd_exec.GetRegisteredCommands();
    std::stringstream ss_cmd_names;
    ss_cmd_names << "chiatool <command> [arguments...], main command name (available commands: " << cmd_names.front();
    for (auto i = std::cbegin(cmd_names) + 1; i != cend(cmd_names); ++i) {
        ss_cmd_names << ", " << *i;
    }
    ss_cmd_names << ")";

    cxxopts::Options opts("Chia tool", "Chia tool to work with generating account, making signature");
    opts.add_options()
        ("help,h", "show this document")
        ("command", "Main command", cxxopts::value<std::string>())
        ;
    opts.add_options("wallet")
        ("new", "Generate a new mnemonic sentences")
        ("path", "The wallet file path content type is json", cxxopts::value<std::string>()->default_value("./wallet.json"))
        ("overwrite", "Only work with `--new` overwrite the existing wallet file when it already exists, otherwise the argument will be ignored")
        ("num-sentences,n", "The number of sentences for generating new wallet, (valid numbers: 12, 15, 18, 21, 24)", cxxopts::value<int>()->default_value("24"))
        ;
    opts.add_options("query")
        ("address", "Query balance of the address", cxxopts::value<std::string>())
        ("rpc-url", "The RPC url to establish connection", cxxopts::value<std::string>())
        ("rpc-port", "The port number of the RPC service", cxxopts::value<uint16_t>())
        ("cert", "Path to the certificate file", cxxopts::value<std::string>())
        ("key", "Path to the key file", cxxopts::value<std::string>())
        ;
    opts.parse_positional("command");
    cxxopts::ParseResult result = opts.parse(argc, argv);
    std::string command_name;
    if (result.count("command") > 0) {
        command_name = result["command"].as<std::string>();
    }
    if (result.count("help") > 0) {
        std::cout << opts.help({command_name}) << std::endl;
        std::cout << ss_cmd_names.str() << std::endl;
        return 0;
    }

    try {
        cmd_exec.RunWithCommand(command_name, result);
    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
    return 0;
}
