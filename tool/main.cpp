#include <iostream>

#include <string>
#include <string_view>

#include <vector>
#include <map>

#include <cxxopts.hpp>

struct Args {
    bool wallet_new;
    std::string wallet_path;
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

class CommandHandler_Wallet : public AbstractCommandHandler {
public:
    Args ParseArgs(cxxopts::ParseResult const& result) const override
    {
        Args args;
        args.wallet_new = result.count("new") > 0;
        if (result.count("path") == 0) {
            throw std::runtime_error("arg `path` is required");
        }
        args.wallet_path = result["path"].as<std::string>();
        return args;
    }

    virtual int Run(Args const& args) const override
    {
        return 0;
    }
};

int main(int argc, char const* argv[])
{
    CommandExecutor cmd_exec;
    cmd_exec.RegisterCommand<CommandHandler_Wallet>("wallet");

    auto cmd_names = cmd_exec.GetRegisteredCommands();
    std::stringstream ss_cmd_names;
    ss_cmd_names << "chiatool <command> [arguments...], main command name (available commands: " << cmd_names.front() << ")";
    for (auto i = std::cbegin(cmd_names) + 1; i != cend(cmd_names); ++i) {
        ss_cmd_names << ", " << *i;
    }

    cxxopts::Options opts("Chia tool", "Chia tool to work with generating account, making signature");
    opts.add_options()
        ("help,h", "show this document")
        ("command", "Main command", cxxopts::value<std::string>())
        ;
    opts.add_options("wallet")
        ("new", "Generate a new mnemonic sentences")
        ("path", "The wallet file path content type is json", cxxopts::value<std::string>()->default_value("./wallet.json"))
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
