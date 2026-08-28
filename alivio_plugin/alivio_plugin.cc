// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// bpf_conformance verifier plugin for Alivio.

#include <array>
#include <cerrno>
#include <charconv>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace
{
struct options_t
{
    std::string alivio;
    std::string section = "xdp";
    bool elf = false;
};

struct process_result_t
{
    int exit_code;
    std::string output;
};

void
print_usage(const char* program)
{
    std::cerr << "usage: " << program << " [hex memory] --alivio PATH [--section NAME] --elf" << std::endl;
}

bool
parse_options(int argc, char** argv, options_t& options)
{
    bool saw_memory = false;
    for (int index = 1; index < argc; index++) {
        std::string_view argument(argv[index]);
        if (argument == "--alivio" || argument == "--section") {
            if (++index >= argc) {
                std::cerr << "missing value for " << argument << std::endl;
                return false;
            }
            if (argument == "--alivio") {
                options.alivio = argv[index];
            } else {
                options.section = argv[index];
            }
        } else if (argument == "--elf") {
            options.elf = true;
        } else if (argument == "--help") {
            return false;
        } else if (argument.starts_with("--")) {
            std::cerr << "unexpected option: " << argument << std::endl;
            return false;
        } else if (!saw_memory) {
            // The verifier does not execute the program, but the optional
            // memory argument remains part of the plugin protocol.
            saw_memory = true;
        } else {
            std::cerr << "unexpected argument: " << argument << std::endl;
            return false;
        }
    }
    if (options.alivio.empty()) {
        std::cerr << "--alivio is required" << std::endl;
        return false;
    }
    if (!options.elf) {
        std::cerr << "Alivio verifier adapter requires bpf_conformance --elf true" << std::endl;
        return false;
    }
    return true;
}

std::string
system_error_message(int error)
{
    return std::error_code(error, std::generic_category()).message();
}

std::optional<std::vector<unsigned char>>
decode_hex(std::istream& input)
{
    std::vector<unsigned char> result;
    std::string token;

    while (input >> token) {
        if (token.size() != 2) {
            std::cerr << "hexadecimal bytes must contain exactly two digits" << std::endl;
            return std::nullopt;
        }

        unsigned int byte = 0;
        const auto* begin = token.data();
        const auto* end = begin + token.size();
        const auto [position, error] = std::from_chars(begin, end, byte, 16);
        if (error != std::errc{} || position != end || byte > 0xff) {
            std::cerr << "invalid hexadecimal byte: " << token << std::endl;
            return std::nullopt;
        }

        result.push_back(static_cast<unsigned char>(byte));
    }

    if (input.bad()) {
        std::cerr << "failed to read hex-encoded ELF input" << std::endl;
        return std::nullopt;
    }

    if (result.empty()) {
        std::cerr << "empty ELF input" << std::endl;
        return std::nullopt;
    }

    return result;
}

class temporary_file_t
{
  public:
    ~temporary_file_t()
    {
        if (!_path.empty()) {
            std::error_code error;
            std::filesystem::remove(_path, error);
        }
    }

    temporary_file_t() = default;
    temporary_file_t(const temporary_file_t&) = delete;
    temporary_file_t& operator=(const temporary_file_t&) = delete;

    bool write(const std::vector<unsigned char>& contents)
    {
        std::string path = (std::filesystem::temp_directory_path() / "alivio-conformance-XXXXXX.o").string();
        int fd = mkstemps(path.data(), 2);
        if (fd < 0) {
            std::cerr << "failed to create temporary ELF: " << system_error_message(errno) << std::endl;
            return false;
        }
        _path = path;

        if (close(fd) < 0) {
            std::cerr << "failed to close temporary ELF: " << system_error_message(errno) << std::endl;
            return false;
        }

        std::ofstream output(_path, std::ios::binary | std::ios::trunc);
        output.write(reinterpret_cast<const char*>(contents.data()), static_cast<std::streamsize>(contents.size()));
        output.close();
        if (!output) {
            std::cerr << "failed to write temporary ELF" << std::endl;
            return false;
        }

        return true;
    }

    const std::filesystem::path& path() const
    {
        return _path;
    }

  private:
    std::filesystem::path _path;
};

bool
run_alivio(const options_t& options, const std::filesystem::path& elf_path, process_result_t& result)
{
    std::array<int, 2> output_pipe;
    if (pipe(output_pipe.data()) < 0) {
        std::cerr << "failed to create output pipe: " << system_error_message(errno) << std::endl;
        return false;
    }

    pid_t child = fork();
    if (child < 0) {
        std::cerr << "failed to fork Alivio: " << system_error_message(errno) << std::endl;
        close(output_pipe[0]);
        close(output_pipe[1]);
        return false;
    }
    if (child == 0) {
        close(output_pipe[0]);
        if (dup2(output_pipe[1], STDOUT_FILENO) < 0 || dup2(output_pipe[1], STDERR_FILENO) < 0) {
            std::cerr << "failed to redirect Alivio output: " << system_error_message(errno) << std::endl;
            _exit(127);
        }
        close(output_pipe[1]);
        execl(
            options.alivio.c_str(),
            options.alivio.c_str(),
            "--quiet",
            "verify",
            elf_path.c_str(),
            "--section",
            options.section.c_str(),
            static_cast<char*>(nullptr));
        std::cerr << "failed to invoke Alivio: " << system_error_message(errno) << std::endl;
        _exit(127);
    }

    close(output_pipe[1]);
    std::array<char, 4096> buffer;
    bool read_succeeded = true;
    while (true) {
        ssize_t size = read(output_pipe[0], buffer.data(), buffer.size());
        if (size < 0 && errno == EINTR) {
            continue;
        }
        if (size < 0) {
            std::cerr << "failed to read Alivio output: " << system_error_message(errno) << std::endl;
            read_succeeded = false;
            break;
        }
        if (size == 0) {
            break;
        }
        result.output.append(buffer.data(), static_cast<size_t>(size));
    }
    close(output_pipe[0]);

    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            std::cerr << "failed to wait for Alivio: " << system_error_message(errno) << std::endl;
            return false;
        }
    }
    if (!read_succeeded) {
        return false;
    }
    result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
    return true;
}

std::string
compact_whitespace(const std::string& value)
{
    std::ostringstream compact;
    bool pending_space = false;
    bool has_output = false;
    for (char character : value) {
        if (std::isspace(static_cast<unsigned char>(character))) {
            pending_space = has_output;
        } else {
            if (pending_space) {
                compact << ' ';
            }
            compact << character;
            has_output = true;
            pending_space = false;
        }
    }
    return compact.str();
}
} // namespace

int
main(int argc, char** argv)
{
    options_t options;
    if (!parse_options(argc, argv, options)) {
        print_usage(argv[0]);
        return 2;
    }

    auto elf = decode_hex(std::cin);
    if (!elf) {
        return 2;
    }

    temporary_file_t temporary_elf;
    if (!temporary_elf.write(*elf)) {
        return 2;
    }

    process_result_t result{};
    if (!run_alivio(options, temporary_elf.path(), result)) {
        return 2;
    }

    std::istringstream output(result.output);
    std::string line;
    constexpr std::string_view fail_prefix = "=== FAIL: ";
    constexpr std::string_view fail_suffix = " ===";
    while (std::getline(output, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line == "=== PASS ===") {
            return 0;
        }
        if (line.starts_with(fail_prefix) && line.ends_with(fail_suffix)) {
            std::cout << line.substr(
                fail_prefix.size(),
                line.size() - fail_prefix.size() - fail_suffix.size())
                      << std::endl;
            return 1;
        }
    }

    auto detail = compact_whitespace(result.output);
    if (result.exit_code != 0) {
        std::cerr << "Alivio exited with code " << result.exit_code << ": " << detail << std::endl;
    } else {
        std::cerr << "could not determine Alivio verifier verdict: " << detail << std::endl;
    }
    return 2;
}
