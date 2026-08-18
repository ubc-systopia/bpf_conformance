// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// bpf_conformance verifier plugin for Prevail.

#include <cerrno>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace
{
struct options_t
{
    std::string prevail;
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
    std::cerr << "usage: " << program << " [hex memory] --prevail PATH [--section NAME] --elf" << std::endl;
}

bool
parse_options(int argc, char** argv, options_t& options)
{
    bool saw_memory = false;
    for (int index = 1; index < argc; index++) {
        std::string_view argument(argv[index]);
        if (argument == "--prevail" || argument == "--section") {
            if (++index >= argc) {
                std::cerr << "missing value for " << argument << std::endl;
                return false;
            }
            if (argument == "--prevail") {
                options.prevail = argv[index];
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
    if (options.prevail.empty()) {
        std::cerr << "--prevail is required" << std::endl;
        return false;
    }
    if (!options.elf) {
        std::cerr << "Prevail verifier adapter requires bpf_conformance --elf true" << std::endl;
        return false;
    }
    return true;
}

int
hex_digit(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

bool
decode_hex(const std::string& encoded, std::vector<unsigned char>& decoded)
{
    int high_nibble = -1;
    for (char value : encoded) {
        if (std::isspace(static_cast<unsigned char>(value))) {
            continue;
        }
        int digit = hex_digit(value);
        if (digit < 0) {
            std::cerr << "invalid character in hex-encoded ELF input" << std::endl;
            return false;
        }
        if (high_nibble < 0) {
            high_nibble = digit;
        } else {
            decoded.push_back(static_cast<unsigned char>((high_nibble << 4) | digit));
            high_nibble = -1;
        }
    }
    if (high_nibble >= 0) {
        std::cerr << "hex-encoded ELF input has an odd number of digits" << std::endl;
        return false;
    }
    if (decoded.empty()) {
        std::cerr << "empty ELF input" << std::endl;
        return false;
    }
    return true;
}

class temporary_file_t
{
  public:
    ~temporary_file_t()
    {
        if (!_path.empty()) {
            unlink(_path.c_str());
        }
    }

    bool write(const std::vector<unsigned char>& contents)
    {
        auto pattern = (std::filesystem::temp_directory_path() / "prevail-conformance-XXXXXX.o").string();
        std::vector<char> path(pattern.begin(), pattern.end());
        path.push_back('\0');
        int fd = mkstemps(path.data(), 2);
        if (fd < 0) {
            std::cerr << "failed to create temporary ELF: " << std::strerror(errno) << std::endl;
            return false;
        }
        _path = path.data();

        size_t written = 0;
        while (written < contents.size()) {
            ssize_t result = ::write(fd, contents.data() + written, contents.size() - written);
            if (result < 0 && errno == EINTR) {
                continue;
            }
            if (result <= 0) {
                std::cerr << "failed to write temporary ELF: " << std::strerror(errno) << std::endl;
                close(fd);
                return false;
            }
            written += static_cast<size_t>(result);
        }
        if (close(fd) < 0) {
            std::cerr << "failed to close temporary ELF: " << std::strerror(errno) << std::endl;
            return false;
        }
        return true;
    }

    const std::string& path() const
    {
        return _path;
    }

  private:
    std::string _path;
};

bool
run_prevail(const options_t& options, const std::string& elf_path, process_result_t& result)
{
    int output_pipe[2];
    if (pipe(output_pipe) < 0) {
        std::cerr << "failed to create output pipe: " << std::strerror(errno) << std::endl;
        return false;
    }

    pid_t child = fork();
    if (child < 0) {
        std::cerr << "failed to fork Prevail: " << std::strerror(errno) << std::endl;
        close(output_pipe[0]);
        close(output_pipe[1]);
        return false;
    }
    if (child == 0) {
        close(output_pipe[0]);
        dup2(output_pipe[1], STDOUT_FILENO);
        dup2(output_pipe[1], STDERR_FILENO);
        close(output_pipe[1]);
        execl(
            options.prevail.c_str(),
            options.prevail.c_str(),
            elf_path.c_str(),
            "--section",
            options.section.c_str(),
            "-f",
            static_cast<char*>(nullptr));
        std::cerr << "failed to invoke Prevail: " << std::strerror(errno) << std::endl;
        _exit(127);
    }

    close(output_pipe[1]);
    char buffer[4096];
    while (true) {
        ssize_t size = read(output_pipe[0], buffer, sizeof(buffer));
        if (size < 0 && errno == EINTR) {
            continue;
        }
        if (size <= 0) {
            break;
        }
        result.output.append(buffer, static_cast<size_t>(size));
    }
    close(output_pipe[0]);

    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            std::cerr << "failed to wait for Prevail: " << std::strerror(errno) << std::endl;
            return false;
        }
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

    std::string encoded_elf{
        std::istreambuf_iterator<char>(std::cin),
        std::istreambuf_iterator<char>()};
    std::vector<unsigned char> elf;
    if (!decode_hex(encoded_elf, elf)) {
        return 2;
    }

    temporary_file_t temporary_elf;
    if (!temporary_elf.write(elf)) {
        return 2;
    }

    process_result_t result{};
    if (!run_prevail(options, temporary_elf.path(), result)) {
        return 2;
    }

    if (result.exit_code == 0 && result.output.find("PASS:") != std::string::npos) {
        return 0;
    }
    if (result.exit_code == 1 && !result.output.empty()) {
        std::cout << result.output;
        if (result.output.back() != '\n') {
            std::cout << '\n';
        }
        return 1;
    }

    auto detail = compact_whitespace(result.output);
    if (result.exit_code != 0) {
        std::cerr << "Prevail exited with code " << result.exit_code << ": " << detail << std::endl;
    } else {
        std::cerr << "could not determine Prevail verifier verdict: " << detail << std::endl;
    }
    return 2;
}
