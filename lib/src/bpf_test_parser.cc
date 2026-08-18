// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <bpf_conformance_core/bpf_test_parser.h>
#include <bpf_conformance_core/bpf_assembler.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iostream>

bpf_test_file_t
parse_test_file_with_verifier(const std::filesystem::path& data_file)
{
    enum class _state
    {
        state_ignore,
        state_assembly,
        state_raw,
        state_result,
        state_memory,
        state_error,
        state_verifier,
        state_verifier_reason,
    } state = _state::state_ignore;

    std::stringstream data_out;
    std::ifstream data_in(data_file);

    std::string result_string;
    std::string mem;
    std::string line;
    std::string expected_error;
    std::string verifier_verdict;
    std::string verifier_reason;
    std::string raw;

    while (std::getline(data_in, line)) {
        // Strip trailing carriage return
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.find("#") != std::string::npos) {
            line = line.substr(0, line.find("#"));
        }
        if (line.find("--") != std::string::npos) {
            if (line.find("asm") != std::string::npos) {
                state = _state::state_assembly;
                continue;
            } else if (line.find("result") != std::string::npos) {
                state = _state::state_result;
                continue;
            } else if (line.find("mem") != std::string::npos) {
                state = _state::state_memory;
                continue;
            } else if (line.find("raw") != std::string::npos) {
                state = _state::state_raw;
                continue;
            } else if (line.find("result") != std::string::npos) {
                state = _state::state_result;
                continue;
            } else if (line.find("no register offset") != std::string::npos) {
                state = _state::state_ignore;
                continue;
            } else if (line.find(" c") != std::string::npos) {
                state = _state::state_ignore;
                continue;
            } else if (line.find("error") != std::string::npos) {
                state = _state::state_error;
                continue;
            } else if (line.find("verifier reason") != std::string::npos) {
                state = _state::state_verifier_reason;
                continue;
            } else if (line.find("verifier") != std::string::npos) {
                state = _state::state_verifier;
                continue;
            } else {
                std::cout << "Skipping: Unknown directive " << line << " in file " << data_file << std::endl;
                return {};
                continue;
            }
        }
        if (line.empty()) {
            continue;
        }

        switch (state) {
        case _state::state_assembly:
            data_out << line << std::endl;
            break;
        case _state::state_result:
            result_string = line;
            break;
        case _state::state_memory:
            mem += std::string(" ") + line;
            break;
        case _state::state_error:
            expected_error = line;
            break;
        case _state::state_raw:
            raw += std::string(" ") + line;
            break;
        case _state::state_verifier:
            verifier_verdict = line;
            break;
        case _state::state_verifier_reason:
            if (!verifier_reason.empty()) {
                verifier_reason += "\n";
            }
            verifier_reason += line;
            break;
        default:
            continue;
        }
    }

    std::optional<bpf_verifier_expectation_t> verifier_expectation;
    if (!verifier_verdict.empty()) {
        if (verifier_verdict == "accept") {
            verifier_expectation = bpf_verifier_expectation_t{bpf_verifier_verdict_t::accept, verifier_reason};
        } else if (verifier_verdict == "reject") {
            verifier_expectation = bpf_verifier_expectation_t{bpf_verifier_verdict_t::reject, verifier_reason};
        } else {
            throw std::runtime_error(
                "Invalid verifier verdict '" + verifier_verdict + "' in test file " + data_file.string());
        }
    }

    const bool has_runtime_expectation = !expected_error.empty() || !result_string.empty();
    if (!has_runtime_expectation && !verifier_expectation.has_value()) {
        std::cout << "Skipping: No runtime or verifier expectation in test file " << data_file << std::endl;
        return {};
    }

    uint64_t result_value;
    if (result_string.empty()) {
        result_value = 0;
    } else if (result_string.find("0x") != std::string::npos) {
        result_value = std::stoull(result_string, nullptr, 16);
    } else {
        result_value = std::stoull(result_string);
    }

    std::vector<ebpf_inst> instructions;
    if (!raw.empty()) {
        std::stringstream raw_stream(raw);

        std::string byte;
        while (raw_stream >> line) {
            uint64_t value;
            ebpf_inst inst;
            if (line.starts_with("0x")) {
                value = std::stoull(line, nullptr, 16);
            } else {
                value = std::stoull(line);
            }
            *reinterpret_cast<uint64_t*>(&inst) = value;
            instructions.push_back(inst);
        }
    } else {
        data_out.seekg(0);
        instructions = bpf_assembler(data_out);
    }

    if (instructions.empty()) {
        std::cout << "Skipping: No instructions in test file " << data_file << std::endl;
        return {};
    }

    std::vector<uint8_t> input_buffer;

    if (!mem.empty()) {
        std::stringstream ss(mem);
        uint32_t value;
        while (ss >> std::hex >> value) {
            input_buffer.push_back(static_cast<uint8_t>(value));
        }
    }

    return {
        input_buffer,
        result_value,
        expected_error,
        instructions,
        has_runtime_expectation,
        verifier_expectation,
    };
}

std::tuple<std::vector<uint8_t>, uint64_t, std::string, std::vector<ebpf_inst>>
parse_test_file(const std::filesystem::path& data_file)
{
    auto test = parse_test_file_with_verifier(data_file);
    if (!test.has_runtime_expectation) {
        return {};
    }
    return {test.memory, test.expected_return_value, test.expected_error, test.instructions};
}
