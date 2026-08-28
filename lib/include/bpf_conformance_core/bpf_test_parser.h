// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <tuple>
#include <vector>
#include "ebpf.h"

enum class bpf_verifier_verdict_t
{
    accept,
    reject,
};

struct bpf_verifier_expectation_t
{
    bpf_verifier_verdict_t verdict;
    std::string reason;
};

struct bpf_test_file_t
{
    std::vector<uint8_t> memory;
    uint64_t expected_return_value = 0;
    std::string expected_error;
    std::vector<ebpf_inst> instructions;
    bool has_runtime_expectation = false;
    std::optional<bpf_verifier_expectation_t> verifier_expectation;
};

/**
 * @brief Parse a test file, including optional verifier expectations.
 *
 * @param[in] data_file Path to the test file.
 */
bpf_test_file_t
parse_test_file_with_verifier(const std::filesystem::path& data_file);

/**
 * Backwards-compatible runtime-only parser API.
 * @brief Parse a test file and return the memory, the expected return value, the expected error string, and the BPF
 * byte code.
 *
 * @param[in] data_file Path to the test file.
 * @return Tuple of input memory, expected return value, the expected error string, and the BPF byte code sequence.
 */
std::tuple<std::vector<uint8_t>, uint64_t, std::string, std::vector<ebpf_inst>>
parse_test_file(const std::filesystem::path& data_file);
