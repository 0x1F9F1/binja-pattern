/*
    Copyright 2018 Brick

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software
    and associated documentation files (the "Software"), to deal in the Software without restriction,
    including without limitation the rights to use, copy, modify, merge, publish, distribute,
    sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or
    substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
    BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "PatternScanner.h"

/*
    Setup:
        i7 8086k @ 5.0 GHZ (6C/12T)
        32 GB DDR4 @ 3000 MHZ

    Pattern:
        Length: 26
        Wildcards: 3
        Longest Run: 11

    +--------------+-------+------------+-------------+
    |     Mode     | GB/s  |   Cycles   | Cycles/Byte |
    +--------------+-------+------------+-------------+
    | -JIT, -Skips | 1.716 | 9763289586 |    2.189550 |
    | +JIT, -Skips | 3.270 | 5224431075 |    1.171650 |
    | -JIT, +Skips | 4.362 | 3931594926 |    0.881715 |
    | +JIT, +Skips | 4.367 | 3934530674 |    0.882373 |
    +--------------+-------+------------+-------------+

    Pattern:
        Length: 11
        Wildcards: 5
        Longest Run: 4

    +--------------+-------+-------------+-------------+
    |     Mode     | GB/s  |   Cycles    | Cycles/Byte |
    +--------------+-------+-------------+-------------+
    | -JIT, -Skips | 1.109 | 15104988203 |     3.38750 |
    | -JIT, +Skips | 1.685 |  9956543280 |     2.23289 |
    | +JIT, -Skips | 3.296 |  5173242826 |     1.16017 |
    | +JIT, +Skips | 3.249 |  5244201802 |     1.17608 |
    +--------------+-------+-------------+-------------+

    42% faster parallel_for_each
    15% faster parallel_partition
*/

#define ENABLE_JIT_COMPILATION

#include <mem/pattern.h>
#include <mem/utils.h>

#if defined(ENABLE_JIT_COMPILATION)
# include <mem/jit_scanner.h>
#endif

constexpr const size_t SCAN_RUNS = 1;
constexpr const size_t MAX_SCAN_RESULTS = 1000;
constexpr const size_t PARTITION_SIZE = 1024 * 1024 * 64;

#include "BackgroundTaskThread.h"
#include "ParallelFunctions.h"

#include <mutex>
#include <atomic>

#include <chrono>

#if defined(_WIN32)
#include <intrin.h>

uint64_t rdtsc()
{
    return __rdtsc();
}
#else
uint64_t rdtsc()
{
    uint32_t lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return (static_cast<uint64_t>(hi) << 32) | lo;
}
#endif

std::string GetInstructionContaningAddress(Ref<BasicBlock> block, uint64_t address)
{
    Ref<BinaryView> view = block->GetFunction()->GetView();
    Ref<Architecture> arch = block->GetArchitecture();
    size_t max_length = arch->GetMaxInstructionLength();

    std::vector<uint8_t> buffer(max_length);

    for (size_t i = block->GetStart(), end = block->GetEnd(); i < end;)
    {
        size_t bytes_read = view->Read(buffer.data(), i, buffer.size());

        InstructionInfo info;

        if (arch->GetInstructionInfo(buffer.data(), i, bytes_read, info))
        {
            if ((address >= i) && (address < (i + info.length)))
            {
                std::vector<InstructionTextToken> tokens;

                if (arch->GetInstructionText(buffer.data(), i, bytes_read, tokens))
                {
                    std::string result;

                    for (const InstructionTextToken& token : tokens)
                    {
                        result += token.text;
                    }

                    return result;
                }
                else
                {
                    break;
                }
            }

            i += info.length;
        }
        else
        {
            break;
        }
    }

    return "";
}

void ScanForArrayOfBytesInternal(Ref<BackgroundTask> task, Ref<BinaryView> view, const mem::pattern& pattern, const std::string& pattern_string)
{
    using stopwatch = std::chrono::steady_clock;

    if (!pattern)
    {
        BinjaLog(ErrorLog, "Pattern \"{}\" is empty or malformed", pattern_string);

        return;
    }

#if defined(ENABLE_JIT_COMPILATION)
    mem::jit_runtime runtime;
    mem::jit_scanner scanner(&runtime, pattern);
#else
    mem::default_scanner scanner(pattern);
#endif

    std::vector<uint64_t> results;

    size_t total_size {0};
    int64_t elapsed_ms {0};
    uint64_t elapsed_cycles {0};

    const auto total_start_time = stopwatch::now();

    brick::view_data view_data (view);

    for (size_t i = 0; i < SCAN_RUNS; ++i)
    {
        results.clear();

        if (task->IsCancelled())
        {
            break;
        }

        const auto start_time = stopwatch::now();
        const auto start_clocks = rdtsc();

        std::vector<uint64_t> sub_results = view_data.scan_all(scanner);

        const auto end_clocks = rdtsc();
        const auto end_time = stopwatch::now();

        for (const auto& seg : view_data.segments)
        {
            total_size += seg.length;
        }

        elapsed_ms += std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        elapsed_cycles += end_clocks - start_clocks;

        if (task->IsCancelled())
        {
            break;
        }

        if (!sub_results.empty())
        {
            if (results.size() <= MAX_SCAN_RESULTS)
            {
                results.reserve(results.size() + sub_results.size());
                results.insert(results.end(), sub_results.begin(), sub_results.end());
            }
            else
            {
                break;
            }
        }
    }

    const auto total_end_time = stopwatch::now();

    int64_t total_elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(total_end_time - total_start_time).count();

    if (task->IsCancelled())
    {
        return;
    }

    std::string report;

    if (results.size() >= MAX_SCAN_RESULTS)
    {
        report += fmt::format("Warning: Too many results, truncated to {}.\n\n", MAX_SCAN_RESULTS);

        results.resize(MAX_SCAN_RESULTS);
    }

    std::sort(results.begin(), results.end());

    report += fmt::format("Found {} results for \"{}\" in {} ms (actual {} ms):\n", results.size(), pattern_string, elapsed_ms, total_elapsed_ms);
    report += fmt::format("0x{:X} bytes = {:.3f} GB/s = {} cycles = {} cycles per byte\n", total_size, (total_size / 1073741824.0) / (elapsed_ms / 1000.0), elapsed_cycles, double(elapsed_cycles) / double(total_size));

    const size_t plength = pattern.size();

    if (plength > 0)
    {
        const mem::byte* pbytes = pattern.bytes();
        const mem::byte* pmasks = pattern.masks();

        report += fmt::format("Pattern: Length {}, \"{}\", \"{}\"\n",
            plength,

            mem::as_hex({ pbytes, plength }, true, true),
            mem::as_hex({ pmasks, plength }, true, true)
        );
    }

    report += "\n";

    for (uint64_t result : results)
    {
        report += fmt::format("0x{:X}", result);

        std::vector<Ref<BasicBlock>> blocks = view->GetBasicBlocksForAddress(result);

        if (!blocks.empty())
        {
            report += " (";

            for (size_t i = 0; i < blocks.size(); ++i)
            {
                Ref<BasicBlock> block = blocks[i];

                if (i)
                {
                    report += ", ";
                }

                std::string instr_text = GetInstructionContaningAddress(block, result);

                report += fmt::format("{}: \"{}\"", block->GetFunction()->GetSymbol()->GetFullName(), instr_text);
            }

            report += ")";
        }

        report += "\n";
    }

    BinaryNinja::ShowPlainTextReport("Scan Results", report);
}

void ScanForArrayOfBytesTask(Ref<BackgroundTask> task, Ref<BinaryView> view, std::string pattern_string, std::string mask_string)
{
    if (mask_string.empty())
    {
        mem::pattern pattern(pattern_string.c_str());

        ScanForArrayOfBytesInternal(task, view, pattern, pattern_string);
    }
    else
    {
        std::string pattern_bytes = mem::unescape(pattern_string.c_str(), pattern_string.size());

        if (pattern_bytes.size() != mask_string.size())
        {
            BinjaLog(ErrorLog, "Pattern/Mask Length Mismatch ({} != {} for {}, {})", pattern_bytes.size(), mask_string.size(), pattern_string, mask_string);

            return;
        }

        mem::pattern pattern(pattern_bytes.c_str(), mask_string.c_str());

        ScanForArrayOfBytesInternal(task, view, pattern, pattern_string + ", " + mask_string);   
    }
}

void ScanForArrayOfBytes(Ref<BinaryView> view)
{
    std::vector<FormInputField> fields;

    fields.push_back(FormInputField::TextLine("Pattern"));
    fields.push_back(FormInputField::TextLine("Mask (Optional)"));

    if (BinaryNinja::GetFormInput(fields, "Input Pattern"))
    {
        std::string pattern_string = fields[0].stringResult, mask_string = fields[1].stringResult;

        Ref<BackgroundTaskThread> task = new BackgroundTaskThread(fmt::format("Scanning for pattern: \"{}\"", pattern_string));

        task->Run(ScanForArrayOfBytesTask, view, pattern_string, mask_string);
    }
}
