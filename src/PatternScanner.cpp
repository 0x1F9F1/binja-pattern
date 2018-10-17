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

        +-------------------+-------+-------------+-------------+
        |       Mode        | GB/s  |   Cycles    | Cycles/Byte |
        +-------------------+-------+-------------+-------------+
        | -MT, -JIT, -Skips | 0.573 | 29056477391 |     6.51460 |
        | -MT, +JIT, -Skips | 0.653 | 25490299715 |     5.71504 |
        | -MT, -JIT, +Skips | 0.924 | 18012534184 |     4.03849 |
        | -MT, +JIT, +Skips | 0.928 | 17933345629 |     4.02074 |
        | +MT, +JIT, -Skips | 1.155 | 14414069353 |     3.23170 |
        | +MT, -JIT, -Skips | 1.260 | 13219412111 |     2.96385 |
        | +MT, -JIT, +Skips | 1.579 | 10541668052 |     2.36349 |
        | +MT, +JIT, +Skips | 1.584 | 10513712196 |     2.35722 |
        +-------------------+-------+-------------+-------------+
*/

#define ENABLE_JIT_COMPILATION
#define ENABLE_PATTERN_SKIPS
// #define DISABLE_MULTI_THREADING

constexpr const size_t SCAN_RUNS = 1;
constexpr const size_t MAX_SCAN_RESULTS = 1000;
constexpr const size_t PARTITION_SIZE = 1024 * 1024 * 4;

#include <mem/pattern.h>
#include <mem/utils.h>

#if defined(ENABLE_JIT_COMPILATION)
#include <mem/jit_pattern.h>
#endif

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

template <typename Pattern>
bool ScanRegion(
    Ref<BackgroundTask> task,
    std::vector<uint64_t>& results,
    std::mutex& mutex,
    const Pattern& pattern,
    mem::region range,
    uint64_t start,
    std::atomic_size_t& total_size)
{
    if (task->IsCancelled())
    {
        return false;
    }

    std::vector<mem::pointer> sub_results = pattern.scan_all(range);

    total_size += range.size;

    if (task->IsCancelled())
    {
        return false;
    }

    if (!sub_results.empty())
    {
        std::lock_guard<std::mutex> lock(mutex);

        if (results.size() <= MAX_SCAN_RESULTS)
        {
            results.reserve(results.size() + sub_results.size());

            for (mem::pointer result : sub_results)
            {
                results.push_back(result.shift(range.start, start).as<uint64_t>());
            }
        }
        else
        {
            return false;
        }
    }

    return true;
}

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

void ScanForArrayOfBytesTask(Ref<BackgroundTask> task, Ref<BinaryView> view, std::string pattern_string)
{
    using stopwatch = std::chrono::steady_clock;

    const auto start_time = stopwatch::now();
    const auto start_clocks = rdtsc();

    mem::pattern pattern(pattern_string.c_str()
#if !defined(ENABLE_PATTERN_SKIPS)
        , mem::pattern_settings {0,0}
#endif
    );

#if defined(ENABLE_JIT_COMPILATION)
    mem::jit_runtime runtime;
    mem::jit_pattern jit_pattern(&runtime, pattern);
#endif

    std::vector<uint64_t> results;
    std::mutex mutex;
    std::atomic_size_t total_size = 0;

    std::vector<Ref<Segment>> segments = view->GetSegments();

    for (size_t i = 0; i < SCAN_RUNS; ++i)
    {
        results.clear();

        if (!segments.empty())
        {
            parallel_for_each(segments.begin(), segments.end(), [&] (const Ref<Segment>& segment) -> bool
            {
                if (task->IsCancelled())
                {
                    return false;
                }

                DataBuffer data = view->ReadBuffer(segment->GetStart(), segment->GetLength());

                bool result = ScanRegion(
                    task, results, mutex,
#if defined(ENABLE_JIT_COMPILATION)
                    jit_pattern,
#else
                    pattern,
#endif
                    { data.GetData(), data.GetLength() },
                    segment->GetStart(),
                    total_size
                );

                task->SetProgressText(fmt::format("Scanning for pattern: \"{}\", found {} results", pattern_string, results.size()));

                return true;
            });
        }
        else
        {
            DataBuffer data = view->ReadBuffer(view->GetStart(), view->GetLength());

            parallel_partition(data.GetLength(), PARTITION_SIZE, pattern.size(), [&] (size_t offset, size_t length)
            {
                if (task->IsCancelled())
                {
                    return false;
                }

                bool result = ScanRegion(
                    task, results, mutex,
#if defined(ENABLE_JIT_COMPILATION)
                    jit_pattern,
#else
                    pattern,
#endif
                    { data.GetDataAt(offset), length },
                    view->GetStart(),
                    total_size
                );

                task->SetProgressText(fmt::format("Scanning for pattern: \"{}\", found {} results", pattern_string, results.size()));

                return true;
            });
        }
    }

    const auto end_clocks = rdtsc();
    const auto end_time = stopwatch::now();

    if (task->IsCancelled())
    {
        return;
    }

    std::string report;

    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    const auto elapsed_clocks = end_clocks - start_clocks;

    if (results.size() >= MAX_SCAN_RESULTS)
    {
        report += fmt::format("Warning: Too many results, truncated to {}.\n\n", MAX_SCAN_RESULTS);

        results.resize(MAX_SCAN_RESULTS);
    }

    std::sort(results.begin(), results.end());

    report += fmt::format("Found {} results for \"{}\" in {} ms:\n", results.size(), pattern_string, elapsed_ms);
    report += fmt::format("Scanned 0x{:X} bytes = {:.3f} GB/s\n", total_size, (total_size / 1'073'741'824.0) / (elapsed_ms / 1000.0));
    report += fmt::format("Cycles: {} = {} cycles per byte\n", elapsed_clocks, double(elapsed_clocks) / double(total_size));

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

void ScanForArrayOfBytes(Ref<BinaryView> view)
{
    std::string pattern_string;

    if (BinaryNinja::GetTextLineInput(pattern_string, "Pattern", "Input Pattern"))
    {
        Ref<BackgroundTaskThread> task = new BackgroundTaskThread(fmt::format("Scanning for pattern: \"{}\"", pattern_string));

        task->Run(&ScanForArrayOfBytesTask, view, pattern_string);
    }
}
