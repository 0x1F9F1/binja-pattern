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
#define ENABLE_MULTI_THREADING
#define ENABLE_PATTERN_SKIPS

constexpr const size_t SCAN_RUNS = 50;
constexpr const size_t MAX_SCAN_RESULTS = 1000;

#include <mem/pattern.h>
#include <mem/utils.h>

#if defined(ENABLE_JIT_COMPILATION)
#include <mem/jit_pattern.h>
#endif

#include "BackgroundTaskThread.h"

#include <thread>
#include <mutex>

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

template <typename ForwardIt, typename UnaryFunction>
void parallel_for_each(ForwardIt first, ForwardIt last, const UnaryFunction& func)
{
#if defined(ENABLE_MULTI_THREADING)
    uint32_t thread_count = std::thread::hardware_concurrency();

    if (thread_count == 0)
    {
        thread_count = 4;
    }

    std::mutex mutex;

    const auto thread_loop = [&]
    {
        while (true)
        {
            std::unique_lock<std::mutex> guard(mutex);

            if (first != last)
            {
                auto value = *first++;

                guard.unlock();

                func(std::move(value));
            }
            else
            {
                break;
            }
        }
    };

    std::vector<std::thread> threads;

    for (uint32_t i = 0; i < thread_count; ++i)
    {
        threads.emplace_back(thread_loop);
    }

    for (auto& thread : threads)
    {
        thread.join();
    }
#else
    std::for_each(first, last, func);
#endif
}

using stopwatch = std::chrono::steady_clock;

void ScanForArrayOfBytesTask(Ref<BackgroundTask> task, Ref<BinaryView> view, std::string pattern_string)
{
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

    size_t total_size = 0;

    std::vector<uint64_t> results;

    std::vector<Ref<Segment>> segments = view->GetSegments();

    for (size_t i = 0; i < SCAN_RUNS; ++i)
    {
        if (!segments.empty())
        {
            std::mutex mutex;

            parallel_for_each(segments.begin(), segments.end(), [&, i] (const Ref<Segment>& segment)
            {
                if (task->IsCancelled())
                {
                    return;
                }

                DataBuffer data = view->ReadBuffer(segment->GetStart(), segment->GetLength());

                std::vector<mem::pointer> scan_results =
    #if defined(ENABLE_JIT_COMPILATION)
                    jit_pattern
    #else
                    pattern
    #endif
                    .scan_all({ data.GetData(), data.GetLength() });

                if (task->IsCancelled())
                {
                    return;
                }

                std::unique_lock<std::mutex> lock(mutex);

                total_size += data.GetLength();

                if (!i)
                {
                    for (mem::pointer result : scan_results)
                    {
                        results.push_back(result.shift(data.GetData(), segment->GetStart()).as<uint64_t>());
                    }
                }

                task->SetProgressText(fmt::format("Scanning for pattern: \"{}\", found {} results", pattern_string, results.size()));
            });
        }
        else
        {
            DataBuffer data = view->ReadBuffer(view->GetStart(), view->GetLength());

            std::vector<mem::pointer> scan_results =
    #if defined(ENABLE_JIT_COMPILATION)
                    jit_pattern
    #else
                    pattern
    #endif
                    .scan_all({ data.GetData(), data.GetLength() });

            if (task->IsCancelled())
            {
                return;
            }

            total_size += data.GetLength();

            if (!i)
            {
                for (mem::pointer result : scan_results)
                {
                    results.push_back(result.shift(data.GetData(), view->GetStart()).as<uint64_t>());
                }
            }
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

    report += fmt::format("Found {} results for \"{}\" in {} ms:\n", results.size(), pattern_string, elapsed_ms);
    report += fmt::format("Scanned 0x{:X} bytes = {:.3f} GB/s\n", total_size, (total_size / 1'073'741'824.0) / (elapsed_ms / 1000.0));
    report += fmt::format("Cycles Used: {} = {} cycles per byte\n", elapsed_clocks, double(elapsed_clocks) / double(total_size));

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

    if (results.size() > MAX_SCAN_RESULTS)
    {
        report += fmt::format("Too many results, only showing first {}.\n", MAX_SCAN_RESULTS);

        results.resize(MAX_SCAN_RESULTS);
    }

    report += "\n";

    for (uint64_t result : results)
    {
        report += fmt::format("0x{:X}", result);

        auto blocks = view->GetBasicBlocksForAddress(result);

        if (!blocks.empty())
        {
            report += " (in ";

            for (size_t i = 0; i < blocks.size(); ++i)
            {
                if (i)
                {
                    report += ", ";
                }

                report += blocks[i]->GetFunction()->GetSymbol()->GetFullName();
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
