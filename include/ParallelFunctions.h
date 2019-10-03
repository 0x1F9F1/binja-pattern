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

#pragma once

#include <cstdint>

#include <atomic>
#include <mutex>
#include <thread>
#include <vector>

template <typename UnaryFunction, typename... Args>
inline void parallel_invoke_n(size_t thread_count, const UnaryFunction& func, const Args&... args)
{
    if (thread_count == 0)
    {
        return;
    }

    if (thread_count == 1)
    {
        func(0, args...);

        return;
    }

    std::vector<std::thread> threads;

    threads.reserve(thread_count);

    for (uint32_t i = 0; i < thread_count; ++i)
    {
        threads.emplace_back(func, i, args...);
    }

    for (std::thread& thread : threads)
    {
        thread.join();
    }
}

inline size_t parallel_get_thread_count()
{
    size_t result = std::thread::hardware_concurrency();

    if (!result)
    {
        result = 1;
    }

    return result;
}

template <typename ForwardIt, typename UnaryPredicate>
inline void parallel_for_each(ForwardIt first, ForwardIt last, const UnaryPredicate& func)
{
    std::mutex mutex;

    return parallel_invoke_n(parallel_get_thread_count(), [&](size_t /*thread_index*/) {
        while (true)
        {
            std::unique_lock<std::mutex> guard(mutex);

            if (first != last)
            {
                auto&& value = *first++;

                guard.unlock();

                if (!func(std::forward<decltype(value)>(value)))
                {
                    break;
                }
            }
            else
            {
                break;
            }
        }
    });
}

template <typename UnaryPredicate>
inline void parallel_partition(size_t total, size_t partition, size_t overlap, const UnaryPredicate& func)
{
    if (partition >= total)
    {
        func(0, total);

        return;
    }

    std::atomic_size_t current {0};

    return parallel_invoke_n(std::min<size_t>(parallel_get_thread_count(), (total + partition - 1) / partition),
        [&, total, partition, overlap](size_t /*thread_index*/) {
            while (true)
            {
                const size_t sub_current = current.fetch_add(partition, std::memory_order_relaxed);

                if (sub_current < total)
                {
                    if (!func(sub_current, std::min<size_t>(partition + overlap, total - sub_current)))
                    {
                        break;
                    }
                }
                else
                {
                    break;
                }
            }
        });
}
