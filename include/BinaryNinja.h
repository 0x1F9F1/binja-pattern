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

#include <binaryninjaapi.h>
#include <binaryninjacore.h>
#include <lowlevelilinstruction.h>
#include <mediumlevelilinstruction.h>

#include <fmt/format.h>

using namespace BinaryNinja;

template <typename String, typename... Args>
void BinjaLog(BNLogLevel level, const String& format, const Args&... args)
{
    BNLog(level, "%s", fmt::format(format, args...).c_str());
}

#include <mem/mem.h>
#include <memory>

#include <mem/cuda_pattern.h>

namespace brick
{
    struct view_segment
    {
        uint64_t start;
        uint64_t length;
        mem::device_data data;

        view_segment(Ref<BinaryView> view, uint64_t start, uint64_t length);
    };

    struct view_data
    {
        Ref<BinaryView> view;
        std::vector<view_segment> segments;

        view_data(Ref<BinaryView> view);

        std::vector<uint64_t> scan_all(const mem::cuda_pattern& pattern) const
        {
            std::vector<uint64_t> results;

            for (const view_segment& segment : segments)
            {
                std::vector<size_t> sub_results = pattern.scan_all(segment.data);

                results.reserve(results.size() + sub_results.size());

                for (size_t sub_result : sub_results)
                {
                    results.emplace_back(segment.start + sub_result);
                }
            }

            return results;
        }
    };
}
