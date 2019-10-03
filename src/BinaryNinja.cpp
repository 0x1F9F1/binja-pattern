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

#include "BinaryNinja.h"

namespace brick
{
    view_segment::view_segment(Ref<BinaryView> view, uint64_t start_, uint64_t length_)
        : start(start_)
        , length(length_)
        , data(new uint8_t[length_])
    {
        if (view->Read(data.get(), start, length) != length)
        {
            // TODO: Handle Errors
        }
    }

    view_data::view_data(Ref<BinaryView> view_)
        : view(view_)
    {
        std::vector<Ref<Segment>> view_segments = view->GetSegments();

        if (!view_segments.empty())
        {
            segments.reserve(view_segments.size());

            for (const Ref<Segment>& segment : view_segments)
            {
                segments.emplace_back(view, segment->GetStart(), segment->GetLength());
            }
        }
        else
        {
            segments.emplace_back(view, view->GetStart(), view->GetLength());
        }
    }
} // namespace brick
