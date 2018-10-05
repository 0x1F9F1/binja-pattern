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

#include "BinaryNinja.h"

#include <thread>

class BackgroundTaskThread
    : public BackgroundTask
{
protected:
    std::thread thread_;

public:
    BackgroundTaskThread(const std::string& initialText)
        : BackgroundTask(initialText, true)
    { }

    template <typename Func, typename... Args>
    void Run(Func&& func, Args&&... args)
    {
        thread_ = std::thread([ ] (Ref<BackgroundTaskThread> task, auto func, auto... args) -> void
        {
            std::invoke(std::move(func), task.GetPtr(), std::move(args)...);

            task->Finish();
            task->thread_.detach();

            task = nullptr;
        }, Ref<BackgroundTaskThread>(this), std::forward<Func>(func), std::forward<Args>(args)...);
    }

    void Join()
    {
        if (thread_.joinable())
        {
            thread_.join();
        }
    }
};
