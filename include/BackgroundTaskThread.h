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

#include <exception>
#include <thread>
#include <type_traits>

class BackgroundTaskThread : public BackgroundTask
{
protected:
    std::thread thread_;

public:
    BackgroundTaskThread(const std::string& initialText)
        : BackgroundTask(initialText, true)
    {}

    ~BackgroundTaskThread()
    {
        if (thread_.joinable())
        {
            thread_.detach();
        }
    }

    template <typename Func, typename... Args>
    void Run(Func&& func, Args&&... args)
    {
        Ref<BackgroundTaskThread> task(this);

        thread_ = std::thread(
            [task](typename std::decay<Func>::type func, typename std::decay<Args>::type... args) -> void {
                try
                {
                    func(task.GetPtr(), std::move(args)...);
                }
                catch (const std::exception& ex)
                {
                    BinjaLog(ErrorLog, "Exception in background task: {}", ex.what());
                }
                catch (...)
                {
                    BinjaLog(ErrorLog, "Unknown Exception in background task");
                }

                task->Finish();
            },
            std::forward<Func>(func), std::forward<Args>(args)...);
    }

    void Join()
    {
        if (thread_.joinable())
        {
            thread_.join();
        }
    }
};
