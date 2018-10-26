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

#include "PatternLoader.h"
#include "BackgroundTaskThread.h"

#include <json.hpp>
#include <fstream>

#include <mem/pattern.h>
#include <mem/utils.h>

#include <unordered_set>

#include "ParallelFunctions.h"

using json = nlohmann::json;

const std::unordered_map<std::string, std::function<bool(BinaryView*, uint64_t&, const json&)>> POINTER_OPS =
{
    { "add", [ ] (BinaryView* view, uint64_t& address, const json& j) -> bool
        {
            address += j.at("value").get<size_t>();

            return true;
        }
    },
    { "sub", [ ] (BinaryView* view, uint64_t& address, const json& j) -> bool
        {
            address -= j.at("value").get<size_t>();

            return true;
        }
    },
    { "rip", [ ] (BinaryView* view, uint64_t& address, const json& j) -> bool
        {
            int32_t offset = 0;

            if (view->Read(&offset, address, sizeof(offset)) != sizeof(offset))
            {
                return false;
            }

            address += offset + j.at("value").get<size_t>();

            return true;
        }
    },
    { "abs", [ ] (BinaryView* view, uint64_t& address, const json&) -> bool
        {
            size_t address_size = view->GetAddressSize();

            switch (address_size)
            {
#define X(TYPE) \
case sizeof(TYPE): \
{ \
    TYPE result = 0; \
    if (view->Read(&result, address, sizeof(result)) != sizeof(result)) \
    { \
        return false; \
    } \
    address = result; \
    return true; \
};

                X(uint8_t)
                X(uint16_t)
                X(uint32_t)
                X(uint64_t)

#undef X
            }

            return false;
        }
    },
};

void ProcessPatternFile(Ref<BackgroundTask> task, Ref<BinaryView> view, std::string file_name)
{
    std::ifstream input_stream(file_name);

    if (!input_stream.good())
    {
        BinjaLog(InfoLog, "Failed to open \"{}\"", file_name);

        return;
    }

    const brick::view_data data(view);

    try
    {
        const json config = json::parse(input_stream);
        const json& patterns = config.at("patterns");

        parallel_for_each(patterns.begin(), patterns.end(), [&] (const json& j) -> bool
        {
            std::string name = j.at("name").get<std::string>();
            std::string type = j.at("category").get<std::string>();
            std::string desc = j.at("desc").get<std::string>();
            std::string pattern_string = j.at("pattern").get<std::string>();

            mem::pattern pattern(pattern_string.c_str());

            if (!pattern)
            {
                BinjaLog(ErrorLog, "Pattern \"{}\" is empty or malformed", pattern_string);

                return true;
            }

            mem::cuda_pattern c_pattern(pattern);

            std::vector<uint64_t> scan_results = data.scan_all(
                c_pattern
            );

            if (scan_results.empty())
            {
                BinjaLog(InfoLog, "Pattern \"{}\" (\"{}\") not found", name, pattern_string);

                return true;
            }

            {
                const auto find = j.find("count");

                if (find != j.end())
                {
                    const auto count = find->get<size_t>();

                    if (count != scan_results.size())
                    {
                        BinjaLog(InfoLog, "Invalid Count: (Got {}, Expected {})", scan_results.size(), count);

                        return true;
                    }
                }
            }

            {
                const auto find = j.find("index");

                if (find != j.end())
                {
                    const auto index = find->get<size_t>();

                    if (index >= scan_results.size())
                    {
                        BinjaLog(InfoLog, "Invalid Index: {}, {} Results", index, scan_results.size());

                        return true;
                    }

                    scan_results = { scan_results.at(index) };
                }
            }

            {
                const auto find = j.find("ops");

                if (find != j.end())
                {
                    for (auto& result : scan_results)
                    {
                        for (const auto& op : *find)
                        {
                            std::string op_type = op.at("type").get<std::string>();

                            if (!POINTER_OPS.at(op_type)(view, result, op))
                            {
                                BinjaLog(InfoLog, "Operation {} failed", op_type);

                                return true;
                            }
                        }
                    }
                }
            }

            std::unordered_set<uint64_t> unique_scan_results(scan_results.begin(), scan_results.end());

            if (unique_scan_results.size() != 1)
            {
                std::string error;

                for (auto result : unique_scan_results)
                {
                    error += fmt::format(" @ 0x{:X}\n", result);
                }

                BinjaLog(InfoLog, "Differing Results: {}", error);

                return true;
            }

            uint64_t offset = *unique_scan_results.begin();

            BinjaLog(InfoLog, "Found {} @ 0x{:X}\n", name, offset);

            BNSymbolType symbol_type = DataSymbol;

            if (type == "Function")
            {
                Ref<Platform> platform = view->GetDefaultPlatform();

                if (platform)
                {
                    view->CreateUserFunction(platform, offset);
                }

                symbol_type = FunctionSymbol;
            }

            Ref<Symbol> symbol = new Symbol(symbol_type, name, offset);

            view->DefineUserSymbol(symbol);

            return true;
        });
    }
    catch (const std::exception&)
    {
        BinjaLog(InfoLog, "Error parsing pattern file \"{}\"", file_name);
    }
}

void LoadPatternFile(Ref<BinaryView> view)
{
    std::string input_file;

    if (BinaryNinja::GetOpenFileNameInput(input_file, "Select Pattern File", "*.json"))
    {
        Ref<BackgroundTaskThread> task = new BackgroundTaskThread("Loading Patterns");

        task->Run(&ProcessPatternFile, view, input_file);
    }
}
