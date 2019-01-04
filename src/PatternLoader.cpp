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
#include "ParallelFunctions.h"
#include "BackgroundTaskThread.h"

#include <fstream>
#include <unordered_set>

#include <mem/pattern.h>
#include <mem/utils.h>

#include <yaml-cpp/yaml.h>

using stopwatch = std::chrono::steady_clock;

const std::unordered_map<std::string, bool(*)(BinaryView*, uint64_t&, const YAML::Node&)> POINTER_OPS =
{
    { "add", [ ] (BinaryView* view, uint64_t& address, const YAML::Node& n) -> bool
        {
            address += n["value"].as<size_t>();

            return true;
        }
    },
    { "sub", [ ] (BinaryView* view, uint64_t& address, const YAML::Node& n) -> bool
        {
            address -= n["value"].as<size_t>();

            return true;
        }
    },
    { "rip", [ ] (BinaryView* view, uint64_t& address, const YAML::Node& n) -> bool
        {
            auto value = n["value"].as<size_t>();

            int32_t offset = 0;

            if (view->Read(&offset, address, sizeof(offset)) != sizeof(offset))
            {
                return false;
            }

            address += offset + value;

            return true;
        }
    },
    { "abs", [ ] (BinaryView* view, uint64_t& address, const YAML::Node& n) -> bool
        {
            (void) n;

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
    const auto total_start_time = stopwatch::now();

    auto config = YAML::LoadFile(file_name);

    auto patterns = config["patterns"];

    if (!patterns.IsSequence())
    {
        BinjaLog(ErrorLog, "File does not contain any patterns");

        return;
    }

    const brick::view_data data(view);

    parallel_for_each(patterns.begin(), patterns.end(), [&] (const YAML::Node& n) -> bool
    {
        try
        {
            std::string name = n["name"].as<std::string>();
            std::string type = n["category"].as<std::string>();
            std::string desc = n["desc"].as<std::string>("");
            std::string pattern_string = n["pattern"].as<std::string>();

            mem::pattern pattern(pattern_string.c_str());

            if (!pattern)
            {
                BinjaLog(ErrorLog, "Pattern \"{}\" is empty or malformed", pattern_string);

                return true;
            }

            mem::default_scanner scanner(pattern);

            std::vector<uint64_t> scan_results = data.scan_all(scanner);

            if (scan_results.empty())
            {
                BinjaLog(InfoLog, "Pattern \"{}\" (\"{}\") not found", name, pattern_string);

                return true;
            }

            {
                const auto count = n["count"].as<size_t>(1);

                if (count != scan_results.size())
                {
                    BinjaLog(InfoLog, "Invalid Count: (Got {}, Expected {})", scan_results.size(), count);

                    return true;
                }
            }

            {
                const auto index = n["index"].as<size_t>(0);

                if (index >= scan_results.size())
                {
                    BinjaLog(InfoLog, "Invalid Index: {}, {} Results", index, scan_results.size());

                    return true;
                }

                scan_results = { scan_results.at(index) };
            }

            {
                const auto ops = n["ops"];

                if (ops && ops.IsSequence())
                {
                    for (auto& result : scan_results)
                    {
                        for (const auto& op : ops)
                        {
                            std::string op_type = op["type"].as<std::string>();

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

                BinjaLog(InfoLog, "Differing Results: {}\n{}", name, error);

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
            // view->DefineDataVariable(offset, Type::VoidType()->WithConfidence(0));

        }
        catch (const std::exception& ex)
        {
            BinjaLog(InfoLog, "Error parsing pattern file \"{}\": {}", file_name, ex.what());
        }
        catch (...)
        {
            BinjaLog(InfoLog, "Error parsing pattern file \"{}\"", file_name);
        }

        return true;
    });

    const auto total_end_time = stopwatch::now();

    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(total_end_time - total_start_time).count();

    BinjaLog(InfoLog, "Found {} patterns in {} ms ({} ms avg)\n", patterns.size(), elapsed_ms, (double) elapsed_ms / (double) patterns.size());
}

void LoadPatternFile(Ref<BinaryView> view)
{
    std::string input_file;

    if (BinaryNinja::GetOpenFileNameInput(input_file, "Select Pattern File", "*.yaml"))
    {
        Ref<BackgroundTaskThread> task = new BackgroundTaskThread("Loading Patterns");

        task->Run(&ProcessPatternFile, view, input_file);
    }
}
