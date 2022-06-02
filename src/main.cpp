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
#include "PatternLoader.h"
#include "PatternMaker.h"
#include "PatternScanner.h"

BN_DECLARE_CORE_ABI_VERSION;

extern "C"
{
    BINARYNINJAPLUGIN bool CorePluginInit()
    {
        PluginCommand::Register("Pattern\\Scan for Pattern", "Scans for an array of bytes", &ScanForArrayOfBytes);
        PluginCommand::Register("Pattern\\Load Pattern File", "Loads a file containing patterns", &LoadPatternFile);

        PluginCommand::RegisterForAddress("Pattern\\Create Signature", "Creates a signature", &GenerateSignature,
            [](Ref<BinaryView> view, uint64_t addr) -> bool {
                Ref<BasicBlock> block = view->GetRecentBasicBlockForAddress(addr);

                if (!block)
                {
                    return false;
                }

                Ref<Function> func = block->GetFunction();
                Ref<Architecture> arch = func->GetArchitecture();

                std::string arch_name = arch->GetName();

                return (arch_name == "x86") || (arch_name == "x86_64");
            });

        BinjaLog(InfoLog, "Loaded binja-pattern");

        return true;
    }
};
