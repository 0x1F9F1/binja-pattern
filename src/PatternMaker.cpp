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

#include "PatternMaker.h"

#include <mem/data_buffer.h>
#include <mem/pattern.h>
#include <mem/utils.h>

#include <Zydis/Zydis.h>

#if defined(_WIN32)
#    define WIN32_LEAN_AND_MEAN
#    include <Windows.h>
#endif

bool CopyToClipboard(const std::string& text)
{
#if defined(_WIN32)
    bool success = false;

    if (OpenClipboard(NULL))
    {
        if (EmptyClipboard())
        {
            HGLOBAL hText = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);

            if (hText)
            {
                void* pText = GlobalLock(hText);

                if (pText)
                {
                    std::memcpy(pText, text.c_str(), text.size() + 1);
                    GlobalUnlock(hText);
                    success = SetClipboardData(CF_TEXT, hText) != NULL;
                }
                else
                {
                    GlobalFree(hText);
                }
            }
        }

        CloseClipboard();
    }

    return success;
#else
    (void) text;

    return false;
#endif
}

struct InstructionMaskDecoder
{
    virtual ~InstructionMaskDecoder() = default;
    virtual size_t Decode(uint64_t address, const uint8_t* data, size_t length, uint8_t* masks) = 0;
};

struct X86MaskDecoder : InstructionMaskDecoder
{
    ZydisDecoder Decoder;

    X86MaskDecoder(size_t address_width)
    {
        switch (address_width)
        {
            case 4: ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32); break;
            case 8: ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64); break;
            default: throw std::runtime_error("Invalid x86 Address Width");
        }
    }

    size_t Decode(uint64_t address, const uint8_t* data, size_t length, uint8_t* masks) override
    {
        ZydisDecodedInstruction insn;

        if (ZYAN_FAILED(ZydisDecoderDecodeBuffer(&Decoder, data, length, &insn)))
        {
            return 0;
        }

        auto& disp = insn.raw.disp;

        if (disp.size != 0)
        {
            std::memset(masks + disp.offset, 0x00, (disp.size + 7) / 8);
        }

        for (size_t i = 0; i < 2; ++i)
        {
            auto& imm = insn.raw.imm[i];

            if (imm.size != 0)
            {
                std::memset(masks + imm.offset, 0x00, (imm.size + 7) / 8);
            }
        }

        return insn.length;
    }
};

void GenerateSignature(Ref<BinaryView> view, uint64_t addr)
{
    Ref<BasicBlock> block = view->GetRecentBasicBlockForAddress(addr);

    if (!block)
    {
        BinjaLog(ErrorLog, "Unknown Address");

        return;
    }

    Ref<Function> func = block->GetFunction();
    Ref<Architecture> arch = func->GetArchitecture();

    std::string arch_name = arch->GetName();

    std::unique_ptr<InstructionMaskDecoder> decoder;

    if (arch_name == "x86" || arch_name == "x86_64")
    {
        decoder = std::make_unique<X86MaskDecoder>(arch->GetAddressSize());
    }
    else
    {
        BinjaLog(ErrorLog, "Unknown architecture: {}", arch_name);

        return;
    }

    mem::byte_buffer insn_buffer(arch->GetMaxInstructionLength());
    mem::byte_buffer mask_buffer(arch->GetMaxInstructionLength());

    mem::byte_buffer bytes;
    mem::byte_buffer masks;

    brick::view_data scan_data(view);

    uint64_t current_addr = addr;

    while (true)
    {
        size_t len = view->Read(insn_buffer.data(), current_addr, insn_buffer.size());

        if (len == 0)
        {
            BinjaLog(ErrorLog, "Failed to read data : 0x{:X}", current_addr);

            break;
        }

        std::memset(mask_buffer.data(), 0xFF, len);

        len = decoder->Decode(current_addr, insn_buffer.data(), len, mask_buffer.data());

        if (len == 0)
        {
            BinjaLog(ErrorLog, "Failed to decode instruction @ 0x{:X}", current_addr);

            break;
        }

        bytes.append(insn_buffer.data(), len);
        masks.append(mask_buffer.data(), len);

        mem::pattern pat(bytes.data(), masks.data(), bytes.size());

        if (pat.size() >= 5)
        {
            bool found = false;

            scan_data(mem::default_scanner(pat), [&](uint64_t result) {
                if (addr == result)
                    return false;

                found = true;

                return true;
            });

            if (!found)
            {
                std::string pat_string = pat.to_string();

                CopyToClipboard(pat_string);

                BinjaLog(InfoLog, "Generated Pattern: \"{}\"", pat_string);

                break;
            }
        }

        if (pat.size() > 256)
        {
            BinjaLog(ErrorLog, "Pattern too long");

            break;
        }

        current_addr += len;
    }
}