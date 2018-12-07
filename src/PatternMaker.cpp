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

#include <mem/pattern.h>
#include <mem/utils.h>
#include <mem/data_buffer.h>

#if 0
# include <capstone/capstone.h>
# define USE_CAPSTONE
#endif

#if 1
# include <Zydis/Zydis.h>
# define USE_ZYDIS
#endif

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
    size_t address_size = arch->GetAddressSize();

    std::string arch_name = arch->GetName();

#if defined(USE_CAPSTONE)
    cs_arch cap_arch;
    cs_mode cap_mode;

    if (arch_name == "x86")
    {
        cap_arch = CS_ARCH_X86;
        cap_mode = CS_MODE_32;
    }
    else if (arch_name == "x86_64")
    {
        cap_arch = CS_ARCH_X86;
        cap_mode = CS_MODE_64;
    }
    else
    {
        BinjaLog(ErrorLog, "Unknown architecture: {}", arch_name);

        return;
    }

    csh handle;

    if (cs_open(cap_arch, cap_mode, &handle) != CS_ERR_OK)
    {
        BinjaLog(ErrorLog, "Failed to init disassembler");

        return;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
#endif

#if defined(USE_ZYDIS)
    ZydisDecoder decoder;

    if (arch_name == "x86")
    {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_32);
    }
    else if (arch_name == "x86_64")
    {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    }
    else
    {
        BinjaLog(ErrorLog, "Unknown architecture: {}", arch_name);

        return;
    }

#endif

    mem::byte_buffer buffer(arch->GetMaxInstructionLength());

    mem::byte_buffer bytes;
    mem::byte_buffer masks;

    brick::view_data scan_data(view);

    uint64_t current_addr = addr;

    while (true)
    {
        size_t len = view->Read(buffer.data(), current_addr, buffer.size());

        if (len == 0)
            break;

#if defined(USE_CAPSTONE)
        cs_insn *insn;

        size_t count = cs_disasm(handle, buffer.data(), len, current_addr, 1, &insn);

        if (count == 0)
            break;

        len = insn->size;
#endif

#if defined(USE_ZYDIS)
        ZydisDecodedInstruction insn;

        if (ZYAN_FAILED(ZydisDecoderDecodeBuffer(&decoder, buffer.data(), len, &insn)))
            break;

        len = insn.length;
#endif

        byte current_masks[16];
        std::memset(current_masks, 0xFF, len);

#if defined(USE_CAPSTONE)
        cs_x86_encoding& enc = insn->detail->x86.encoding;

        if (enc.disp_offset != 0)
        {
            std::memset(current_masks + enc.disp_offset, 0x00, enc.disp_size);

            BinjaLog(InfoLog, "Disp 0x{:X}, {}, {}", current_addr, enc.disp_offset, enc.disp_size);
        }

        if (enc.imm_offset != 0)
        {
            // if (enc.imm_size == address_size)
            {
                std::memset(current_masks + enc.imm_offset, 0x00, enc.imm_size);

                BinjaLog(InfoLog, "Imm 0x{:X}, {}, {}", current_addr, enc.imm_offset, enc.imm_size);
            }
        }

        cs_free(insn, count);
#endif

#if defined(USE_ZYDIS)
        auto& disp = insn.raw.disp;

        if (disp.size != 0)
        {
            std::memset(current_masks + disp.offset, 0x00, (disp.size + 7) / 8);

            BinjaLog(InfoLog, "Disp 0x{:X}, {}, {}", current_addr, disp.offset, disp.size);
        }

        for (size_t i = 0; i < 2; ++i)
        {
            auto& imm = insn.raw.imm[i];

            if (imm.size != 0)
            {
                std::memset(current_masks + imm.offset, 0x00, (imm.size + 7) / 8);

                BinjaLog(InfoLog, "Imm{} 0x{:X}, {}, {}", i, current_addr, imm.offset, imm.size);
            }
        }
#endif

        bytes.append(buffer.data(), len);
        masks.append(current_masks, len);

        mem::pattern pat(bytes.data(), masks.data(), bytes.size());

        bool found = false;

        scan_data(mem::default_scanner(pat), [&] (uint64_t result)
        {
            if (addr == result)
                return false;

            found = true;

            return true;
        });

        if (!found)
        {
            BinjaLog(InfoLog, "Generated Pattern: {}", pat.to_string());

            break;
        }

        if (pat.size() > 256)
        {
            BinjaLog(ErrorLog, "Pattern too long");

            break;
        }

        current_addr += len;
    }

#if defined(USE_CAPSTONE)
    cs_close(&handle);
#endif
}
