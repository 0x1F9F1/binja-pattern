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

#include <fstream>
#include <unordered_set>

#include <mem/pattern.h>
#include <mem/utils.h>

#include <yaml-cpp/yaml.h>

using stopwatch = std::chrono::steady_clock;

namespace mem
{
    namespace sm
    {
        enum opcode : size_t
        {
            op_push,
            op_add,
            op_sub,
            op_mul,
            op_div,
            op_mod,
            op_and,
            op_or,
            op_xor,
            op_neg,
            op_sx,
            op_dup,
            op_drop,
            op_load,
            op_sym,

            // Internal
            op_paren,

            op_invalid = SIZE_MAX,
        };

        enum symbol : size_t
        {
            sym_here,
        };

        enum paren_type : size_t
        {
            paren_default,
            paren_bracket,
        };

        struct environment
        {
            std::function<bool(size_t addr, size_t size, size_t& out)> read_integer;
            std::function<bool(size_t sym, size_t& out)> resolve_symbol;
        };

        bool compile_infix(const char* string, std::vector<size_t>& code);
        bool compile_postfix(const char* string, std::vector<size_t>& code);

        bool execute(
            const std::vector<size_t>& input, size_t* stack, size_t stack_size, size_t& sp_out, const environment& env);

        struct token
        {
            opcode op {op_invalid};
            size_t operand_count {0};
            std::array<size_t, 1> operands {};

            token(opcode op, size_t operand_count = 0, const std::initializer_list<size_t>& operands = {});
        };

        token::token(opcode op_, size_t operand_count_, const std::initializer_list<size_t>& operands_)
            : op(op_)
            , operand_count(operand_count_)
        {
            std::copy(operands_.begin(), operands_.end(), operands.begin());
        }

        size_t get_precedence(opcode op)
        {
            switch (op)
            {
                case op_mul:
                case op_div:
                case op_mod: return 6;

                case op_add:
                case op_sub: return 5;

                case op_and: return 4;

                case op_xor: return 3;

                case op_or: return 2;

                case op_paren: return 0;

                default: return 1;
            }
        }

        void push_code(std::vector<size_t>& code, const token& token)
        {
            code.push_back(token.op);

            for (size_t i = 0; i < token.operand_count; ++i)
                code.push_back(token.operands[i]);
        }

        void push_token(std::vector<size_t>& code, std::stack<token>& pending, const token& new_token)
        {
            if (new_token.op != op_paren)
            {
                size_t precedence = get_precedence(new_token.op);

                while (!pending.empty())
                {
                    const token& current = pending.top();
                    size_t current_precedence = get_precedence(current.op);

                    if (precedence > current_precedence)
                    {
                        break;
                    }

                    push_code(code, current);

                    pending.pop();

                    if (precedence == current_precedence)
                    {
                        break;
                    }
                }
            }

            pending.push(new_token);
        }

        bool match_parens(std::vector<size_t>& code, std::stack<token>& pending, paren_type type)
        {
            while (!pending.empty())
            {
                token current = pending.top();
                pending.pop();

                if (current.op == op_paren)
                {
                    return (current.operand_count == 1 && current.operands[0] == type);
                }

                push_code(code, current);
            }

            return false;
        }

        bool compile_infix(const char* string, std::vector<size_t>& code)
        {
            code.clear();

            std::stack<token> pending;

            char_queue input(string);

            while (input)
            {
                int current = input.peek();

                if (current == ' ')
                {
                    input.pop();
                }
                else if (current == '+')
                {
                    input.pop();
                    push_token(code, pending, {op_add});
                }
                else if (current == '-')
                {
                    input.pop();
                    push_token(code, pending, {op_sub});
                }
                else if (current == '*')
                {
                    input.pop();
                    push_token(code, pending, {op_mul});
                }
                else if (current == '/')
                {
                    input.pop();
                    push_token(code, pending, {op_div});
                }
                else if (current == '%')
                {
                    input.pop();
                    push_token(code, pending, {op_mod});
                }
                else if (current == '&')
                {
                    input.pop();
                    push_token(code, pending, {op_and});
                }
                else if (current == '|')
                {
                    input.pop();
                    push_token(code, pending, {op_or});
                }
                else if (current == '^')
                {
                    input.pop();
                    push_token(code, pending, {op_xor});
                }
                else if (current == '(')
                {
                    input.pop();

                    push_token(code, pending, {op_paren, 1, {paren_default}});
                }
                else if (current == ')')
                {
                    input.pop();

                    if (!match_parens(code, pending, paren_default))
                    {
                        return false;
                    }
                }
                else if (current == '[')
                {
                    input.pop();

                    push_token(code, pending, {op_paren, 1, {paren_bracket}});
                }
                else if (current == ']')
                {
                    input.pop();

                    if (!match_parens(code, pending, paren_bracket))
                    {
                        return false;
                    }

                    size_t read_size = 0;
                    bool is_signed = false;
                    bool is_relative = false;

                    if (input.peek() == '.')
                    {
                        input.pop();

                        if (input.peek() == 'r')
                        {
                            input.pop();

                            is_relative = true;
                        }

                        if (input.peek() == 's')
                        {
                            input.pop();

                            is_signed = true;
                        }

                        current = input.peek();

                        if (current == 'b')
                        {
                            input.pop();
                            read_size = 1;
                        }
                        else if (current == 'w')
                        {
                            input.pop();
                            read_size = 2;
                        }
                        else if (current == 'd')
                        {
                            input.pop();
                            read_size = 4;
                        }
                        else if (current == 'q')
                        {
                            input.pop();
                            read_size = 8;
                        }
                        else if (is_relative)
                        {
                            read_size = 4;

                            is_signed = true;
                        }
                        else
                        {
                            return false;
                        }
                    }

                    if (is_relative)
                    {
                        push_code(code, {op_dup});
                    }

                    push_code(code, {op_load, 1, {read_size}});

                    if (is_signed)
                    {
                        push_code(code, {op_sx, 1, {read_size * 8}});
                    }

                    if (is_relative)
                    {
                        push_code(code, {op_add});
                    }
                }
                else if (current == '$')
                {
                    input.pop();

                    char name[64 + 1];
                    size_t name_length = 0;

                    while (input)
                    {
                        current = input.peek();

                        if (current == ' ')
                            break;

                        if (name_length + 1 > 64)
                            return false;

                        name[name_length++] = (char) current;
                    }

                    name[name_length++] = '\0';

                    size_t sym = SIZE_MAX;

                    if (!std::strcmp(name, "") || !std::strcmp(name, "here"))
                    {
                        sym = sym_here;
                    }
                    else
                    {
                        return false;
                    }

                    push_code(code, {op_sym, 1, {sym}});
                }
                else if (xctoi(current) != -1)
                {
                    int temp = -1;

                    size_t value = 0;

                    while ((temp = xctoi(input.peek())) != -1)
                    {
                        input.pop();

                        value = (value * 16) + temp;
                    }

                    push_code(code, {op_push, 1, {value}});
                }
                else
                {
                    return false;
                }
            }

            while (!pending.empty())
            {
                token current = pending.top();
                pending.pop();

                if (current.op == op_paren)
                    return false;

                push_code(code, current);
            }

            return true;
        }

        bool compile_postfix(const char* string, std::vector<size_t>& code)
        {
            code.clear();

            char_queue input(string);

            while (input)
            {
                int current = input.peek();

                if (current == ' ')
                {
                    input.pop();
                }
                else if (current == '+')
                {
                    input.pop();
                    code.push_back(op_add);
                }
                else if (current == '-')
                {
                    input.pop();
                    code.push_back(op_sub);
                }
                else if (current == '*')
                {
                    input.pop();
                    code.push_back(op_mul);
                }
                else if (current == '/')
                {
                    input.pop();
                    code.push_back(op_div);
                }
                else if (current == '%')
                {
                    input.pop();
                    code.push_back(op_mod);
                }
                else if (current == '&')
                {
                    input.pop();
                    code.push_back(op_and);
                }
                else if (current == '|')
                {
                    input.pop();
                    code.push_back(op_or);
                }
                else if (current == '^')
                {
                    input.pop();
                    code.push_back(op_xor);
                }
                else if (current == '>')
                {
                    input.pop();
                    code.push_back(op_dup);
                }
                else if (current == '<')
                {
                    input.pop();
                    code.push_back(op_drop);
                }
                else if (current == '[')
                {
                    input.pop();

                    bool is_signed = false;
                    size_t width = SIZE_MAX;

                    if (input.peek() == 's')
                    {
                        input.pop();
                        is_signed = true;
                    }
                    else if (input.peek() == 'u')
                    {
                        input.pop();
                        is_signed = false;
                    }

                    if (input.peek() == 'b')
                    {
                        input.pop();
                        width = 1;
                    }
                    else if (input.peek() == 'w')
                    {
                        input.pop();
                        width = 2;
                    }
                    else if (input.peek() == 'd')
                    {
                        input.pop();
                        width = 4;
                    }
                    else if (input.peek() == 'q')
                    {
                        input.pop();
                        width = 8;
                    }
                    else
                    {
                        return false;
                    }

                    if (width > sizeof(size_t))
                        return false;

                    if (input.peek() != ']')
                        return false;

                    input.pop();

                    code.push_back(op_load);
                    code.push_back(width);

                    if (is_signed)
                    {
                        code.push_back(op_sx);
                        code.push_back(width * 8);
                    }
                }
                else if (current == '$')
                {
                    input.pop();

                    char name[64 + 1];
                    size_t name_length = 0;

                    while (input)
                    {
                        current = input.peek();

                        if (current == ' ')
                            break;

                        if (name_length + 1 > 64)
                            return false;

                        name[name_length++] = (char) current;
                    }

                    name[name_length++] = '\0';

                    size_t sym = SIZE_MAX;

                    if (!std::strcmp(name, "") || !std::strcmp(name, "here"))
                    {
                        sym = sym_here;
                    }
                    else
                    {
                        return false;
                    }

                    code.push_back(op_sym);
                    code.push_back(sym);
                }
                else if (xctoi(current) != -1)
                {
                    int temp = -1;

                    size_t value = 0;

                    while ((temp = mem::xctoi(input.peek())) != -1)
                    {
                        input.pop();

                        value = (value * 16) + temp;
                    }

                    code.push_back(op_push);
                    code.push_back(value);
                }
                else
                {
                    return false;
                }
            }

            return true;
        }

        bool execute(
            const std::vector<size_t>& input, size_t* stack, size_t stack_size, size_t& sp_out, const environment& env)
        {
            size_t ip = 0;
            size_t sp = 0;

            const size_t* code = input.data();
            const size_t code_size = input.size();

            std::memset(stack, 0, stack_size * sizeof(size_t));

            while (ip < code_size)
            {
                size_t op = code[ip++];

                switch (op)
                {
                    case op_push:
                    {
                        if (ip + 1 > code_size)
                            return false;

                        if (sp + 1 > stack_size)
                            return false;

                        stack[sp++] = code[ip++];
                    }
                    break;

                    case op_add:
                    {
                        if (sp < 2)
                            return false;

                        size_t temp = stack[--sp];

                        stack[sp - 1] += temp;
                    }
                    break;

                    case op_sub:
                    {
                        if (sp < 2)
                            return false;

                        size_t temp = stack[--sp];

                        stack[sp - 1] -= temp;
                    }
                    break;

                    case op_mul:
                    {
                        if (sp < 2)
                            return false;

                        size_t temp = stack[--sp];

                        stack[sp - 1] *= temp;
                    }
                    break;

                    case op_div:
                    {
                        if (sp < 2)
                            return false;

                        size_t temp = stack[--sp];

                        if (temp == 0)
                            return false;

                        stack[sp - 1] /= temp;
                    }
                    break;

                    case op_mod:
                    {
                        if (sp < 2)
                            return false;

                        size_t temp = stack[--sp];

                        if (temp == 0)
                            return false;

                        stack[sp - 1] %= temp;
                    }
                    break;

                    case op_and:
                    {
                        if (sp < 2)
                            return false;

                        size_t temp = stack[--sp];

                        stack[sp - 1] &= temp;
                    }
                    break;

                    case op_or:
                    {
                        if (sp < 2)
                            return false;

                        size_t temp = stack[--sp];

                        stack[sp - 1] |= temp;
                    }
                    break;

                    case op_xor:
                    {
                        if (sp < 2)
                            return false;

                        size_t temp = stack[--sp];

                        stack[sp - 1] ^= temp;
                    }
                    break;

                    case op_neg:
                    {
                        if (sp < 1)
                            return false;

                        stack[sp - 1] = size_t(0) - stack[sp - 1];
                    }
                    break;

                    case op_sx:
                    {
                        if (ip + 1 > code_size)
                            return false;

                        if (sp < 1)
                            return false;

                        size_t bits = code[ip++];
                        size_t mask = size_t(1) << (bits - 1);

                        stack[sp - 1] = (stack[sp - 1] ^ mask) - mask;
                    }
                    break;

                    case op_dup:
                    {
                        if (sp < 1)
                            return false;

                        if (sp + 1 > stack_size)
                            return false;

                        size_t temp = stack[sp - 1];

                        stack[sp++] = temp;
                    }
                    break;

                    case op_drop:
                    {
                        if (sp < 1)
                            return false;

                        --sp;
                    }
                    break;

                    case op_load:
                    {
                        if (!env.read_integer)
                            return false;

                        if (ip + 1 > code_size)
                            return false;

                        if (sp < 1)
                            return false;

                        size_t addr = stack[sp - 1];
                        size_t size = code[ip++];

                        size_t temp = SIZE_MAX;

                        if (!env.read_integer(addr, size, temp))
                            return false;

                        stack[sp - 1] = temp;
                    }
                    break;

                    case op_sym:
                    {
                        if (!env.resolve_symbol)
                            return false;

                        if (ip + 1 > code_size)
                            return false;

                        if (sp + 1 > stack_size)
                            return false;

                        size_t sym = code[ip++];
                        size_t temp = SIZE_MAX;

                        if (!env.resolve_symbol(sym, temp))
                            return false;

                        stack[sp++] = temp;
                    }
                    break;

                    default: { return false;
                    }
                }
            }

            sp_out = sp;

            return true;
        }
    } // namespace sm
} // namespace mem

void ProcessPatternFile(Ref<BackgroundTask> task, Ref<BinaryView> view, std::string file_name)
{
    const auto total_start_time = stopwatch::now();

    auto config = YAML::LoadFile(file_name);

    auto patterns = config["patterns"];

    if (!patterns || !patterns.IsSequence())
    {
        BinjaLog(ErrorLog, "File does not contain any patterns");

        return;
    }

    const brick::view_data data(view);

    std::for_each(patterns.begin(), patterns.end(), [&](const YAML::Node& n) -> bool {
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
                BinjaLog(ErrorLog, "Pattern \"{}\" (\"{}\") not found", name, pattern_string);

                return true;
            }

            {
                const auto ops = n["ops"];

                if (ops)
                {
                    if (ops.IsScalar())
                    {
                        std::vector<size_t> expr;

                        std::string ops_string = ops.as<std::string>();

                        if (!mem::sm::compile_infix(ops_string.c_str(), expr))
                        {
                            BinjaLog(ErrorLog, "Error parsing \"{}\"", ops_string);

                            return true;
                        }

                        BinaryReader reader(view, view->GetDefaultEndianness());

                        for (auto iter = scan_results.begin(); iter != scan_results.end();)
                        {
                            size_t sp_out = SIZE_MAX;
                            size_t stack[16];

                            mem::sm::environment env;

                            env.read_integer = [view, &reader](size_t addr, size_t size, size_t& out) -> bool {
                                if (size == 0)
                                    size = view->GetAddressSize();

                                if (size > sizeof(size_t))
                                    return false;

                                reader.Seek(addr);

                                switch (size)
                                {
                                    case 1:
                                    {
                                        uint8_t result;
                                        if (!reader.TryRead8(result))
                                        {
                                            return false;
                                        }
                                        out = result;
                                        return true;
                                    }
                                    case 2:
                                    {
                                        uint16_t result;
                                        if (!reader.TryRead16(result))
                                        {
                                            return false;
                                        }
                                        out = result;
                                        return true;
                                    }
                                    case 4:
                                    {
                                        uint32_t result;
                                        if (!reader.TryRead32(result))
                                        {
                                            return false;
                                        }
                                        out = result;
                                        return true;
                                    }
                                    case 8:
                                    {
                                        uint64_t result;
                                        if (!reader.TryRead64(result))
                                        {
                                            return false;
                                        }
                                        out = result;
                                        return true;
                                    }
                                }

                                return false;
                            };

                            size_t here = *iter;

                            env.resolve_symbol = [here](size_t sym, size_t& out) -> bool {
                                switch (sym)
                                {
                                    case mem::sm::sym_here:
                                    {
                                        out = here;

                                        return true;
                                    };
                                }

                                return false;
                            };

                            if (mem::sm::execute(expr, stack, 16, sp_out, env) && (sp_out == 1))
                            {
                                *iter++ = stack[0];
                            }
                            else
                            {
                                BinjaLog(ErrorLog, "Eval Failed");

                                iter = scan_results.erase(iter);
                            }
                        }
                    }
                    else
                    {
                        BinjaLog(ErrorLog, "Invalid Operands for {}", name);
                    }
                }
            }

            if (scan_results.empty())
            {
                BinjaLog(ErrorLog, "Not Found: {}\n", name);
            }

            std::unordered_set<uint64_t> unique_scan_results(scan_results.begin(), scan_results.end());

            if (unique_scan_results.size() != 1)
            {
                {
                    const auto count = n["count"].as<size_t>(1);

                    if (count != scan_results.size())
                    {
                        BinjaLog(
                            ErrorLog, "{}: Invalid Count: (Got {}, Expected {})", name, scan_results.size(), count);

                        return true;
                    }
                }

                {
                    const auto index = n["index"].as<size_t>(0);

                    if (index >= scan_results.size())
                    {
                        BinjaLog(ErrorLog, "{}: Invalid Index: {}, {} Results", name, index, scan_results.size());

                        return true;
                    }

                    unique_scan_results = {scan_results.at(index)};
                }
            }

            if (unique_scan_results.size() != 1)
            {
                std::string error;

                for (auto result : unique_scan_results)
                {
                    error += fmt::format(" @ 0x{:X}\n", result);
                }

                BinjaLog(ErrorLog, "Differing Results: {}\n{}", name, error);

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
            BinjaLog(ErrorLog, "Error parsing pattern file \"{}\": {}", file_name, ex.what());
        }
        catch (...)
        {
            BinjaLog(ErrorLog, "Error parsing pattern file \"{}\"", file_name);
        }

        return true;
    });

    const auto total_end_time = stopwatch::now();

    const auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(total_end_time - total_start_time).count();

    BinjaLog(InfoLog, "Found {} patterns in {} ms ({} ms avg)\n", patterns.size(), elapsed_ms,
        (double) elapsed_ms / (double) patterns.size());
}

void LoadPatternFile(Ref<BinaryView> view)
{
    std::string input_file;

    if (BinaryNinja::GetOpenFileNameInput(input_file, "Select Pattern File", "*.yml;*.yaml"))
    {
        Ref<BackgroundTaskThread> task = new BackgroundTaskThread("Loading Patterns");

        task->Run(&ProcessPatternFile, view, input_file);
    }
}
