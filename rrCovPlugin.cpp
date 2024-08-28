/*
 *  ____  ____  _____              
 * |  _ \|  _ \|  ___|   _ ________
 * | |_) | |_) | |_ | | | |_  /_  /
 * |  _ <|  _ <|  _|| |_| |/ / / / 
 * |_| \_\_| \_\_|   \__,_/___/___|
 *
 * Copyright (C) National University of Singapore
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This is a modified version of E9AFL.
 *
 * The main change is that the bitmap base is stored in the %gs register.
 */

#include <cassert>

#include <initializer_list>
#include <map>
#include <sstream>
#include <string>
#include <set>
#include <vector>

#include <getopt.h>

#include "e9plugin.h"

using namespace e9tool;

#include "rrfuzz.h"

/*
 * Options.
 */
enum Option
{
    OPTION_NEVER,
    OPTION_DEFAULT,
    OPTION_ALWAYS
};
static Option option_debug      = OPTION_DEFAULT;
static Option option_Oselect    = OPTION_DEFAULT;
static Option option_Oblock     = OPTION_DEFAULT;

enum Counter
{
    COUNTER_CLASSIC,
    COUNTER_NEVER_ZERO,
    COUNTER_SATURATED
};

static Option parseOption(const char *str)
{
    if (strcmp(str, "never") == 0)
        return OPTION_NEVER;
    if (strcmp(str, "default") == 0)
        return OPTION_DEFAULT;
    if (strcmp(str, "always") == 0)
        return OPTION_ALWAYS;
    error("bad option value \"%s\"; expected one of {\"never\", \"default\", "
        "\"always\"}", str);
}

static Counter parseCounter(const char *str)
{
    if (strcmp(str, "classic") == 0)
        return COUNTER_CLASSIC;
    if (strcmp(str, "neverzero") == 0)
        return COUNTER_NEVER_ZERO;
    if (strcmp(str, "saturated") == 0)
        return COUNTER_SATURATED;
    error("bad counter value \"%s\"; expected one of {\"classic\", \"neverzero\", "
        "\"saturated\"}", str);
}

/*
 * CFG
 */
struct BasicBlock
{
    std::vector<intptr_t> preds;    // Predecessor BBs
    std::vector<intptr_t> succs;    // Successor BBs
    intptr_t instrument = -1;       // Instrumentation point
    int id              = -1;       // ID
    bool optimized      = false;    // Optimize block?
    bool bad            = false;    // Bad block?
};
typedef std::map<intptr_t, BasicBlock> CFG;
#define BB_INDIRECT     (-1)

/*
 * Paths
 */
typedef std::map<BasicBlock *, BasicBlock *> Paths;

/*
 * All instrumentation points.
 */
static std::set<intptr_t> instrument;

/*
 * Options.
 */
enum
{
    OPTION_COUNTER,
    OPTION_OBLOCK,
    OPTION_OSELECT,
    OPTION_DEBUG,
    OPTION_PATH,
};

/*
 * Initialization.
 */
extern void *e9_plugin_init(const Context *cxt)
{
    static const struct option long_options[] =
    {
        {"counter", required_argument, nullptr, OPTION_COUNTER},
        {"Oblock",  required_argument, nullptr, OPTION_OBLOCK},
        {"Oselect", required_argument, nullptr, OPTION_OSELECT},
        {"debug",   no_argument,       nullptr, OPTION_DEBUG},
        {"path",    required_argument, nullptr, OPTION_PATH},
        {nullptr,   no_argument,       nullptr, 0}
    };
    std::string option_path(".");
    Counter option_counter = COUNTER_CLASSIC;
    optind = 1;
    char * const *argv = cxt->argv->data();
    int argc = (int)cxt->argv->size();
    while (true)
    {
        int idx;
        int opt = getopt_long_only(argc, argv, "Po:v", long_options, &idx);
        if (opt < 0)
            break;
        switch (opt)
        {
            case OPTION_COUNTER:
                option_counter = parseCounter(optarg);
                break;
            case OPTION_OBLOCK:
                option_Oblock = parseOption(optarg);
                break;
            case OPTION_OSELECT:
                option_Oselect = parseOption(optarg);
                break;
            case OPTION_DEBUG:
                option_debug = OPTION_ALWAYS;
                break;
            case OPTION_PATH:
                option_path = optarg;
                break;
            default:
                error("invalid command-line options for %s", argv[0]);
        }
    }
    if (option_Oblock == OPTION_ALWAYS)
        warning("always removing AFL instrumentation for bad blocks; coverage "
            "may be incomplete");

    // Make seed depend on filename.
    unsigned seed = 0;
    const char *filename = getELFFilename(cxt->elf);
    for (int i = 0; filename[i] != '\0'; i++)
        seed = 101 * seed + (unsigned)filename[i];
    srand(seed);

    // Send the AFL instrumentation:
    //
    // Save state:
    //
    // lea -0x4000(%rsp),%rsp
    // push %rax
    // seto %al
    // lahf
    // push %rax
    //
    const int32_t stack_adjust = 0x4000;
    std::stringstream code;
    code << 0x48 << ',' << 0x8d << ',' << 0xa4 << ',' << 0x24 << ','
         << "{\"int32\":" << -stack_adjust << "},";
    code << 0x50 << ',';
    code << 0x0f << ',' << 0x90 << ',' << 0xc0 << ',';
    code << 0x9f << ',';
    code << 0x50 << ',';

    // AFL instrumentation:
    //
    // mov %gs:prev_loc,%eax                // mov prev_loc,%eax
    // xor $curr_loc,%eax
    // and %gs:mask,%eax
    // ...                                  // Increment hitcount
    // movl $curr_loc1,%gs:prev_loc         // mov (curr_loc>>1),prev_loc
    //
    int32_t offset = offsetof(INTERFACE, cov);
    code << 0x65 << ',' << 0x8b << ',' << 0x04 << ',' << 0x25 << ','
         << "{\"int32\":" << offset << "},";
    offset += sizeof(uint32_t);
    code << 0x35 << ',' << "\"$curr_loc\"" << ',';
    code << 0x65 << ',' << 0x23 << ',' << 0x04 << ',' << 0x25 << ','
         << "{\"int32\":" << offset << "},";
    offset += sizeof(uint32_t);
    switch (option_counter)
    {
        default:
        case COUNTER_CLASSIC:
            // incb %gs:map(%rax)
            code << 0x65 << ',' << 0xfe << ',' << 0x40 << ',' <<
                offset << ',';
            break;
        case COUNTER_NEVER_ZERO:
            // addb $0x1,%gs:map(%rax)
            // adcb $0x0,%gs:map(%rax)
            code << 0x65 << ',' << 0x80 << ',' << 0x40 << ',' << 
                offset << ',' << 0x01 << ',';
            code << 0x65 << ',' << 0x80 << ',' << 0x50 << ',' <<
                offset << ',' << 0x00 << ',';
            break;
        case COUNTER_SATURATED:
            // addb $0x1,%gs:map(%rax)
            // sbbb $0x0,%gs:map(%rax)
            code << 0x65 << ',' << 0x80 << ',' << 0x40 << ',' << 
                offset << ',' << 0x01 << ',';
            code << 0x65 << ',' << 0x80 << ',' << 0x58 << ',' <<
                offset << ',' << 0x00 << ',';
            break;
    }
    code << 0x65 << ',' << 0xc7 << ',' << 0x04 << ',' << 0x25 << ','
         << "{\"int32\":" << 0 << "}," << "\"$curr_loc_1\"" << ',';
 
    // Restore state:
    //
    // pop %rax
    // add $0x7f,%al
    // sahf
    // pop %rax  
    // lea 0x4000(%rsp),%rsp
    //
    code << 0x58 << ',';
    code << 0x04 << ',' << 0x7f << ',';
    code << 0x9e << ',';
    code << 0x58 << ',';
    code << 0x48 << ',' << 0x8d << ',' << 0xa4 << ',' << 0x24 << ','
         << "{\"int32\":" << stack_adjust << "},";
    code << "\".LEND\"";

    sendTrampolineMessage(cxt->out, "$afl", code.str().c_str());

    static const uint8_t enable[] =
    {
        // mov $SYS_enable,%eax
        // syscall
        // retq
        0xb8, 0x54, 0x01, 0x00, 0x00,
        0x0f, 0x05,
        0xc3
    };
    static const uint8_t disable[] =
    {
        // mov $SYS_disable,%eax
        // syscall
        // retq
        0xb8, 0x55, 0x01, 0x00, 0x00,
        0x0f, 0x05,
        0xc3
    };
    sendReserveMessage(cxt->out, 0x0, nullptr, 0x0, 0x0, 0x0, 0x0, 0x0, false,
        disable, sizeof(disable), enable, sizeof(enable));

    return nullptr;
}

/*
 * Normalize a block address.
 */
static intptr_t normalize(intptr_t addr, const Targets &targets)
{
    if (addr == BB_INDIRECT)
        return BB_INDIRECT;
    auto i = targets.lower_bound(addr);
    if (i == targets.end())
        return BB_INDIRECT;
    return i->first;
}

/*
 * Add a predecessor block.
 */
static void addPredecessor(intptr_t pred, intptr_t succ,
    const Targets &targets, CFG &cfg)
{
    pred = normalize(pred, targets);
    succ = normalize(succ, targets);
    auto j = cfg.find(succ);
    if (j == cfg.end())
    {
        BasicBlock empty;
        auto r = cfg.insert({succ, empty});
        j = r.first;
    }
    j->second.preds.push_back(pred);
}

/*
 * Add a successor block.
 */
static void addSuccessor(intptr_t pred, intptr_t succ,
    const Targets &targets, CFG &cfg)
{
    pred = normalize(pred, targets);
    succ = normalize(succ, targets);
    auto j = cfg.find(pred);
    if (j == cfg.end())
    {
        BasicBlock empty;
        auto r = cfg.insert({pred, empty});
        j = r.first;
    }
    j->second.succs.push_back(succ);
}

/*
 * Build the CFG from the set of jump targets.
 */
static void buildCFG(const ELF *elf, const Instr *Is, size_t size,
    const Targets &targets, CFG &cfg)
{
    for (const auto &entry: targets)
    {
        intptr_t target = entry.first, bb = target;
        TargetKind kind = entry.second;

        size_t i = findInstr(Is, size, target);
        if (i >= size)
            continue;

        BasicBlock empty;
        (void)cfg.insert({bb, empty});

        if ((kind & TARGET_INDIRECT) != 0)
            addPredecessor(BB_INDIRECT, bb, targets, cfg);

        const Instr *I = Is + i;

        for (++i; i < size; i++)
        {
            InstrInfo info0, *info = &info0;
            getInstrInfo(elf, I, info);
            bool end = false;
            intptr_t target = -1, next = -1;
            switch (info->mnemonic)
            {
                case MNEMONIC_RET:
                    end = true;
                    break;
                case MNEMONIC_JMP:
                    end = true;
                    // Fallthrough:
                case MNEMONIC_CALL:
                    if (info->op[0].type == OPTYPE_IMM)
                        target = (intptr_t)info->address +
                            (intptr_t)info->size + (intptr_t)info->op[0].imm;
                    break;
                case MNEMONIC_JO: case MNEMONIC_JNO: case MNEMONIC_JB:
                case MNEMONIC_JAE: case MNEMONIC_JE: case MNEMONIC_JNE:
                case MNEMONIC_JBE: case MNEMONIC_JA: case MNEMONIC_JS:
                case MNEMONIC_JNS: case MNEMONIC_JP: case MNEMONIC_JNP:
                case MNEMONIC_JL: case MNEMONIC_JGE: case MNEMONIC_JLE:
                case MNEMONIC_JG:
                    end = true;
                    next = (intptr_t)info->address + (intptr_t)info->size;
                    target = next + (intptr_t)info->op[0].imm;
                    break;
                default:
                    break;
            }
            if (target > 0x0)
                addPredecessor(bb, target, targets, cfg);
            if (next > 0x0)
                addPredecessor(bb, next, targets, cfg);
            if (end)
            {
                if (target > 0)
                    addSuccessor(bb, target, targets, cfg);
                if (next > 0)
                    addSuccessor(bb, next, targets, cfg);
                if (!(target > 0 || next > 0))
                    addSuccessor(bb, BB_INDIRECT, targets, cfg);
                break;
            }
            const Instr *J = I+1;
            if (I->address + I->size != J->address)
                break;
            if (targets.find(J->address) != targets.end())
            {
                // Fallthrough:
                addPredecessor(bb, J->address, targets, cfg);
                addSuccessor(bb, J->address, targets, cfg);
                break;
            }
            I = J;
        }
    }

    int id = 0;
    for (auto &entry: cfg)
        entry.second.id = id++;
}

/*
 * Attempt to optimize away a bad block.
 */
static void optimizeBlock(CFG &cfg, BasicBlock &bb);
static void optimizePaths(CFG &cfg, BasicBlock *pred_bb, BasicBlock *succ_bb,
    Paths &paths)
{
    auto i = paths.find(succ_bb);
    if (i != paths.end())
    {
        // Multiple paths to succ_bb;
        BasicBlock *unopt_bb = nullptr;
        if (pred_bb != nullptr)
            unopt_bb = pred_bb;
        else if (i->second != nullptr)
            unopt_bb = i->second;

        // Note: (unopt_bb == nullptr) can happen in degenerate cases, e.g.:
        // jne .Lnext; .Lnext: ...
        if (unopt_bb != nullptr)
        {
            unopt_bb->optimized = false;
            optimizeBlock(cfg, *unopt_bb);
        }
        return;
    }
    paths.insert({succ_bb, pred_bb});
    if (succ_bb == nullptr || !succ_bb->optimized)
        return;

    pred_bb = succ_bb;
    for (auto succ: succ_bb->succs)
    {
        auto i = cfg.find(succ);
        succ_bb = (i == cfg.end()? nullptr: &i->second);
        optimizePaths(cfg, pred_bb, succ_bb, paths);
    }
}
static void optimizeBlock(CFG &cfg, BasicBlock &bb)
{
    if (bb.optimized)
        return;
    Paths paths;
    for (auto succ: bb.succs)
    {
        auto i = cfg.find(succ);
        BasicBlock *succ_bb = (i == cfg.end()? nullptr: &i->second);
        optimizePaths(cfg, nullptr, succ_bb, paths);
    }
}

/*
 * Verify the optimization is correct (for debugging).
 */
static void verify(CFG &cfg, intptr_t curr, BasicBlock *bb,
    std::set<BasicBlock *> &seen)
{
    for (auto succ: bb->succs)
    {
        auto i = cfg.find(succ);
        BasicBlock *succ_bb = (i == cfg.end()? nullptr: &i->second);
        if (succ_bb == nullptr)
            fprintf(stderr, " BB_%d->indirect", bb->id);
        else
            fprintf(stderr, " BB_%d->BB_%d", bb->id,
                cfg.find(succ)->second.id);
        auto r = seen.insert(succ_bb);
        if (!r.second)
        {
            putc('\n', stderr);
            error("multiple non-instrumented paths detected");
        }
        if (succ_bb != nullptr && succ_bb->optimized)
            verify(cfg, succ, succ_bb, seen);
    }
}
static void verify(CFG &cfg)
{
    if (option_Oblock == OPTION_ALWAYS)
        return;
    putc('\n', stderr);
    for (auto &entry: cfg)
    {
        BasicBlock *bb = &entry.second;
        if (bb->optimized)
            continue;
        fprintf(stderr, "\33[32mVERIFY\33[0m BB_%d:",
            cfg.find(entry.first)->second.id);
        std::set<BasicBlock *> seen;
        verify(cfg, entry.first, bb, seen);
        putc('\n', stderr);
    }
    putc('\n', stderr);
}

/*
 * Calculate all instrumentation points.
 */
static void calcInstrumentPoints(const ELF *elf, const Instr *Is, size_t size,
    Targets &targets, std::set<intptr_t> &instrument)
{
    // Step #1: build the CFG:
    CFG cfg;
    buildCFG(elf, Is, size, targets, cfg);

    // Step #2: find all instrumentation-points/bad-blocks
    for (const auto &entry: targets)
    {
        intptr_t target = entry.first, bb = target;
        TargetKind kind = entry.second;

        size_t i = findInstr(Is, size, target);
        if (i >= size)
            continue;
        const Instr *I = Is + i;

        uint8_t target_size = I->size;
        for (++i; option_Oselect != OPTION_NEVER && i < size &&
                target_size < /*sizeof(jmpq)=*/5; i++)
        {
            InstrInfo info0, *info = &info0;
            getInstrInfo(elf, I, info);
            bool end = false;
            switch (info->mnemonic)
            {
                case MNEMONIC_RET:
                case MNEMONIC_CALL:
                case MNEMONIC_JMP:
                case MNEMONIC_JO: case MNEMONIC_JNO: case MNEMONIC_JB:
                case MNEMONIC_JAE: case MNEMONIC_JE: case MNEMONIC_JNE:
                case MNEMONIC_JBE: case MNEMONIC_JA: case MNEMONIC_JS:
                case MNEMONIC_JNS: case MNEMONIC_JP: case MNEMONIC_JNP:
                case MNEMONIC_JL: case MNEMONIC_JGE: case MNEMONIC_JLE:
                case MNEMONIC_JG:
                    end = true;
                    break;
                default:
                    break;
            }
            if (end)
                break;
            const Instr *J = I+1;
            if (I->address + I->size != J->address)
                break;
            if (targets.find(J->address) != targets.end())
                break;
            if (J->size > target_size)
            {
                target      = J->address;
                target_size = J->size;
            }
            I = J;
        }
        auto j = cfg.find(bb);
        assert(j != cfg.end());
        j->second.instrument = target;
        j->second.bad        = (target_size < /*sizeof(jmpq)=*/5);
        switch (option_Oblock)
        {
            case OPTION_NEVER:
                j->second.optimized = false;
                break;
            case OPTION_DEFAULT:
                // To be refined in Step #3
                j->second.optimized =
                    (j->second.bad && (kind & TARGET_INDIRECT) == 0);
                break;
            case OPTION_ALWAYS:
                j->second.optimized = j->second.bad;
                break;
        }
    }

    // Step #3: Optimize away bad blocks:
    if (option_Oblock == OPTION_DEFAULT)
        for (auto &entry: cfg)
            optimizeBlock(cfg, entry.second);

    // Step #4: Collect final instrumentation points.
    for (auto &entry: cfg)
    {
        if (!entry.second.optimized)
            instrument.insert(entry.second.instrument);
    }

    // Setp #5: Print debugging information (if necessary)
    for (size_t i = 0; (option_debug == OPTION_ALWAYS) && i < size; i++)
    {
        InstrInfo I0, *I = &I0;
        getInstrInfo(elf, Is + i, I);

        auto j = cfg.find(I->address);
        if (j != cfg.end())
        {
            fprintf(stderr, "\n# \33[32mBB_%d\33[0m%s%s\n", cfg[I->address].id,
                (j->second.bad? " [\33[31mBAD\33[0m]": ""),
                (j->second.bad && !j->second.optimized?
                    " [\33[31mUNOPTIMIZED\33[0m]": ""));
            fprintf(stderr, "# preds = ");
            int count = 0;
            for (auto pred: j->second.preds)
            {
                if (count++ != 0)
                    putc(',', stderr);
                if (pred == BB_INDIRECT)
                {
                    fprintf(stderr, "indirect");
                    continue;
                }
                auto l = cfg.find(pred);
                if (l != cfg.end())
                    fprintf(stderr, "BB_%u", l->second.id);
                else
                    fprintf(stderr, "%p", (void *)pred);
            }
            fprintf(stderr, "\n# succs = ");
            count = 0;
            for (auto succ: j->second.succs)
            {
                if (count++ != 0)
                    putc(',', stderr);
                if (succ == BB_INDIRECT)
                {
                    fprintf(stderr, "indirect");
                    continue;
                }
                auto l = cfg.find(succ);
                if (l != cfg.end())
                    fprintf(stderr, "BB_%u", l->second.id);
                else
                    fprintf(stderr, "%p", (void *)succ);
            }
            putc('\n', stderr);
        }
        if (instrument.find(I->address) != instrument.end())
            fprintf(stderr, "%lx: \33[33m%s\33[0m\n", I->address,
                I->string.instr);
        else
            fprintf(stderr, "%lx: %s\n", I->address, I->string.instr);
    }
    if (option_debug == OPTION_ALWAYS)
        verify(cfg);
}

/*
 * Events.
 */
extern void e9_plugin_event(const Context *cxt, Event event)
{
    switch (event)
    {
        case EVENT_DISASSEMBLY_COMPLETE:
        {
            Targets targets;
            buildTargets(cxt->elf, cxt->Is->data(), cxt->Is->size(), targets);
            calcInstrumentPoints(cxt->elf, cxt->Is->data(), cxt->Is->size(),
                targets, instrument);
            break;
        }
        default:
            break;
    }
}

/*
 * Matching.  Return `true' iff we should instrument this instruction.
 */
extern intptr_t e9_plugin_match(const Context *cxt)
{
    return (instrument.find(cxt->I->address) != instrument.end());
}

/*
 * Patch template.
 */
extern void e9_plugin_code(const Context *cxt)
{
    fputs("\"$afl\",", cxt->out);
}

/*
 * Patching.
 */
extern void e9_plugin_patch(const Context *cxt)
{
    if (instrument.find(cxt->I->address) == instrument.end())
        return;
    int32_t curr_loc = rand() % MAP_SIZE;
    fprintf(cxt->out, "\"$curr_loc\":{\"int32\":%d},", curr_loc);
    fprintf(cxt->out, "\"$curr_loc_1\":{\"int32\":%d},", curr_loc >> 1);
}

