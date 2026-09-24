// FzwyHook.dll — inline hook module injected into WeChatAppEx.exe.
//
// Replaces the frida role in vendor/wmpf: puts the mini-program into debug mode,
// so WMPF's built-in remote debug client connects to our local port 9421.
//
// [Hard constraints]
//  1. No Qt — the target process has no Qt6Core.dll; LoadLibrary would fail.
//     Use only Win32 + standard library.
//  2. Must statically link the MinGW runtime (CMake -static), otherwise the
//     target process can't find libstdc++-6.dll / libgcc_s_seh-1.dll.
//  3. Don't do work in DllMain — heavy work under the loader lock will deadlock.
//     Spawn a thread and do it asynchronously.
//
// [Hook principle]
//   Overwrite the first N bytes of the target function with E9 rel32, jumping
//   to a nearby stub. The stub saves volatile registers -> calls C callback ->
//   replays the overwritten original instructions -> jumps back to target+N.
//
//   [History] onLeave was implemented two ways — rewriting the stack return address
//   (frida-style) and tail ret -> int3 + VEH — but WeChat enforces the CET hardware
//   shadow stack: on ret the CPU compares the normal and shadow stacks and raises
//   #CP(0xc0000409) on mismatch. Both crashed in testing, so all onLeave code was
//   removed; CDP filtering is bypassed on the C++ side instead (contextId enumeration,
//   see WmpfChannel).

#include <windows.h>
#include <tlhelp32.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <atomic>
#include <string>
#include <vector>

#include "../x64len.h"

namespace {

constexpr int kMaxDisplaced = 32;
constexpr int kPatchLen = 5;        // E9 rel32
constexpr int kMaxThreads = 256;

std::wstring g_logPath;
std::wstring g_dllDir;
std::wstring g_dllBaseName;   // own file name (without extension), used for naming the "unhook" event

// Set when unhook command received: don't install hooks (let new DLL take over)
volatile long g_disabled = 0;

void logLine(const char *fmt, ...) {
    if (g_logPath.empty())
        return;
    char msg[1024] = {};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    // Note: cannot mix wide/narrow output on the same FILE* (the stream becomes
    // wide-oriented, and narrow output is silently dropped). So we convert to
    // wide chars and write once with fwprintf.
    wchar_t wmsg[1024] = {};
    MultiByteToWideChar(CP_UTF8, 0, msg, -1, wmsg, 1024);
    FILE *f = _wfopen(g_logPath.c_str(), L"a, ccs=UTF-8");
    if (!f)
        return;
    SYSTEMTIME st{};
    GetLocalTime(&st);
    fwprintf(f, L"[%02d:%02d:%02d.%03d] %ls\n", st.wHour, st.wMinute, st.wSecond,
             st.wMilliseconds, wmsg);
    fclose(f);
}

struct StubBuilder {
    std::vector<uint8_t> b;
    void u8(uint8_t v) { b.push_back(v); }
    void u64(uint64_t v) {
        for (int i = 0; i < 8; ++i)
            b.push_back(uint8_t(v >> (8 * i)));
    }
    void movRaxImm64(uint64_t v) {
        u8(0x48);
        u8(0xB8);
        u64(v);
    }
    void movRcxImm64(uint64_t v) {
        u8(0x48);
        u8(0xB9);
        u64(v);
    }
    int size() const { return int(b.size()); }
};

struct Hook {
    std::string name;
    uint8_t *target = nullptr;
    int displacedLen = 0;
    int entryLen = 0;
    uint8_t saved[kMaxDisplaced] = {};
    uint8_t *stub = nullptr;
};

Hook *g_loadStartHook = nullptr;

// Scene ID whitelist (matches frida hook.js)
const int kSceneWhitelist[] = {1005, 1007, 1008, 1011, 1012, 1027, 1035, 1037,
                               1053, 1074, 1145, 1178, 1256, 1260, 1302, 1308};

struct SceneInfo {
    std::vector<int> offsets;  // 6-level pointer chain
    bool valid() const { return offsets.size() == 6; }
};
// Double buffer + atomic index: the reader (fzwyHookEnter) runs in trampoline context
// and must not allocate memory or take locks, so reinstall fills the inactive slot and
// then flips the index atomically. Slots are never freed, so a reader always sees a
// complete object — no window where a concurrent clear() is observed.
SceneInfo g_sceneBuf[2];
std::atomic<int> g_sceneActive{0};

volatile long g_enterCount = 0;
volatile long g_scenePatched = 0;
volatile long g_lastScene = -1;   // last read scene ID (-1 = not read)
volatile long g_chainStep = -1;   // which pointer-chain step failed; -1 = success
volatile long g_sceneHits = 0;

// MinGW doesn't support MSVC's __try/__except, so SEH exception guarding is unavailable.
// Instead, validate each level with VirtualQuery before accessing: a bad read at most
// yields a wrong value, without bringing an exception into WeChat's flow
// (writes additionally require the page to be writable).
bool memReadable(const void *p, size_t n) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!p || VirtualQuery(p, &mbi, sizeof(mbi)) == 0)
        return false;
    if (mbi.State != MEM_COMMIT)
        return false;
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
        return false;
    const DWORD ok = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ |
                     PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if ((mbi.Protect & ok) == 0)
        return false;
    // conservatively reject cross-page spans
    const size_t avail = mbi.RegionSize -
                         (reinterpret_cast<const uint8_t *>(p) -
                          reinterpret_cast<const uint8_t *>(mbi.BaseAddress));
    return avail >= n;
}

bool memWritable(const void *p, size_t n) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!p || VirtualQuery(p, &mbi, sizeof(mbi)) == 0)
        return false;
    if (mbi.State != MEM_COMMIT)
        return false;
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
        return false;
    const DWORD ok =
        PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if ((mbi.Protect & ok) == 0)
        return false;
    const size_t avail = mbi.RegionSize -
                         (reinterpret_cast<const uint8_t *>(p) -
                          reinterpret_cast<const uint8_t *>(mbi.BaseAddress));
    return avail >= n;
}

// extern "C" with a simple signature: the stub calls this via an imm64 absolute address.
extern "C" void fzwyHookEnter(void *ctx, uint64_t *rcxSlot, uint64_t *rdxSlot, uint64_t *retSlot) {
    auto *h = static_cast<Hook *>(ctx);
    if (!h)
        return;
    InterlockedIncrement(&g_enterCount);

    if (h == g_loadStartHook) {
        // Enable the debug flag: set the low byte of args[1] to 1.
        const uint64_t flag = *rdxSlot;
        if ((flag & 0xFF) != 1)
            *rdxSlot = (flag & ~uint64_t(0xFF)) | 1;

        // Follow the pointer chain to get the scene ID; if it matches the whitelist,
        // rewrite it to 1101 (= opened from devtools).
        //
        // Chain depth, matching hook.js:
        //   p = [this + o0]; p = [p + o1]; p = [p + o2]; p = [p + o3]; p = [p + o4];
        //   scene = *(int *)(p + o5)          <- last offset is "address-of", not "dereference"
        // 5 dereferences + 1 int read total. One extra dereference would read garbage.
        // Double-buffer read: atomic index load only — no locks, no allocation
        // (trampoline context).
        const SceneInfo &scene = g_sceneBuf[g_sceneActive.load(std::memory_order_acquire)];
        if (scene.valid()) {
            const uint8_t *p = reinterpret_cast<const uint8_t *>(*rcxSlot);
            bool ok = (p != nullptr);
            const int n = int(scene.offsets.size());
            int step = -1;
            for (int i = 0; ok && i < n - 1; ++i) {
                const uint8_t *slot = p + scene.offsets[i];
                if (!memReadable(slot, sizeof(void *))) {
                    ok = false;
                    step = i;
                    break;
                }
                p = *reinterpret_cast<const uint8_t *const *>(slot);
                if (!p) {
                    ok = false;
                    step = i;
                }
            }
            if (ok) {
                const uint8_t *scenePtr = p + scene.offsets[n - 1];
                if (memReadable(scenePtr, sizeof(int))) {
                    const int scene = *reinterpret_cast<const int *>(scenePtr);
                    g_lastScene = scene;
                    g_chainStep = -1;
                    InterlockedIncrement(&g_sceneHits);
                    if (memWritable(scenePtr, sizeof(int))) {
                        for (int s : kSceneWhitelist) {
                            if (scene == s) {
                                *const_cast<int *>(reinterpret_cast<const int *>(scenePtr)) = 1101;
                                InterlockedIncrement(&g_scenePatched);
                                break;
                            }
                        }
                    }
                } else {
                    g_chainStep = n - 1;
                }
            } else {
                g_chainStep = step;
            }
        }
    }
    (void)retSlot;  // onLeave removed as CET-infeasible (see file header); parameter kept so the stub layout is unchanged
}

bool buildStub(Hook *h) {
    const uint64_t target = reinterpret_cast<uint64_t>(h->target);
    const uint64_t enterFn = reinterpret_cast<uint64_t>(&fzwyHookEnter);

    // On entry, rsp ≡ 8 (mod 16) (caller's call pushed 8-byte return address)
    StubBuilder s;
    s.u8(0x9C);                                    // pushfq
    s.u8(0x50);                                    // push rax
    s.u8(0x51);                                    // push rcx
    s.u8(0x52);                                    // push rdx
    s.u8(0x41); s.u8(0x50);                        // push r8
    s.u8(0x41); s.u8(0x51);                        // push r9
    s.u8(0x48); s.u8(0x83); s.u8(0xEC); s.u8(0x08);  // sub rsp, 8   -> rsp ≡ 0
    // Slots (relative to current rsp): r9=+8 r8=+16 rdx=+24 rcx=+32 rax=+40 flags=+48 retaddr=+56
    s.movRcxImm64(reinterpret_cast<uint64_t>(h));
    s.u8(0x48); s.u8(0x8D); s.u8(0x54); s.u8(0x24); s.u8(0x20);  // lea rdx,[rsp+0x20] &rcx
    s.u8(0x4C); s.u8(0x8D); s.u8(0x44); s.u8(0x24); s.u8(0x18);  // lea r8, [rsp+0x18] &rdx
    s.u8(0x4C); s.u8(0x8D); s.u8(0x4C); s.u8(0x24); s.u8(0x38);  // lea r9, [rsp+0x38] &retaddr
    s.movRaxImm64(enterFn);
    s.u8(0xFF); s.u8(0xD0);                        // call rax
    s.u8(0x48); s.u8(0x83); s.u8(0xC4); s.u8(0x08);  // add rsp, 8
    s.u8(0x41); s.u8(0x59);                        // pop r9
    s.u8(0x41); s.u8(0x58);                        // pop r8
    s.u8(0x5A);                                    // pop rdx (callback may have modified it)
    s.u8(0x59);                                    // pop rcx
    s.u8(0x58);                                    // pop rax
    s.u8(0x9D);                                    // popfq
    // At this point rsp == function entry state; replay the overwritten original instructions
    for (int i = 0; i < h->displacedLen; ++i)
        s.u8(h->saved[i]);
    // jump back to target + displacedLen
    s.movRaxImm64(target + h->displacedLen);
    s.u8(0xFF); s.u8(0xE0);                        // jmp rax

    const int entryLen = s.size();

    // Allocate executable memory near the target (within rel32 range)
    const size_t need = size_t(entryLen) + 16;
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    uint8_t *mem = nullptr;
    for (uint64_t delta = 0; delta < 0x70000000ull && !mem; delta += si.dwAllocationGranularity) {
        for (int sign = 0; sign < 2 && !mem; ++sign) {
            uint64_t cand = sign ? target + delta : (target > delta ? target - delta : 0);
            if (!cand)
                continue;
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(cand), &mbi, sizeof(mbi)) == 0)
                continue;
            if (mbi.State != MEM_FREE || mbi.RegionSize < need)
                continue;
            mem = static_cast<uint8_t *>(VirtualAlloc(reinterpret_cast<LPVOID>(cand), need,
                                                      MEM_COMMIT | MEM_RESERVE,
                                                      PAGE_EXECUTE_READWRITE));
        }
    }
    if (!mem) {
        logLine("分配跳板失败：±1.75GB 内没有可用空闲区");
        return false;
    }
    h->stub = mem;
    h->entryLen = entryLen;
    memcpy(h->stub, s.b.data(), size_t(entryLen));

    const int64_t rel = int64_t(reinterpret_cast<uint64_t>(h->stub)) -
                        int64_t(target + kPatchLen);
    if (rel > INT32_MAX || rel < INT32_MIN) {
        logLine("跳板距离过远，rel32 放不下");
        VirtualFree(mem, 0, MEM_RELEASE);
        h->stub = nullptr;
        return false;
    }
    return true;  // actual entry patching is done in commitHook (that's when other threads are frozen)
}

// Suspend other threads when patching, to avoid a thread executing on the overwritten bytes
struct ThreadFreezer {
    std::vector<HANDLE> threads;
    void freeze() {
        // No heap allocation inside the freeze window: a suspended thread may hold the
        // CRT heap lock and malloc would deadlock the whole WeChat process — reserve
        // all capacity before suspending any thread.
        threads.reserve(kMaxThreads);
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return;
        const DWORD me = GetCurrentProcessId();
        const DWORD myTid = GetCurrentThreadId();
        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != me || te.th32ThreadID == myTid)
                    continue;
                // Check capacity before suspending: if SuspendThread succeeded with a full
                // vector, the thread would only be CloseHandle'd and never resumed —
                // permanently suspended, WeChat frozen.
                if (threads.size() >= kMaxThreads)
                    break;
                HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (!h)
                    continue;
                if (SuspendThread(h) != DWORD(-1))
                    threads.push_back(h);
                else
                    CloseHandle(h);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }
    void thaw() {
        for (HANDLE h : threads) {
            ResumeThread(h);
            CloseHandle(h);
        }
        threads.clear();
    }
};

// Read config: <dll directory>\FzwyHook.cfg
// Supports hooks=loadStart for phased enablement. cdpFilter= is still parsed for
// backward compatibility with existing cfg files (the CDP filter hook was removed).
bool readConfig(const std::wstring &path, std::wstring *module, uint64_t *loadStart,
                uint64_t *cdpFilter, std::vector<int> *scene, bool *doLoad) {
    FILE *f = _wfopen(path.c_str(), L"r, ccs=UTF-8");
    if (!f)
        return false;
    wchar_t line[512];
    while (fgetws(line, 512, f)) {
        std::wstring s(line);
        while (!s.empty() && (s.back() == L'\n' || s.back() == L'\r' || s.back() == L' '))
            s.pop_back();
        const size_t eq = s.find(L'=');
        if (eq == std::wstring::npos)
            continue;
        const std::wstring k = s.substr(0, eq);
        const std::wstring v = s.substr(eq + 1);
        if (k == L"module")
            *module = v;
        else if (k == L"loadStart")
            *loadStart = wcstoull(v.c_str(), nullptr, 16);
        else if (k == L"cdpFilter")
            *cdpFilter = wcstoull(v.c_str(), nullptr, 16);
        else if (k == L"hooks") {
            *doLoad = (v.find(L"loadStart") != std::wstring::npos);
        } else if (k == L"scene") {
            scene->clear();
            const wchar_t *p = v.c_str();
            while (*p) {
                wchar_t *end = nullptr;
                const long n = wcstol(p, &end, 10);
                if (end == p)
                    break;
                scene->push_back(int(n));
                p = end;
                if (*p == L',')
                    ++p;
            }
        }
    }
    fclose(f);
    return true;
}

// Prepare phase: decode prologue, generate and lay down the trampoline.
// **All memory allocation is done here** — when actually patching the entry, other threads
// are suspended, and a suspended thread may hold the heap lock; allocating during the
// freeze window would deadlock.
bool prepareHook(Hook *h) {
    if (!h->target) {
        logLine("%s：找不到目标函数", h->name.c_str());
        return false;
    }
    memcpy(h->saved, h->target, kMaxDisplaced);
    if (h->saved[0] == 0xE9) {
        logLine("%s：目标已被其它工具挂钩（首字节 E9），放弃", h->name.c_str());
        return false;
    }
    char why[256] = {};
    if (!x64_measure_displacement(h->saved, kMaxDisplaced, kPatchLen, &h->displacedLen, nullptr, why,
                                  sizeof(why))) {
        logLine("%s：序言不可搬移（%s），放弃", h->name.c_str(), why);
        return false;
    }
    return buildStub(h);
}

// Commit phase: suspend other threads -> patch bytes -> resume.
// Only does VirtualProtect / memcpy / FlushInstructionCache here; no memory allocation.
// Returns 0 on success, otherwise GetLastError(). Must NOT log on failure: logLine does
// CRT heap allocation, and a suspended thread may hold the heap lock -> deadlock.
// The caller records the error code and logs after thawing.
DWORD commitHook(Hook *h) {
    const int64_t rel =
        int64_t(reinterpret_cast<uint64_t>(h->stub)) - int64_t(reinterpret_cast<uint64_t>(h->target) + kPatchLen);
    uint8_t patch[kMaxDisplaced] = {};
    patch[0] = 0xE9;
    const int32_t rel32 = int32_t(rel);
    memcpy(patch + 1, &rel32, 4);
    for (int i = kPatchLen; i < h->displacedLen; ++i)
        patch[i] = 0x90;  // fill excess bytes with NOP (trampoline jumps to target+displacedLen; these bytes are dead zone)

    DWORD oldProt = 0;
    if (!VirtualProtect(h->target, size_t(h->displacedLen), PAGE_EXECUTE_READWRITE, &oldProt))
        return GetLastError();
    memcpy(h->target, patch, size_t(h->displacedLen));
    VirtualProtect(h->target, size_t(h->displacedLen), oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), h->target, size_t(h->displacedLen));
    return 0;
}

// Online unhook: restore the entry with saved original bytes, and deactivate.
// After restoration, the old trampoline remains executable (not freed), so threads
// currently executing it won't crash; new calls just no longer go through us.
// A subsequently injected new DLL version can then take over the same entry.
void unhookOne(Hook *h) {
    if (!h->target || h->displacedLen <= 0)
        return;
    // Same as the commit path: freeze other threads while overwriting entry bytes,
    // otherwise a thread may be executing right on the bytes being restored.
    // No logging inside the freeze window (logLine allocates; a suspended thread may
    // hold the heap lock) — record the error code and log after thawing.
    DWORD err = 0;
    {
        ThreadFreezer fz;
        fz.freeze();
        DWORD oldProt = 0;
        if (!VirtualProtect(h->target, size_t(h->displacedLen), PAGE_EXECUTE_READWRITE, &oldProt)) {
            err = GetLastError();
        } else {
            memcpy(h->target, h->saved, size_t(h->displacedLen));
            VirtualProtect(h->target, size_t(h->displacedLen), oldProt, &oldProt);
            FlushInstructionCache(GetCurrentProcess(), h->target, size_t(h->displacedLen));
        }
        fz.thaw();
    }
    if (err)
        logLine("%s：卸载时 VirtualProtect 失败 %lu", h->name.c_str(), err);
    else
        logLine("%s：已还原入口（卸载）", h->name.c_str());
}

void unhookAll() {
    if (g_loadStartHook)
        unhookOne(g_loadStartHook);
    g_disabled = 1;
}

// Is the E9 patch currently on the target entry our own (jumping to our own stub)?
// Used on reinstall: if so, the previous saved/displacedLen/stub must be kept as-is —
// re-running prepareHook would memcpy the E9 patch bytes into `saved` and then bail out
// on the E9 check, leaving saved = patch bytes and displacedLen == 0, after which
// unhookOne can never restore the original entry again.
bool isOurPatch(const Hook *h) {
    if (!h->target || !h->stub || h->displacedLen < kPatchLen)
        return false;
    if (h->target[0] != 0xE9)
        return false;
    int32_t rel = 0;
    memcpy(&rel, h->target + 1, sizeof(rel));
    return h->target + kPatchLen + rel == h->stub;
}

// Perform one installation. Can be called repeatedly (LoadLibrary on an already-loaded DLL
// doesn't re-run DllMain, so the injector triggers another round via a named event).
int doInstall() {
    if (g_disabled) {
        // Defensive path: the reinstall command normally clears g_disabled first (see
        // workerThread), so this should not be reached. Return non-zero — returning 0
        // would make signalReady falsely report success.
        logLine("已收到卸载命令，本次跳过安装");
        return 3;
    }
    const std::wstring &dir = g_dllDir;

    std::wstring module = L"flue.dll";
    uint64_t loadStart = 0, cdpFilter = 0;
    bool doLoad = true;
    // Double-buffer write: fill the inactive slot, then flip the index atomically
    // after parsing (readers run in trampoline context; see g_sceneBuf).
    const int sceneSlot = 1 - g_sceneActive.load(std::memory_order_relaxed);
    g_sceneBuf[sceneSlot].offsets.clear();
    if (!readConfig(dir + L"\\FzwyHook.cfg", &module, &loadStart, &cdpFilter,
                    &g_sceneBuf[sceneSlot].offsets, &doLoad)) {
        logLine("读不到 FzwyHook.cfg，放弃");
        return 1;
    }
    (void)cdpFilter;  // parsed only for old cfg compatibility; the CDP filter hook was removed
    g_sceneActive.store(sceneSlot, std::memory_order_release);
    logLine("配置：module=%ls loadStart=0x%llx scene=%zu 项 hooks=%s",
            module.c_str(), (unsigned long long)loadStart,
            g_sceneBuf[sceneSlot].offsets.size(), doLoad ? "loadStart" : "");

    // Wait for module to load (injection may happen before the module is ready)
    HMODULE mod = nullptr;
    for (int i = 0; i < 100 && !mod; ++i) {
        mod = (module == L"WeChatAppEx.exe") ? GetModuleHandleW(nullptr) : GetModuleHandleW(module.c_str());
        if (!mod)
            Sleep(100);
    }
    if (!mod) {
        logLine("模块 %ls 未加载，放弃", module.c_str());
        return 1;
    }
    const uint8_t *base = reinterpret_cast<const uint8_t *>(mod);
    logLine("模块基址 %p", base);

    static Hook hLoad;
    hLoad.name = "OnLoadStart";
    hLoad.target = const_cast<uint8_t *>(base + loadStart);
    // The SendToClientFilter (CDP filter) hook was removed entirely. WeChat enforces the
    // CET hardware shadow stack and both onLeave implementations crash (see file header):
    // return-address rewrite dies at the function's ret, tail int3 + VEH dies inside
    // ntdll, both #CP(0xc0000409) (verified). Instead we bypass on the C++ side: when
    // executionContextCreated is filtered out and contextId is unavailable, brute-force
    // enumerate small-integer contextIds to reach the AppService context (see WmpfChannel).
    g_loadStartHook = &hLoad;

    // Reinstall: if the entry still carries our own E9 patch, keep saved/displacedLen/stub
    // untouched and skip re-prepare (see isOurPatch) — only the config (offsets) is refreshed.
    // Otherwise reset fields left from the previous install (old trampolines from repeated
    // installs are leaked, not reclaimed — they may still be referenced).
    const bool loadIntact = doLoad && isOurPatch(&hLoad);
    if (!loadIntact) {
        hLoad.displacedLen = 0;
        hLoad.entryLen = 0;
        hLoad.stub = nullptr;
    }

    // First "prepare": decode, generate and lay down trampoline — all memory allocation done here
    const bool p1 = doLoad && (loadIntact || prepareHook(&hLoad));

    const auto dumpHex = [](const char *tag, const uint8_t *bytes, int len) {
        if (!bytes || len <= 0)
            return;
        char hex[3 * 200 + 1] = {};
        int n = 0;
        for (int i = 0; i < len && n < int(sizeof(hex)) - 4; ++i)
            n += snprintf(hex + n, sizeof(hex) - size_t(n), "%02X ", bytes[i]);
        logLine("  %s(%d)= %s", tag, len, hex);
    };
    if (p1 && !loadIntact) {
        dumpHex("OnLoadStart 原始序言", hLoad.saved, hLoad.displacedLen);
        dumpHex("OnLoadStart entry stub", hLoad.stub, hLoad.entryLen);
    }

    // Then "commit": only suspend other threads during the small window of entry byte patching.
    // No allocation during the freeze window (suspended threads may hold the heap lock) —
    // that includes logging: commitHook only returns an error code, we log after thawing.
    // An entry already carrying our own patch (loadIntact) needs no commit.
    bool ok1 = loadIntact;
    DWORD err1 = 0;
    if (p1 && !loadIntact) {
        ThreadFreezer fz;
        fz.freeze();
        err1 = commitHook(&hLoad);
        ok1 = (err1 == 0);
        fz.thaw();
    }
    if (err1)
        logLine("OnLoadStart：VirtualProtect 失败 %lu", err1);

    logLine("安装结果：OnLoadStart=%s(%d 字节)%s",
            ok1 ? "OK" : "失败", hLoad.displacedLen, loadIntact ? "（沿用现有 hook）" : "");
    if (ok1)
        logLine("  OnLoadStart stub=%p", hLoad.stub);
    const bool need1 = doLoad;
    return (ok1 == need1) ? 0 : 2;
}

void signalReady() {
    // Event name must include the DLL's own file name: multiple DLL versions may coexist in the
    // same process; after an old version is unhooked it still calls signalReady(), and if the
    // name were the same it would prematurely satisfy the injector's wait — resulting in
    // "reports success but the new version was never loaded".
    wchar_t evName[128];
    swprintf(evName, 128, L"FzwyHookReady_%lu_%ls", GetCurrentProcessId(), g_dllBaseName.c_str());
    HANDLE ev = OpenEventW(EVENT_MODIFY_STATE, FALSE, evName);
    if (ev) {
        SetEvent(ev);
        CloseHandle(ev);
    }
}

// Persistent thread: install once, then wait for the injector's "reinstall" command.
// Needed because when the DLL is already in the target process, LoadLibraryW only
// increments the ref count and doesn't re-run DllMain, so re-hooking must go through
// this command channel.
DWORD WINAPI workerThread(LPVOID self) {
    auto *hSelf = static_cast<HMODULE>(self);

    wchar_t dllPath[MAX_PATH] = {};
    GetModuleFileNameW(hSelf, dllPath, MAX_PATH);
    g_dllDir = dllPath;
    const size_t slash = g_dllDir.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        g_dllBaseName = g_dllDir.substr(slash + 1);
        g_dllDir = g_dllDir.substr(0, slash);
    }
    const size_t dot = g_dllBaseName.find_last_of(L'.');
    if (dot != std::wstring::npos)
        g_dllBaseName = g_dllBaseName.substr(0, dot);
    g_logPath = g_dllDir + L"\\FzwyHook.log";

    logLine("======== FzwyHook 载入 pid=%lu 名称=%ls ========", GetCurrentProcessId(),
            g_dllBaseName.c_str());

    // Both command events include the DLL's own file name: multiple versions may be loaded
    // sequentially in the same process; the injector must be able to command a specific version
    // precisely (otherwise an auto-reset event would be grabbed by a random waiting thread).
    wchar_t cmdName[128];
    swprintf(cmdName, 128, L"FzwyHookCmd_%lu_%ls", GetCurrentProcessId(), g_dllBaseName.c_str());
    HANDLE cmd = CreateEventW(nullptr, FALSE, FALSE, cmdName);
    wchar_t unhookName[128];
    swprintf(unhookName, 128, L"FzwyHookUnhook_%lu_%ls", GetCurrentProcessId(),
             g_dllBaseName.c_str());
    HANDLE unhookEv = CreateEventW(nullptr, FALSE, FALSE, unhookName);
    HANDLE waits[2] = {cmd, unhookEv};

    for (;;) {
        const int rc = doInstall();
        logLine("doInstall 返回 %d", rc);
        // Signal ready only on real success. The DLL stays resident in the target, so
        // signaling on failure/skip would make the injector falsely report "hook
        // installed" — after an unhook the tool would show success while nothing is hooked.
        if (rc == 0)
            signalReady();
        if (!cmd || !unhookEv)
            return DWORD(rc);
        // Loop waiting for commands, periodically report stats (the hook path does no I/O, to avoid slowing/hanging WeChat)
        long lastEnter = -1, lastScene = -1;
        for (;;) {
            const DWORD w = WaitForMultipleObjects(2, waits, FALSE, 2000);
            if (w == WAIT_OBJECT_0) {
                logLine("收到重新安装命令");
                // Clear the unhook lockout: the DLL is never FreeLibrary'd after unhook,
                // so the next tool start relies on this command to reinstall.
                g_disabled = 0;
                break;
            }
            if (w == WAIT_OBJECT_0 + 1) {
                logLine("收到卸载命令");
                unhookAll();
                continue;  // keep waiting; don't fall through to doInstall (g_disabled makes it a no-op)
            }
            const long e = g_enterCount, s = g_scenePatched;
            if (e != lastEnter || s != lastScene) {
                logLine("统计：OnLoadStart 进入 %ld 次；场景改写 %ld 次"
                        " | 最近场景号=%ld 读到 %ld 次 链失败步=%ld",
                        e, s, g_lastScene, g_sceneHits, g_chainStep);
                lastEnter = e;
                lastScene = s;
            }
        }
    }
}

}  // namespace

BOOL WINAPI DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        HANDLE t = CreateThread(nullptr, 0, workerThread, hModule, 0, nullptr);
        if (t)
            CloseHandle(t);
    }
    return TRUE;
}
