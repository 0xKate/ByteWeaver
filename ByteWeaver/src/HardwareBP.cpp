// Copyright(C) 2025 0xKate - MIT License
#include <HardwareBP.h>
#include <tlhelp32.h>

namespace ByteWeaver {

// ── Statics ──────────────────────────────────────────────────────────────────
std::atomic<uint8_t>                   HardwareBP::UsedSlots{ 0 };
std::mutex                             HardwareBP::BpMutex;
std::unordered_map<int, HardwareBP*> HardwareBP::ActiveBps;

// ── Slot allocation ───────────────────────────────────────────────────────────
int HardwareBP::AllocateDrSlot() {
    uint8_t slots = UsedSlots.load(std::memory_order_relaxed);
    for (int i = 0; i < 4; ++i) {
        if (!(slots & 1u << i)) {
            if (UsedSlots.compare_exchange_strong(slots,
                    static_cast<uint8_t>(slots | 1u << i),
                    std::memory_order_acq_rel))
                return i;
            i = -1; // lost the race, restart scan
            slots = UsedSlots.load(std::memory_order_relaxed);
        }
    }
    return -1;
}

void HardwareBP::FreeDrSlot(const int index) {
    if (index < 0 || index > 3) return;
    UsedSlots.fetch_and(
        static_cast<uint8_t>(~(1u << index)),
        std::memory_order_acq_rel);
}

// ── Thread enumeration ────────────────────────────────────────────────────────
// ReSharper disable twice CppLocalVariableMayBeConst
static void ForEachThread(const std::function<void(HANDLE)>& fn) {
    const DWORD pid = GetCurrentProcessId();
    const DWORD tid = GetCurrentThreadId();


    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te{ sizeof(THREADENTRY32) };
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            const bool isSelf = te.th32ThreadID == tid;
            HANDLE hThread = OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                (isSelf ? 0 : THREAD_SUSPEND_RESUME),
                FALSE, te.th32ThreadID);
            if (!hThread) continue;

            if (!isSelf) SuspendThread(hThread);
            fn(hThread);
            if (!isSelf) ResumeThread(hThread);

            CloseHandle(hThread);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

// ── VEH handler ───────────────────────────────────────────────────────────────
// ReSharper disable once CppParameterMayBeConstPtrOrRef
LONG WINAPI HardwareBP::VehHandler(EXCEPTION_POINTERS* ep) {
    if (const DWORD code = ep->ExceptionRecord->ExceptionCode; code != EXCEPTION_SINGLE_STEP && code != STATUS_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    CONTEXT* ctx = ep->ContextRecord;

    std::lock_guard lock(BpMutex);
    for (int i = 0; i < 4; ++i) {
        if (!(ctx->Dr6 & 1ull << i)) continue;

        auto it = ActiveBps.find(i);
        if (it == ActiveBps.end()) continue;

        ctx->Dr6 &= ~(1ull << i); // clear status bit

        if (it->second->m_callback)
            return it->second->m_callback(ctx, it->second->m_address);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// ── Per-thread arm/disarm ─────────────────────────────────────────────────────
// ReSharper disable once CppLocalVariableMayBeConst
// ReSharper disable once CppParameterMayBeConst
bool HardwareBP::EnableOnThread(HANDLE hThread) const {
    if (m_drIndex < 0 || m_drIndex > 3) return false;

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) return false;

    (&ctx.Dr0)[m_drIndex] = static_cast<decltype(ctx.Dr0)>(m_address);

    const int localEnableBit = m_drIndex * 2;
    const int conditionShift = 16 + m_drIndex * 4;
    const int lengthShift    = 18 + m_drIndex * 4;

    // Clear existing fields for this slot then write new ones
    ctx.Dr7 &= ~(
        1ull << localEnableBit    |
        0b11ull << conditionShift |
        0b11ull << lengthShift);

    ctx.Dr7 |= 1ull << localEnableBit;
    ctx.Dr7 |= static_cast<DWORD64>(m_condition) << conditionShift;
    ctx.Dr7 |= static_cast<DWORD64>(m_size)      << lengthShift;

    return SetThreadContext(hThread, &ctx) != FALSE;
}

// ReSharper disable once CppParameterMayBeConst
bool HardwareBP::DisableOnThread(HANDLE hThread) const {
    if (m_drIndex < 0 || m_drIndex > 3) return false;

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) return false;

    (&ctx.Dr0)[m_drIndex] = 0;

    const int localEnableBit = m_drIndex * 2;
    const int conditionShift = 16 + m_drIndex * 4;
    const int lengthShift    = 18 + m_drIndex * 4;

    ctx.Dr7 &= ~(
        1ull << localEnableBit    |
        0b11ull << conditionShift |
        0b11ull << lengthShift);

    return SetThreadContext(hThread, &ctx) != FALSE;
}

// ── Constructor / Destructor ──────────────────────────────────────────────────
HardwareBP::HardwareBP(const uintptr_t address,
                           const HardwareBPCondition condition,
                           HardwareBPCallback callback,
                           const HardwareBPSize size)
    : m_address(address)
    , m_condition(condition)
    , m_size(size)
    , m_callback(std::move(callback))
{}

HardwareBP::~HardwareBP() {
    if (m_enabled) Disable();
}

// ── Move semantics ────────────────────────────────────────────────────────────
HardwareBP::HardwareBP(HardwareBP&& other) noexcept
    : m_address(other.m_address)
    , m_condition(other.m_condition)
    , m_size(other.m_size)
    , m_callback(std::move(other.m_callback))
    , m_drIndex(other.m_drIndex)
    , m_enabled(other.m_enabled)
    , m_vehHandle(other.m_vehHandle)
{
    // Transfer dispatch table entry to this instance
    if (m_enabled) {
        std::lock_guard lock(BpMutex);
        ActiveBps[m_drIndex] = this;
    }
    // Neutralize the moved-from object so its destructor is a no-op
    other.m_drIndex   = -1;
    other.m_enabled   = false;
    other.m_vehHandle = nullptr;
}

HardwareBP& HardwareBP::operator=(HardwareBP&& other) noexcept {
    if (this == &other) return *this;
    if (m_enabled) Disable();

    m_address   = other.m_address;
    m_condition = other.m_condition;
    m_size      = other.m_size;
    m_callback  = std::move(other.m_callback);
    m_drIndex   = other.m_drIndex;
    m_enabled   = other.m_enabled;
    m_vehHandle = other.m_vehHandle;

    if (m_enabled) {
        std::lock_guard lock(BpMutex);
        ActiveBps[m_drIndex] = this;
    }

    other.m_drIndex   = -1;
    other.m_enabled   = false;
    other.m_vehHandle = nullptr;
    return *this;
}

// ── Enable / Disable ──────────────────────────────────────────────────────────
bool HardwareBP::Enable() {
    if (m_enabled) return false;

    m_drIndex = AllocateDrSlot();
    if (m_drIndex < 0) return false;

    m_vehHandle = AddVectoredExceptionHandler(1, VehHandler);
    if (!m_vehHandle) {
        FreeDrSlot(m_drIndex);
        m_drIndex = -1;
        return false;
    }

    {
        std::lock_guard lock(BpMutex);
        ActiveBps[m_drIndex] = this;
    }

    // ReSharper disable once CppParameterMayBeConst
    ForEachThread([this](HANDLE hThread) { EnableOnThread(hThread); });

    m_enabled = true;
    return true;
}

bool HardwareBP::Disable() {
    if (!m_enabled) return false;

    // ReSharper disable once CppParameterMayBeConst
    ForEachThread([this](HANDLE hThread) { DisableOnThread(hThread); });

    {
        std::lock_guard lock(BpMutex);
        ActiveBps.erase(m_drIndex);
    }

    RemoveVectoredExceptionHandler(m_vehHandle);
    m_vehHandle = nullptr;

    FreeDrSlot(m_drIndex);
    m_drIndex = -1;
    m_enabled = false;
    return true;
}

} // namespace ByteWeaver