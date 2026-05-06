// Copyright(C) 2025 0xKate - MIT License
#include <HardwareBP.h>
#include <tlhelp32.h>

namespace ByteWeaver {

// ── Statics ───────────────────────────────────────────────────────────────────
std::atomic<uint8_t>                 HardwareBP::UsedSlots{ 0 };
std::mutex                           HardwareBP::BpMutex;
std::unordered_map<int, HardwareBP*> HardwareBP::ActiveBps;

// ── Helpers ───────────────────────────────────────────────────────────────────
static const char* ConditionName(const HardwareBPCondition c) {
    switch (c) {
        case HardwareBPCondition::Execute:   return "Execute";
        case HardwareBPCondition::Write:     return "Write";
        case HardwareBPCondition::ReadWrite: return "ReadWrite";
        default:                                         return "Unknown";
    }
}

static const char* SizeName(const HardwareBPSize s) {
    switch (s) {
        case HardwareBPSize::Size1: return "1";
        case HardwareBPSize::Size2: return "2";
        case HardwareBPSize::Size4: return "4";
        case HardwareBPSize::Size8: return "8";
        default:                                return "?";
    }
}

// ── Slot allocation ───────────────────────────────────────────────────────────
int HardwareBP::AllocateDrSlot() {
    uint8_t slots = UsedSlots.load(std::memory_order_relaxed);
    for (int i = 0; i < 4; ++i) {
        if (!(slots & (1u << i))) {
            if (UsedSlots.compare_exchange_strong(
                    slots,
                    static_cast<uint8_t>(slots | (1u << i)),
                    std::memory_order_acq_rel)) {
                Debug("[HardwareBP] Allocated DR slot %d (UsedSlots=0x%02X)", i, slots | (1u << i));
                return i;
            }
            // Lost the CAS race — reload and restart
            i = -1;
            slots = UsedSlots.load(std::memory_order_relaxed);
        }
    }
    Warn("[HardwareBP] All 4 DR slots are in use — cannot allocate");
    return -1;
}

void HardwareBP::FreeDrSlot(const int index) {
    if (index < 0 || index > 3) {
        Warn("[HardwareBP] FreeDrSlot: invalid index %d", index);
        return;
    }
    const uint8_t prev = UsedSlots.fetch_and(
        static_cast<uint8_t>(~(1u << index)),
        std::memory_order_acq_rel);
    Debug("[HardwareBP] Freed DR slot %d (UsedSlots: 0x%02X -> 0x%02X)",
                  index, prev, prev & ~(1u << index));
}

// ── Thread enumeration ────────────────────────────────────────────────────────
static void ForEachThread(const std::function<void(HANDLE)>& fn) {
    const DWORD pid = GetCurrentProcessId();
    const DWORD tid = GetCurrentThreadId();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        Warn("[HardwareBP] ForEachThread: CreateToolhelp32Snapshot failed (err=%lu)", GetLastError());
        return;
    }

    int visited = 0;
    THREADENTRY32 te{ sizeof(THREADENTRY32) };
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            const bool isSelf = (te.th32ThreadID == tid);
            const DWORD access = THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                 (isSelf ? 0u : THREAD_SUSPEND_RESUME);

            HANDLE hThread = OpenThread(access, FALSE, te.th32ThreadID);
            if (!hThread) {
                Warn("[HardwareBP] ForEachThread: OpenThread failed for TID=%lu (err=%lu)",
                             te.th32ThreadID, GetLastError());
                continue;
            }

            Debug("[HardwareBP] ForEachThread: visiting TID=%lu%s",
                          te.th32ThreadID, isSelf ? " (self)" : "");

            if (!isSelf) SuspendThread(hThread);
            fn(hThread);
            if (!isSelf) ResumeThread(hThread);

            CloseHandle(hThread);
            ++visited;
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    Debug("[HardwareBP] ForEachThread: visited %d thread(s)", visited);
}

// ── VEH handler ───────────────────────────────────────────────────────────────
LONG WINAPI HardwareBP::VehHandler(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP &&
        ep->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    CONTEXT* ctx = ep->ContextRecord;
    const HwbpDrWord dr6 = static_cast<HwbpDrWord>(ctx->Dr6);

    std::lock_guard lock(BpMutex);

    // TF re-arm step — no DR bits set, this is our single-step firing
    // after we let one instruction through. Re-enable all execute BPs.
    bool anyFired = false;
    for (int i = 0; i < 4; ++i)
        if (dr6 & (static_cast<HwbpDrWord>(1u) << i))
            anyFired = true;

    if (!anyFired) {
        for (auto& [index, bp] : ActiveBps) {
            if (bp->m_condition == HardwareBPCondition::Execute) {
                ctx->Dr7 |= (static_cast<HwbpDrWord>(1u) << (index * 2));
                //Debug("[HardwareBP] VEH: re-armed DR%d after TF step", index);
            }
        }
        ctx->EFlags &= ~0x100u;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // A DR slot fired — find which one and invoke its callback
    for (int i = 0; i < 4; ++i) {
        if (!(dr6 & (static_cast<HwbpDrWord>(1u) << i))) continue;

        auto it = ActiveBps.find(i);
        if (it == ActiveBps.end()) continue;

        ctx->Dr6 &= ~(static_cast<HwbpDrWord>(1u) << i);

        HardwareBP* bp = it->second;

        if (bp->m_callback)
            return bp->m_callback(ctx);
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// ── Per-thread arm ────────────────────────────────────────────────────────────
bool HardwareBP::EnableOnThread(HANDLE hThread) const {
    if (m_drIndex < 0 || m_drIndex > 3) {
        Warn("[HardwareBP] EnableOnThread: bad DR index %d", m_drIndex);
        return false;
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) {
        Warn("[HardwareBP] EnableOnThread: GetThreadContext failed (err=%lu)", GetLastError());
        return false;
    }

    // Write the watch address into the correct DRn register.
    // (&ctx.Dr0)[m_drIndex] works because Dr0-Dr3 are laid out contiguously
    // as native pointer-sized words in CONTEXT on both x86 and x64.
    (&ctx.Dr0)[m_drIndex] = static_cast<decltype(ctx.Dr0)>(m_address);

    // DR7 bit layout (per Intel SDM):
    //   Local enable : bit  (m_drIndex * 2)
    //   Condition R/W: bits (16 + m_drIndex * 4) .. (17 + m_drIndex * 4)
    //   Length LEN   : bits (18 + m_drIndex * 4) .. (19 + m_drIndex * 4)
    const int localEnableBit = m_drIndex * 2;
    const int conditionShift = 16 + m_drIndex * 4;
    const int lengthShift    = 18 + m_drIndex * 4;

    // Use arch-appropriate word width so we never promote to 64-bit on x86
    HwbpDrWord dr7 = static_cast<HwbpDrWord>(ctx.Dr7);

    // Clear the three fields for this slot
    dr7 &= ~(
        (static_cast<HwbpDrWord>(1u)    << localEnableBit) |
        (static_cast<HwbpDrWord>(0x3u)  << conditionShift) |
        (static_cast<HwbpDrWord>(0x3u)  << lengthShift));

    // Write new values
    dr7 |= (static_cast<HwbpDrWord>(1u)                        << localEnableBit);
    dr7 |= (static_cast<HwbpDrWord>(static_cast<uint8_t>(m_condition)) << conditionShift);
    dr7 |= (static_cast<HwbpDrWord>(static_cast<uint8_t>(m_size))      << lengthShift);

    ctx.Dr7 = static_cast<decltype(ctx.Dr7)>(dr7);

    Debug("[HardwareBP] EnableOnThread: DR%d=0x%p DR7=0x%08X cond=%s size=%s bytes",
                  m_drIndex,
                  reinterpret_cast<void*>(m_address),
                  static_cast<unsigned>(ctx.Dr7),
                  ConditionName(m_condition),
                  SizeName(m_size));

    if (!SetThreadContext(hThread, &ctx)) {
        if constexpr (BYTEWEAVER_ENABLE_BREAKPOINT_LOGGING)
        Warn("[HardwareBP] EnableOnThread: SetThreadContext failed (err=%lu)", GetLastError());
        return false;
    }
    return true;
}

// ── Per-thread disarm ─────────────────────────────────────────────────────────
bool HardwareBP::DisableOnThread(HANDLE hThread) const {
    if (m_drIndex < 0 || m_drIndex > 3) {
        Warn("[HardwareBP] DisableOnThread: bad DR index %d", m_drIndex);
        return false;
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) {
        Warn("[HardwareBP] DisableOnThread: GetThreadContext failed (err=%lu)", GetLastError());
        return false;
    }

    (&ctx.Dr0)[m_drIndex] = 0;

    const int localEnableBit = m_drIndex * 2;
    const int conditionShift = 16 + m_drIndex * 4;
    const int lengthShift    = 18 + m_drIndex * 4;

    HwbpDrWord dr7 = static_cast<HwbpDrWord>(ctx.Dr7);
    dr7 &= ~(
        (static_cast<HwbpDrWord>(1u)   << localEnableBit) |
        (static_cast<HwbpDrWord>(0x3u) << conditionShift) |
        (static_cast<HwbpDrWord>(0x3u) << lengthShift));
    ctx.Dr7 = static_cast<decltype(ctx.Dr7)>(dr7);

    if constexpr (BYTEWEAVER_ENABLE_BREAKPOINT_LOGGING)
        Debug("[HardwareBP] DisableOnThread: cleared DR%d, DR7=0x%08X",
                  m_drIndex, static_cast<unsigned>(ctx.Dr7));

    if (!SetThreadContext(hThread, &ctx)) {
        Warn("[HardwareBP] DisableOnThread: SetThreadContext failed (err=%lu)", GetLastError());
        return false;
    }
    return true;
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
{
    if constexpr (BYTEWEAVER_ENABLE_BREAKPOINT_LOGGING) {
    #if HWBP_64BIT
        Debug("[HardwareBP] Constructed (x64): address=0x%p cond=%s size=%s bytes",
                      reinterpret_cast<void*>(address), ConditionName(condition), SizeName(size));
    #else
        Debug("[HardwareBP] Constructed (x86): address=0x%p cond=%s size=%s bytes",
                      reinterpret_cast<void*>(address), ConditionName(condition), SizeName(size));
    #endif
    }

}

HardwareBP::~HardwareBP() {
    if (m_enabled) {
        if constexpr (BYTEWEAVER_ENABLE_BREAKPOINT_LOGGING)
            Debug("[HardwareBP] Destructor: auto-disabling DR%d for address 0x%p",
                          m_drIndex, reinterpret_cast<void*>(m_address));
        Disable();
    }
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
    if constexpr (BYTEWEAVER_ENABLE_BREAKPOINT_LOGGING)
        Debug("[HardwareBP] Move-constructed: transferring DR%d (address=0x%p)",
                      m_drIndex, reinterpret_cast<void*>(m_address));

    if (m_enabled) {
        std::lock_guard lock(BpMutex);
        ActiveBps[m_drIndex] = this;
    }
    other.m_drIndex   = -1;
    other.m_enabled   = false;
    other.m_vehHandle = nullptr;
}

HardwareBP& HardwareBP::operator=(HardwareBP&& other) noexcept {
    if (this == &other) return *this;

    if constexpr (BYTEWEAVER_ENABLE_BREAKPOINT_LOGGING)
        Debug("[HardwareBP] Move-assigned: releasing current DR%d, acquiring DR%d",
                      m_drIndex, other.m_drIndex);

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

// ── Enable ────────────────────────────────────────────────────────────────────
bool HardwareBP::Enable() {
    if (m_enabled) {
        Warn("[HardwareBP] Enable: already enabled on DR%d", m_drIndex);
        return false;
    }

#if !HWBP_64BIT
    if (m_size == HardwareBPSize::Size8) {
        Warn("[HardwareBP] Enable: Size8 is x64-only — ignoring on x86");
        return false;
    }
#endif

    m_drIndex = AllocateDrSlot();
    if (m_drIndex < 0) {
        Warn("[HardwareBP] Enable: no free DR slot");
        return false;
    }

    m_vehHandle = AddVectoredExceptionHandler(1, VehHandler);
    if (!m_vehHandle) {
        Warn("[HardwareBP] Enable: AddVectoredExceptionHandler failed (err=%lu)", GetLastError());
        FreeDrSlot(m_drIndex);
        m_drIndex = -1;
        return false;
    }

    {
        std::lock_guard lock(BpMutex);
        ActiveBps[m_drIndex] = this;
    }

    int successCount = 0;
    ForEachThread([this, &successCount](HANDLE hThread) {
        if (EnableOnThread(hThread)) ++successCount;
    });

    m_enabled = true;
    if constexpr (BYTEWEAVER_ENABLE_BREAKPOINT_LOGGING)
        Debug("[HardwareBP] Enabled: DR%d, address=0x%p, cond=%s, size=%s bytes, threads armed=%d",
                     m_drIndex,
                     reinterpret_cast<void*>(m_address),
                     ConditionName(m_condition),
                     SizeName(m_size),
                     successCount);

    return true;
}

// ── Disable ───────────────────────────────────────────────────────────────────
bool HardwareBP::Disable() {
    if (!m_enabled) {
        Warn("[HardwareBP] Disable: not currently enabled");
        return false;
    }

    int successCount = 0;
    ForEachThread([this, &successCount](HANDLE hThread) {
        if (DisableOnThread(hThread)) ++successCount;
    });

    {
        std::lock_guard lock(BpMutex);
        ActiveBps.erase(m_drIndex);
    }

    RemoveVectoredExceptionHandler(m_vehHandle);
    m_vehHandle = nullptr;

    Info("[HardwareBP] Disabled: DR%d, address=0x%p, threads disarmed=%d",
                 m_drIndex,
                 reinterpret_cast<void*>(m_address),
                 successCount);

    FreeDrSlot(m_drIndex);
    m_drIndex = -1;
    m_enabled = false;
    return true;
}

} // namespace ByteWeaver