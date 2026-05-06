// Copyright(C) 2025 0xKate - MIT License
#pragma once

#include <ByteWeaverPCH.h>

#include <functional>

namespace ByteWeaver {

  enum class HardwareBPCondition: uint8_t {
    Execute = 0b00,
      Write = 0b01,
      ReadWrite = 0b11,
  };

  /// Only meaningful for Write/ReadWrite conditions.
  enum class HardwareBPSize: uint8_t {
    Size1 = 0b00,
      Size2 = 0b01,
      Size8 = 0b10, // x64 only
      Size4 = 0b11,
  };

  using HardwareBPCallback = std:: function < LONG(CONTEXT * ctx, uintptr_t address) > ;

  class HardwareBP {
    public: HardwareBP(uintptr_t address,
      HardwareBPCondition condition,
      HardwareBPCallback callback,
      HardwareBPSize size = HardwareBPSize::Size1);
    ~HardwareBP();

    // Non-copyable, movable
    HardwareBP(const HardwareBP & ) = delete;
    HardwareBP & operator = (const HardwareBP & ) = delete;
    HardwareBP(HardwareBP && ) noexcept;
    HardwareBP & operator = (HardwareBP && ) noexcept;

    bool Enable();
    bool Disable();
    [
      [nodiscard]
    ] bool IsEnabled() const {
      return m_enabled;
    }

    bool EnableOnThread(HANDLE hThread) const;
    bool DisableOnThread(HANDLE hThread) const;

    [
      [nodiscard]
    ] int DrIndex() const {
      return m_drIndex;
    }
    [
      [nodiscard]
    ] uintptr_t Address() const {
      return m_address;
    }
    [
      [nodiscard]
    ] HardwareBPCondition Condition() const {
      return m_condition;
    }

    private: uintptr_t m_address;
    HardwareBPCondition m_condition;
    HardwareBPSize m_size;
    HardwareBPCallback m_callback;
    int m_drIndex = -1;
    bool m_enabled = false;
    PVOID m_vehHandle = nullptr;

    static int AllocateDrSlot();
    static void FreeDrSlot(int index);
    static std::atomic < uint8_t > UsedSlots;

    static LONG WINAPI VehHandler(EXCEPTION_POINTERS * ep);
    static std::mutex BpMutex;
    static std::unordered_map < int,
    HardwareBP * > ActiveBps;
  };

} // namespace ByteWeaver