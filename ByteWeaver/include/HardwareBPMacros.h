// Copyright(C) 2025 0xKate - MIT License
#pragma once
#include <HardwareBP.h>

/// Execute breakpoint — fires when the CPU is about to execute the instruction at Address.
/// Size is always Size1 for execute; specifying it would be meaningless.
#define INSTALL_HWBP_EXEC(Address, Callback) \
ByteWeaver::HwBreakpoint(        \
reinterpret_cast<uintptr_t>(Address), \
ByteWeaver::HwBpCondition::Execute,   \
Callback)

/// Write watchpoint — fires when Size bytes at Address are written.
#define INSTALL_HWBP_WRITE(Address, Size, Callback) \
ByteWeaver::HwBreakpoint(               \
reinterpret_cast<uintptr_t>(Address),  \
ByteWeaver::HwBpCondition::Write,      \
Callback,                              \
ByteWeaver::HwBpSize::Size##Size)

/// Read/write watchpoint — fires on any access to Size bytes at Address.
#define INSTALL_HWBP_RW(Address, Size, Callback)    \
ByteWeaver::HwBreakpoint(               \
reinterpret_cast<uintptr_t>(Address),  \
ByteWeaver::HwBpCondition::ReadWrite,  \
Callback,                              \
ByteWeaver::HwBpSize::Size##Size)