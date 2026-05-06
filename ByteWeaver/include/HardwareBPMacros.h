// Copyright(C) 2025 0xKate - MIT License
#pragma once
#include <HardwareBP.h>

/// Execute breakpoint — fires when the CPU is about to execute the instruction at Address.
/// Size is always Size1 for execute.
#define INSTALL_HWBP_EXEC(Address, Callback)        \
ByteWeaver::HardwareBP(                         \
reinterpret_cast<uintptr_t>(Address),       \
ByteWeaver::HardwareBPCondition::Execute,   \
Callback)

/// Write watchpoint — fires when Size bytes at Address are written.
#define INSTALL_HWBP_WRITE(Address, Size, Callback) \
ByteWeaver::HardwareBP(                         \
reinterpret_cast<uintptr_t>(Address),       \
ByteWeaver::HardwareBPCondition::Write,     \
Callback,                                   \
ByteWeaver::HardwareBPSize::Size##Size)

/// Read/write watchpoint — fires on any access to Size bytes at Address.
#define INSTALL_HWBP_RW(Address, Size, Callback)    \
ByteWeaver::HardwareBP(                         \
reinterpret_cast<uintptr_t>(Address),       \
ByteWeaver::HardwareBPCondition::ReadWrite, \
Callback,                                   \
ByteWeaver::HardwareBPSize::Size##Size)