# fw_0x420e.py
#
# Generic firmware file in case we do not know something...
#
# Copyright (c) 2020 The InternalBlue Team. (MIT License)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
# - The Software is provided "as is", without warranty of any kind, express or
#   implied, including but not limited to the warranties of merchantability,
#   fitness for a particular purpose and noninfringement. In no event shall the
#   authors or copyright holders be liable for any claim, damages or other
#   liability, whether in an action of contract, tort or otherwise, arising from,
#   out of or in connection with the Software or the use or other dealings in the
#   Software.

from __future__ import absolute_import
from .fw import MemorySection, FirmwareDefinition
from .. import Address


class CYW20739B1(FirmwareDefinition):
    """
    CYW20719 is a Cypress evaluation board, the newest one that is currently available.

    Known issues:

    * `Launch_RAM` does not terminate and crashes the board.

      To get this working anyway:
      The `Launch_RAM` handler HCI callback is at `0x1AB218` and it can be overwritten with the
      address of the memory snippet you want to launch. For example, at `0x0x222500` there is some
      free memory. Put the function there. Then:

      internalblue.patchRom(0x1AB218, p32(ASM_LOCATION_RNG+1)):  # function table entries are sub+1

    """

    # Firmware Infos
    # Evaluation Kit CYW920719, which is also named CYW20739 internally, because they like fuzzy name definitions
    FW_NAME = "BCM89359"
    # TODO this is not the iPhone firmware, we need to add a switch in fw.py

    # Device Infos
    DEVICE_NAME = (
        0x280CD0  # rm_deviceLocalName, FIXME has no longer a length byte prepended
    )
    BD_ADDR = 0x00201df8  # rm_deviceBDAddr

    # Heap
    BLOC_HEAD = 0x0020061c  # g_dynamic_memory_GeneralUsePools
    BLOC_NG = True  # Next Generation Bloc Buffer

    # Memory Sections
    #                          start,    end,           is_rom? is_ram?
    SECTIONS = [
        MemorySection(0x00000000, 0xc9fff, False, True),  # Internal ROM
        MemorySection(0x000D0000, 0x000DFFFF, False, True),  # PatchRam
        # Internal Memory Cortex M3
        MemorySection(0x00200000, 0x0022FFFF, False, True),
        MemorySection(0x00300000, 0x003007ff, False, True),  # MMIO
        MemorySection(0x00310000, 0x00321fff, False, True),  # MMIO
        MemorySection(0x00326000, 0x0032ffff, False, True),  # MMIO
        MemorySection(0x00338000, 0x00367fff, False, True),  # MMIO
        MemorySection(0x00370000, 0x0037ffff, False, True),  # MMIO
        MemorySection(0x00390000, 0x00397fff, False, True),  # MMIO
        MemorySection(0x00410000, 0x00413fff, False, True),  # MMIO
        MemorySection(0x00420000, 0x00423fff, False, True),  # MMIO
        MemorySection(0x00600000, 0x006007ff, False, True),  # MMIO
        MemorySection(0x00640000, 0x006407ff, False, True),  # MMIO
        MemorySection(0x00650000, 0x006507ff, False, True),  # MMIO
        MemorySection(0x00651000, 0x006517ff, False, True),  # MMIO
        # ARM Private Peripheral busד
        MemorySection(0xE0000000, 0xE00FFFFF, False, True),

    ]

    # Patchram
    PATCHRAM_TARGET_TABLE_ADDRESS = Address(0x310000)
    PATCHRAM_ENABLED_BITMAP_ADDRESS = Address(0x00310304)
    PATCHRAM_VALUE_TABLE_ADDRESS = Address(0x000d0000)
    PATCHRAM_NUMBER_OF_SLOTS = 192
    PATCHRAM_ALIGNED = False
    # only seems to work 4-byte aligned here ...

    # Launch_RAM is faulty so we need to overwrite it. This is the position of the handler.
    LAUNCH_RAM = 0x000bbc80
    HCI_EVENT_COMPLETE = 0x000015d6

    # Connection Struct and Table
    CONNECTION_LIST_ADDRESS = 0x00221914  # pRm_whole_conn = 0x280C9C points to this
    CONNECTION_MAX = 11  # g_bt_max_connections = 0 in firmware
    CONNECTION_STRUCT_LENGTH = 0x168  # ??

    # Enable enhanced advertisement reports (bEnhancedAdvReport)
    ENHANCED_ADV_REPORT_ADDRESS = Address(0x00202e08)

    # Snippet for fuzzLmp()
    # execute standard SendLmpPdu HCI to fill parameters
    FUZZLMP_HOOK_ADDRESS = 0x00078c96

    # Assembler snippet for tracepoints
    # In contrast to the Nexus 5 patch, we uninstall ourselves automatically and use internal debug functions
    TRACEPOINT_BODY_ASM_LOCATION = 0x0022a000
    TRACEPOINT_HOOKS_LOCATION = 0x0022a200
    TRACEPOINT_HOOK_SIZE = 40
    TRACEPOINT_HOOK_ASM = """
            push {r0-r12, lr}       // save all registers on the stack (except sp and pc)
            ldr  r6, =0x%x          // addTracepoint() injects pc of original tracepoint here
            mov  r7, %d             // addTracepoint() injects the patchram slot of the hook patch
            bl   0x%x               // addTracepoint() injects TRACEPOINT_BODY_ASM_LOCATION here
            pop  {r0-r12, lr}       // restore registers
    
            // branch back to the original instruction
            b 0x%x                  // addTracepoint() injects the address of the tracepoint
    """

    TRACEPOINT_BODY_ASM_SNIPPET = """

            mov   r8, lr     // save link register in r8

            mov  r0, r7      // r7 still contains the patchram slot number
            bl   patch_uninstallPatchEntry     // disable_patchram_slot(slot)
    
            // dump registers like before
    
            // save status register in r5
            mrs  r5, cpsr
    
            // malloc HCI event buffer
            mov  r0, 0xff    // event code is 0xff (vendor specific HCI Event)
            mov  r1, 76      // buffer size: size of registers (68 bytes) + type and length + 'TRACE_'
            bl   0x186ca      // hci_allocateEventBlockWithLen(0xff, 78)
            mov  r4, r0      // save pointer to the buffer in r4
    
            // append our custom header (the word 'TRACE_') after the event code and event length field
            add  r0, 2            // write after the length field
            ldr  r1, =0x43415254  // 'TRAC'
            str  r1, [r0]
            add  r0, 4            // advance the pointer.
            ldr  r1, =0x5f45      // 'E_'
            strh r1, [r0]
            add  r0, 2            // advance the pointer. r0 now points to the start of the register values
    
            // store pc
            str  r6, [r0]    // r6 still contains the address of the original pc
            add  r0, 4       // advance the pointer.
    
            // store sp
            mov  r1, 56      // 14 saved registers * 4
            add  r1, sp
            str  r1, [r0]
            add  r0, 4       // advance the pointer.
    
            // store status register
            str  r5, [r0]
            add  r0, 4       // advance the pointer.
    
            // store other registers
            mov  r1, sp
            mov  r2, 56
            bl   0x95a88     // memcpy(dst, src, len)
    
            // send HCI buffer to the host
            mov  r0, r4      // r4 still points to the beginning of the HCI buffer
            bl   0x18696      // hci_sendEvent
            
            // restore status register
            msr  cpsr_f, r5
    
            // bl 0xc24       // bthci_event_vs_DBFW_CoreDumpRAMImageEvent
    
            mov  lr, r8      // restore lr from r8
            bx   lr          // return
    
    // Adapted implementaion of patch_uninstallPatchEntry(int slot):
    patch_uninstallPatchEntry:
            cmp        r0,#0xc0
            bcc        do_uninstallPatch
            b          data_patch_uninstallPatchEntry
    do_uninstallPatch:            
            mov.w      r2, #0x310000
            add        r2, #0x304
            lsrs       r1,r0,#0x5
            add.w      r1,r2,r1, lsl #0x2
            and        r0,r0,#0x1f
            ldr        r2,[r1,#0x0]
            movs       r3,#0x1
            lsls       r3,r0
            bics       r2,r3
            str        r2,[r1,#0x0]
            bx         lr

            
    data_patch_uninstallPatchEntry:

            sub.w      r1,r0,#0xc0
            lsls       r0,r0,#0x2
            sub.w      r0,r0,#0x300
            add.w      r0,r0,#0x310000
            movw       r2,#0xffff
            str.w      r2,[r0,#0x320]         

            push       {r4,lr}
            mov.w      r2, #0x310000
            add        r2, #0x31c
            ldr        r4,[r2,#0x0]                                 
            movs       r3,#0x1
            lsls       r3,r1
            bics       r4,r3
            str        r4,[r2,#0x0]                                 
            pop        {r4,pc}
    """
