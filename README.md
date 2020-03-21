InternalBlue
============

Several Broadcom/Cypress Bluetooth firmwares and their firmware
update mechanism have been reverse engineered. Based on that we developed a
Bluetooth experimentation framework which is able to patch the firmware and
therefore implement monitoring and injection tools for the lower layers of
the Bluetooth protocol stack.


Recent Changes
--------------
* We upgraded from Python 2 to Python 3. If you wrote your own scripts, this might break them. In this case, use
  the [python2](https://github.com/seemoo-lab/internalblue/releases/tag/python2) release.

* We reworked the *iOS* implementation.


Publications and Background
---------------------------

* **Master Thesis** (07/2018)
  
  *InternalBlue* was initially developed and documented in the
[Masterthesis](https://github.com/seemoo-lab/internalblue/raw/master/internalblue_thesis_dennis_mantz.pdf) by Dennis Mantz.
Afterwards the development was continued by SEEMOO. It was awarded with the [CAST Förderpreis](https://www.cysec.tu-darmstadt.de/cysec/start_news_details_136448.en.jsp).

* **MRMCD Talk** (09/2018)

  The basic framework for Nexus 5 / BCM4339 was presented at the MRMCD Conference
2018 in Darmstadt. The talk was also [recorded](https://media.ccc.de/v/2018-154-internalblue-a-deep-dive-into-bluetooth-controller-firmware) and includes an overview of the framework as well as
two demo usages at the end (Following a **Secure Simple Pairing procedure in
Wireshark** and implementing a **proof of concept for CVE-2018-5383**).


* **35C3 Talk** (12/2018)

  More extensions were [presented](https://media.ccc.de/v/35c3-9498-dissecting_broadcom_bluetooth) at 35C3 2018 in Leipzig. New features include 
creating connections to non-discoverable devices. Moreover, we gave a **demo of
CVE-2018-19860**, which can crash Bluetooth on several Broadcom chips. This talk
was also recorded and gives a more high level overview.

* **TROOPERS Talk** (03/2019)

* **WiSec Paper** (05/2019)

  Our WiSec paper [Inside Job: Diagnosing Bluetooth Lower Layers Using Off-the-Shelf Devices](https://arxiv.org/abs/1905.00634) on reversing the
  Broadcom Bluetooth diagnostics protocol was accepted, demonstrated and got the replicability label.

* **MobiSys Paper** (06/2019)

  Our MobiSys paper [InternalBlue - Bluetooth Binary Patching and Experimentation Framework
](https://arxiv.org/abs/1905.00631) on the complete *InternalBlue* ecosystem got accepted.


* **REcon Talk** (06/2019)

  We gave a talk at REcon, [Reversing and Exploiting Broadcom Bluetooth](https://cfp.recon.cx/reconmtl2019/talk/EQTRGU/).
  It provides a first intuition on how to do binary patching in C with Nexmon to change Bluetooth functionality.

* **MRMCD Talk** (09/2019)

  Our talk [Playing with Bluetooth](https://media.ccc.de/v/2019-185-playing-with-bluetooth) focuses on new device support
  within *InternalBlue* and the Patchram state of various devices.
  
* **36C3 Talk** (12/2019)
  
  The rather generic talk [All wireless communication stacks are equally broken](https://media.ccc.de/v/36c3-10531-all_wireless_communication_stacks_are_equally_broken)
  points out a couple of new research directions and new Bluetooth projects coming up.

* **EWSN Paper & Demo** (02/2020)

  We did some work on improving blacklisting performance of BLE data connections. Currently in a separate *blacklisting* branch.

* **CiderSecCon Talk** (03/2020)

  TROOPERS was canceled, but we did a stream of a talk that was recorded on [YouTube](https://www.youtube.com/watch?v=Nx2ZDLaJ1-0&t=4920).
  


Supported Features
------------------

This list is subject to change, but we give you a brief overview. You probably have a platform with a Broadcom chip that supports most features :)

On any Bluetooth chip:
* Send HCI commands
* Monitor HCI
* Establish connections

On any Broadcom Bluetooth chip:
* Read and write RAM
* Read and write assembly to RAM
* Read ROM
* Set defined breakpoints that crash on execution
* Inject arbitrary valid LMP messages (opcode and length must me standard compliant, contents and order are arbitrary)
* Use diagnostic features to monitor LMP and LCP (with new **Android** H4 driver patch, still needs to be integrated into BlueZ)
* Read AFH channel map

On selected Broadcom Bluetooth chips:
* Write to ROM via Patchram (any chip with defined firmware file >= build date 2012)
* Interpret core dumps (Nexus 5/6P, Samsung Galaxy S6, Evaluation Boards, Samsung Galaxy S10/S10e/S10+)
* Debug firmware with tracepoints (Nexus 5 and Evaluation Board CYW20735)
* Fuzz invalid LMP messages (Nexus 5 and Evaluation Board CYW20735)
* Inject LCP messages, including invalid messages (Nexus 5, Raspberry Pi 3/3+/4) 
* Full object and function symbol table (Cypress Evaluation Boards only)
* Demos for Nexus 5 only:
  * ECDH CVE-2018-5383 example
  * NiNo example
  * MAC address filter example
* KNOB attack test for various devices, including Raspberry Pi 3+/4
* BLE receptoin statistics

A comprehensive list of chips and which devices have them can be found in the [firmware](internalblue/fw/README.md) module documentation.




Requirements
------------

Android:
* Ideally recompiled `bluetooth.default.so`, but also works on any rooted smartphone, see [Android instructions](android_bluetooth_stack/README.md)
* Android device connected via ADB
* Best support is currently given for Nexus 5 / BCM4339
* Optional: Patch for Android driver to support Broadcom H4 forwarding
* Optional, if H4: Wireshark [Broadcom H4 Dissector Plugin](https://github.com/seemoo-lab/h4bcm_wireshark_dissector)

Linux:
* BlueZ, instructions see [here](linux_bluez/README.md)
* Best support for Raspberry Pi 3/3+/4 and Cypress evaluation boards
* For most commands: Privileged access

iOS:
* A jailbroken iOS device (tested on iOS 12 and 13 with iPhone 6, SE, 7, 8, X , does not work on iPhones newer than XR, these devices have a Bluetooth chip connected via PCIe)
* `usbmuxd`, which is pre installed on macOS but is available on most Linux distributions as well. Alternatively it can be obtained from [here](https://github.com/libimobiledevice/usbmuxd).
* The [``internalblued`` daemon](ios-internalblued/README.md) installed on the iOS device

* Optional, no jailbreak required: install [iOS Bluetooth Debug Profile](https://developer.apple.com/bug-reporting/profiles-and-logs/) to obtain
  HCI and diagnostic messages, either via diagnostic report feature (all iOS versions) or live with PacketLogger (since iOS 13)

macOS:
* Homebrew
* Xcode 10.2.1
* Instructions see [here](macos-framework/README.md)

Setup and Installation
----------------------

The framework uses __ADB__ (Android Debug Bridge) to connect to an Android
smartphone, __BlueZ__ sockets on Linux, or the included __iOS Proxy__ on iOS.

For [Android](android_bluetooth_stack) with ADB, either connect the phone via USB or setup ADB over TCP and make sure you
enable USB debugging in the developer settings of Android.

If you have a jailbroken [iOS](ios-proxy) device, you need to install a proxy that locally connects
to the Bluetooth device and forwards HCI commands and events.

On [Linux](linux_bluez) with *BlueZ*, everything should work out of the box, but
you need to execute *InternalBlue* as root for most features.

The InternalBlue framework is written in Python 2. You can install it together
with all dependencies by using pip:

    git clone https://github.com/seemoo-lab/internalblue.git
    cd internalblue
    pip install .

It will install the following dependencies:
* pwntools

The pwntools module needs the binutils package for ARM 32-bit to be installed
on the system. This has to be installed manually by using the packet manager
of your Linux distribution:

    # for Arch Linux
    sudo pacman -S arm-none-eabi-binutils

    # for Ubuntu
    sudo apt install binutils-arm-linux-gnueabi
    
All steps on a plain Ubuntu 18.04:

    sudo apt install git python-setuptools binutils-arm-linux-gnueabi adb pip python-dev gcc
    git clone https://github.com/seemoo-lab/internalblue
    cd internalblue
    sudo pip install .
    cd ..
    
    sudo apt-get install wireshark-dev wireshark cmake
    git clone https://github.com/seemoo-lab/h4bcm_wireshark_dissector
    cd h4bcm_wireshark_dissector
    mkdir build
    cd build
    cmake ..
    make
    make install

Packets required on a current (July 2019) Raspian:
     
     sudo apt-get --allow-releaseinfo-change update
     sudo apt-get install git python-setuptools binutils-arm-none-eabi adb python-pip python-dev gcc libffi-dev



Usage
-----

The CLI (Command Line Interface) of InternalBlue can be started by running:

    python -m internalblue.cli

The setup.py installation will also place a shortcut to the CLI into the $PATH
so that it can be started from a command line using:

    internalblue

It should automatically connect to your Android phone through ADB or your local Linux
with BlueZ. With BlueZ, some commands can be sent by unprivileged users (i.e. version
requests) and some commands require privileged users (i.e. establishing connections).
Use the *help* command to display a list of available commands. A typical set of
actions to check if everything is working properly would be:

    wireshark start
    connect ff:ff:13:37:ab:cd
    sendlmp 01 -d 02

Note that InternalBlue only displays 4 byte MAC addresses in some places. This is
because the leading two bytes are not required by Bluetooth communication, you
can replace them with anything you want.







License
-------

Copyright 2018-2020 The InternalBlue Team

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
