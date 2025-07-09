Introduction

This HardwareLibs project is meant as an example for using the 16550 UART API.
This project uses a combination of the UART and interrupt API to construct a
rudimentary CLI application over the serial port. A simple memory dump
application is also implemented.

=====

Source Files

The following are descriptions of the source and header files contained in this
project:

alt_16550_buffer.{c,h}

  This file acts as a usermode circular buffer for the 16550 UART. It uses UART
  interrupts to continuously copy data out of the UART RX FIFO. It also buffers data
  to be sent to the UART and will continuously copy it out as the UART TX FIFO
  empties. It has added functionality to echo back characters read back on to
  the screen and to read groups of data ending in a new line in one batch.

alt_16550_prompt.{c,h}

  This file acts as a callback dispatch mechanism. Clients of this structure
  register keywords with an associated callback. Once a command is recognized,
  it dispatches that particular callback. A default callback is used to
  implement a prompt and a callback if no commands are recognized.

echo_prompt.{c,h}

  This is the echo prompt. It simply echoes back anything the user types.

main.c

  This file is the main glue for all the components. It initializes the
  interrupt API, UART API, buffers, and prompts. It then starts the default
  prompt, the launcher prompt.

launcher_prompt.{c,h}

  This is the launcher prompt which is used as the top level prompt. It can
  instantiate other prompts.

memory_prompt.{c,h}

  This is the memory prompt. It implements a simple memory dump application.

=====

Launching the DS Debugger

1. DS must be launched from the SoC EDS Command Shell in order to have all
   environment variables properly set up.  Launch the SoC EDS Command Shell
   in Windows by selecting Altera <version> -> SoC Embedded Design Suite ->
   SoC EDS <version> Command Shell. In Linux, run embedded_command_shell.sh
   found in the linux64 directory. (Do not source the .sh, simply type its
   name at the prompt.)
2. A version of Quartus Prime must be installed in order for the DS debugger
   to function properly with the USB Blaster. A free version can be
   downloaded from the Altera website.
  2a. After launching the SoC EDS Command Shell, type "echo $QUARTUS_ROOTDIR"
      at the prompt.  This should be set to the quartus subdirectory of an
      install of the Quartus Prime tool.  If it is instead set to a qprogrammer/
      subdirectory, please reset it by typing the following command:
      export QUARTUS_ROOTDIR=<path to quartus subdirectory>
      An example of what the path might look like is given below:
      export QUARTUS_ROOTDIR="C:/intelFPGA/20.1std/quartus/"
3. Type "armds_ide &" at the SoC EDS Command Shell prompt to launch the DS
   Debugger.
4. In Arm Development Studio IDE, right click inside the Projects pane, select Import..., then
   General -> Existing Projects into Workspace. Import the project as an
   archived file if it is still zipped and tarred, otherwise select the
   root directory it has be unzipped/untarred into.

=====

Building Example

Before running the example, the target executable first needs to be built.

1. In DS, build the application:
  1a. Switch to the C/C++ Perspective if not already in that perspective by
      selecting the menu: Window >> Open Perspective >> C/C++.
  1b. In the "Project Explorer" panel, right-mouse-click
      "Altera-SoCFPGA-HardwareLib-16550-CV-ARMCC" and select "Build Project".

The Console panel (bottom of the UI) should detail the progress of the build
and report any warnings or errors.

=====

System Setup

1. Connect the USB to serial bridge to the host computer.
2. Connect the USB-BlasterII to the host computer.
3. Install the USB to serial bridge driver on the host computer if that driver
   is not already present. Consult documentation for the DevKit for
   instructions on installing the USB to serial bridge driver.
4. Install the USB-BlasterII driver on the host computer if that driver is not
   already present. Consult documentation for QuartusII for instructions on
   installing the USB-BlasterII driver.
5. In DS, configure the launch configuration.
  5a. Select the menu: Run >> Debug Configurations...
  5b. In the options on the left, expand "DS Debugger" and select
      "Altera-SoCFPGA-HardwareLib-16550-CV-ARMCC-Debug".
  5c. In the "Connections" section near the bottom, click Browse.
  5d. Select the appropriate USB-BlasterII to use. Multiple items will be
      presented if there is more than one USB-BlasterII connection attached to
      the host computer. These selections might take a few seconds to load.
  5e. Click "Apply" then "OK" to apply the USB-BlasterII selection.
  5f. Click "Close" to close the Debug Configuration. Otherwise click "Debug"
      run the example in the debugger.
  5g. If a prompt appears asking if you'd like to change to the debug
      perspective, click yes.

=====

Running the Example

After building the example and setting up the host computer system, the example
can be run by following these steps.

1. Open a terminal session on the host computer to the serial port associated
   with the USB to serial bridge using a 8-N-1 configuration (8 databits per
   frame, no parity, and 1 stopbit) at 115200 baud. If using the PuTTY terminal
   application, select Terminal in the Category pane and check "Implicit CR in
   every LF" to ensure proper formatting to the terminal. While not strictly
   necessary, the terminal will allow for interaction with the CLI.
2. In DS, launch the debug configuration.
  2a. Switch to the Debug Perspective if not already in that perspective by
      selecting the menu: Window >> Open Perspective >> DS Debug.
  2b. In the "Debug Control" panel, right-mouse-click
      "Altera-SoCFPGA-HardwareLib-16550-CV-ARMCC-Debug" and select
      "Connect to Target".
3. Load the preloader, run the preloader to initialize the board
  2a. Load the preloader by running the command "loadfile <path_to_preloader>", and
      "restore <path_to_preloader_dtb> binary &_end" in the Commands tab
  2b. Set a hardware breakpoint at the point before preloader loads u-boot.img
      by running "thbreak spl_boot_device"
  2c. Set the debug entrypoint to preloader by running "set debug-from *$entrypoint"
  2d. Start running the preloader by typing "start", and then "continue" in the Commands
      tab
  2e. After the breakpoint has been hit, preloader have finished initializing the board
  2f. Discard the symbol file by running "discard-symbol-file <path_to_preloader>"
4. Load the examples
  3a. Run "load <path_to_application.axf>"
  3b. Run command "run" in the Command tab to run the application
5. To avoid warnings, disconnect from the target before making changes to the code
   and rebuilding.
