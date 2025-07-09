Introduction

This HardwareLibs project is meant as an example for using the Timer
API. This project uses a combination of the Timer, Interrupt, and GPIO API to
trigger an interrupt at a fixed interval and blink the LEDs attached to the
GPIO interface.

=====

Source Files

The following are descriptions of the source and header files contained in this
project:

main.c

  This file is the main glue for all the components. It initializes the
  interrupt system, GPIO system, and starts the timer to fire at a fixed
  interval. When the timer interrupt fires, it toggles the LEDs attached to the
  GPIO interface in grey code order. After a few interrupts are fired,
  everything is cleaned up in reverse order.

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
      "Altera-SoCFPGA-HardwareLib-Timer-CV-ARMCC" and select "Build Project".

The Console panel (bottom of the UI) should detail the progress of the build
and report any warnings or errors.

=====

System Setup

1. Connect the USB-BlasterII to the host computer.
2. Install the USB-BlasterII driver on the host computer if that driver is not
   already present. Consult documentation for QuartusII for instructions on
   installing the USB-BlasterII driver.
3. In DS, configure the launch configuration.
  3a. Select the menu: Run >> Debug Configurations...
  3b. In the options on the left, expand "DS Debugger" and select
      "Altera-SoCFPGA-HardwareLib-Timer-CV-ARMCC-Debug".
  3c. In the "Connections" section near the bottom, click Browse.
  3d. Select the appropriate USB-BlasterII to use. Multiple items will be
      presented if there is more than one USB-BlasterII connection attached to
      the host computer. These selections might take a few seconds to load.
  3e. Click "Apply" then "OK" to apply the USB-BlasterII selection.
  3f. Click "Close" to close the Debug Configuration. Otherwise click "Debug"
      run the example in the debugger.
  3g. If a prompt appears asking if you'd like to change to the debug
      perspective, click yes.

=====

Running the Example

After building the example and setting up the host computer system, the example
can be run by following these steps.

1. In DS, launch the debug configuration.
  1a. Switch to the Debug Perspective if not already in that perspective by
      selecting the menu: Window >> Open Perspective >> DS Debug.
  1b. In the "Debug Control" panel, right-mouse-click
      "Altera-SoCFPGA-HardwareLib-Timer-CV-ARMCC-Debug" and select
      "Connect to Target".
2. Load the preloader, run the preloader to initialize the board
  2a. Load the preloader by running the command "loadfile <path_to_preloader>", and
      "restore <path_to_preloader_dtb> binary &_end" in the Commands tab
  2b. Set a hardware breakpoint at the point before preloader loads u-boot.img
      by running "thbreak spl_boot_device"
  2c. Set the debug entrypoint to preloader by running "set debug-from *$entrypoint"
  2d. Start running the preloader by typing "start", and then "continue" in the Commands
      tab
  2e. After the breakpoint has been hit, preloader have finished initializing the board
  2f. Discard the symbol file by running "discard-symbol-file <path_to_preloader>"
3. Load the examples
  3a. Run "load <path_to_application.axf>"
  3b. Run command "run" in the Command tab to run the application
4. To avoid warnings, disconnect from the target before making changes to the code
   and rebuilding.
