Introduction

This HardwareLibs project is meant as an example for a simple printout on
Hello world on armclang

=====

Source Files

The following are descriptions of the source and header files contained in this
project:

hello.c

  This file is the where the main function located, and the printf function
  is written inside the main function

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
      export QUARTUS_ROOTDIR="C:/intelFPGA/20.1/quartus/"
3. Type "armds_ide &" at the SoC EDS Command Shell prompt to launch the DS
   Debugger.
4. In ARM DS, right click inside the Projects pane, select Import..., then
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
      "Altera-SoCFPGA-HelloWorld-Baremetal-ARMCC" and select "Build Project".

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
      "Altera-SoCFPGA-HelloWorld-Baremetal-ARMCC".
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
      "Altera-SoCFPGA-HelloWorld-Baremetal-ARMCC-Debug" and select
      "Connect to Target".
2. Load the examples
  2a. Run "load <path_to_Altera-SoCFPGA-HelloWorld-Baremetal-ARMCC.axf>"
  2b. Run command "run" in the Command tab to run the application
3. To avoid warnings, disconnect from the target before making changes to the code
   and rebuilding.
