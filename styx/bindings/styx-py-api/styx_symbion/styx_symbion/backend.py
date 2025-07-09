# BSD 2-Clause License
#
# Copyright (c) 2024, Styx Emulator Project
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
from styx_emulator.angr import StyxConcreteTargetBackend
from angr_targets.concrete import ConcreteTarget


class StyxConcreteTarget(ConcreteTarget):
    """
    A ConcreteTarget for use with interacting with the Styx Emulator!

    This is the primary entrypoint for use with Angr. !! Please note that this
    is an integration with Angr's Symbion feature (https://docs.angr.io/en/latest/advanced-topics/symbion.html).

    Due to Angr's limited support for external backends, synchronization of states between angr and styx is not
    handled by this target, meaning that synchronization has to be done by the user.
    """
    __backend: StyxConcreteTargetBackend

    def __init__(self, cpu, **kwargs):
        self.__backend = StyxConcreteTargetBackend(cpu, **kwargs)

    def read_memory(self, address, nbytes, **kwargs):
        """
        Reading from memory of the target

        :param int address: The address to read from
        :param int nbytes:  The amount number of bytes to read
        :return:        The memory read
        :rtype: bytes
        :raise angr.errors.ConcreteMemoryError:
        """
        return self.__backend.read_memory(address, nbytes, **kwargs)

    def write_memory(self, address, value, **kwargs):
        """
        Writing to memory of the target

        :param int address:   The address from where the memory-write should start
        :param str value:     The actual value written to memory
        :raise angr.errors.ConcreteMemoryError:
        """
        return self.__backend.write_memory(address, value, **kwargs)

    def read_register(self, register, **kwargs):
        """ "
        Reads a register from the target

        :param str register: The name of the register
        :return: int value of the register content
        :rtype int
        :raise angr.errors.ConcreteRegisterError: in case the register doesn't exist or any other exception
        """
        value = self.__backend.read_register(register, **kwargs)
        if register.lower() == "pc":
            return value + 1
        return value

    def write_register(self, register, value, **kwargs):
        """
        Writes a register to the target

        :param str register:     The name of the register
        :param int value:        int value written to be written register
        :raise angr.errors.ConcreteRegisterError:
        """
        return self.__backend.write_register(register, value, **kwargs)

    def read_all_registers(self):
        """
        Reads the entire register file from the concrete target

        This is primarily to facilitate state transitions and debugging interfaces
        Many targets have a batch register reading function to enable this, as a performance optimization

        :return: A dictionary mapping the string register name to its integer value
        """
        return self.__backend.read_all_registers()

    def write_all_registers(self, values):
        """
        Writes the entire register file to the concrete target

        :param values: A dictionary mapping the registers' names to their integer values
        :return:
        """
        return self.__backend.write_all_registers(values)

    def set_breakpoint(self, address, **kwargs):
        """
        Inserts a breakpoint

        :param int address: The address at which to set the breakpoint
        :param optional bool hardware: Hardware breakpoint
        :param optional bool temporary:  Tempory breakpoint
        :raise angr.errors.ConcreteBreakpointError:
        """
        return self.__backend.set_breakpoint(address, **kwargs)

    def remove_breakpoint(self, address, **kwargs):
        return self.__backend.remove_breakpoint(address, **kwargs)

    def set_watchpoint(self, address, **kwargs):
        """
        Inserts a watchpoint

        :param address: The name of a variable or an address to watch
        :param optional bool write:    Write watchpoint
        :param optional bool read:     Read watchpoint
        :raise angr.errors.ConcreteBreakpointError:
        """
        return self.__backend.set_watchpoint(address, **kwargs)

    def remove_watchpoint(self, address, **kwargs):
        return self.__backend.remove_watchpoint(address, **kwargs)

    def get_mappings(self):
        return self.__backend.get_mappings()

    def reset(self, halt=False):
        """
        Resets the target to its initial state.

        :param halt: Whether the target should be halted after the reset.
        :return:
        """
        return self.__backend.reset(halt=False)

    def step(self):
        """
        Tell the target to advance one 'step'
        Note that, unlike angr, concrete targets typically operate at the granularity of single instructions
        :return:
        """
        return self.__backend.step()

    def run(self):
        return self.__backend.run()

    def is_running(self):
        return self.__backend.is_running()

    def stop(self):
        return self.__backend.stop()

    def wait_for_running(self):
        """
        Block until the target is running
        :return:
        """
        # NOTE: This is a default implementation.  You should probably override it
        return self.__backend.wait_for_running()

    def wait_for_halt(self):
        """
        Block until the target is halted.
        :return:
        """
        # NOTE: This is a default implementation. Please override it
        return self.__backend.wait_for_halt()

    def wait_for_breakpoint(self, which=None):
        """

        :param which: integer address of the breakpoint to wait for
        :return:
        """
        # NOTE: We can't implement this by default since targets don't track their own breakpoints
        return self.__backend.wait_for_breakpoint(which=None)
