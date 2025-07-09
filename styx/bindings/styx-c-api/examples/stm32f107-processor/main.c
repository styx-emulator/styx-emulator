#include "stdio.h"
#include "styx_emulator.h"
#include <stdint.h>
#include <string.h>

#define TARGET_PGM                                                   \
  "../../../../../data/test-binaries/arm/stm32f107/bin/blink_flash/" \
  "blink_flash.bin"

void log_signal(StyxProcessorCore cpu)
{
  (void)cpu;
  // look at this: it prints
  uint64_t pc;
  StyxProcessorCore_pc(cpu, &pc);
  printf("Hit loop @ pc 0x%lX\n", pc);
}

void handle_error(StyxFFIError error)
{
  StyxFFIErrorMsg_t msg = StyxFFIErrorMsg(error);
  printf("uh oh: %s\n", msg);
  StyxFFIErrorMsg_free(msg);
}

int main(void)
{
  StyxFFIErrorPtr error = NULL;
  StyxProcessorBuilder builder = NULL;
  StyxExecutor executor = NULL;
  StyxPlugin procTracePlugin = NULL;
  StyxLoader loader = NULL;
  StyxProcessor proc = NULL;
  StyxEmulationReport report = NULL;

  // enable styx logging
  // Styx_init_logging(5, "trace");

  // create the builder
  if ((error = StyxProcessorBuilder_new(&builder)))
  {
    goto defer;
  }
  // set the executor
  if ((error = StyxExecutor_Executor_default(&executor)))
  {
    goto defer;
  }
  error = StyxProcessorBuilder_set_executor(builder, executor);
  executor = NULL;
  if (error)
  {
    goto defer;
  }
  if ((error = StyxProcessorBuilder_set_backend(builder, STYX_BACKEND_UNICORN)))
  {
    goto defer;
  }

  // set the loader
  if ((error = StyxLoader_RawLoader_new(&loader)))
  {
    goto defer;
  }
  error = StyxProcessorBuilder_set_loader(builder, loader);
  loader = NULL;
  if (error)
  {
    goto defer;
  }

  if ((error = StyxPlugin_ProcessorTracingPlugin_default(&procTracePlugin)))
  {
    goto defer;
  }
  error = StyxProcessorBuilder_add_plugin(builder, procTracePlugin);
  procTracePlugin = NULL;
  if (error)
  {
    goto defer;
  }

  // set the target program
  if ((error = StyxProcessorBuilder_set_target_program(
           builder, TARGET_PGM, (uint32_t)strlen(TARGET_PGM))))
  {
    goto defer;
  }

  // have the cpu use 16001 as the Ipc port
  if ((error = StyxProcessorBuilder_set_ipc_port(builder, 16001)))
  {
    goto defer;
  }

  // add a code hook just to test that hooks indeed work
  StyxHook_Code log_signal_hook = {
      .start = 0x590e,
      .end = 0x590e,
      .callback = log_signal,
  };
  if ((error = StyxProcessorBuilder_add_code_hook(builder, log_signal_hook)))
  {
    goto defer;
  }

  // build the processor
  printf("[*] building processor\n");
  if ((error =
           StyxProcessorBuilder_build(builder, STYX_TARGET_STM32F107, &proc)))
  {
    goto defer;
  }

  /// dispose the builder
  StyxProcessorBuilder_free(&builder);
  builder = NULL;

  // this runs the cpu (blocking)
  printf("[*] running processor\n");
  if ((error = StyxProcessor_start_blocking_constraints(proc, 1000, 1000, &report)))
  {
    goto defer;
  }
  printf("[*] processor stopped\n");

  int instructions = StyxEmulationReport_instructions(report);
  printf("[*] total instructions executed: %i\n", instructions);

defer:
  if (error)
  {
    handle_error(*error);
    StyxFFIErrorPtr_free(&error);
  }

  if (builder)
    StyxProcessorBuilder_free(&builder);
  if (executor)
    StyxExecutor_free(&executor);
  if (procTracePlugin)
    StyxPlugin_free(&procTracePlugin);
  if (loader)
    StyxLoader_free(&loader);
  if (proc)
    StyxProcessor_free(&proc);
  return 0;
}
