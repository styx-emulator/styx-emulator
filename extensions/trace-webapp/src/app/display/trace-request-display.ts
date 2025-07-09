import {
  EmulationArgs,
  ProgramIdentifierArgs,
  TraceAppSessionArgs
} from "../../../src/generated/args_pb";
import { Program } from "../../../src/generated/symbolic_pb";
import { InitializeTraceRequest } from "../../../src/generated/traceapp_pb";

import { TraceAppSessionArgsDisplay } from "../styx-idl";

export interface Validator {
  validate(): boolean;
}

// We expect these to not fail due to optional protobuf fields, as long as
// the Request has been validated.
export interface ValidTraceRequest {
  modeDescription: string;
}

/**
 * UI Wrapper for:
 *  InitializeTraceRequest: the original request
 *  TraceAppSessionArgs: the original args
 *  Program: the original program
 */
export class TraceRequestDisplay implements ValidTraceRequest {
  startRequest: InitializeTraceRequest;
  program: Program;
  traceAppSessionArgs: TraceAppSessionArgs;
  traceAppSessionArgsDisplay: TraceAppSessionArgsDisplay;

  public set pid(v: ProgramIdentifierArgs) {
    this.startRequest.getArgs()?.setPid(v);
  }
  public set emulation_args(v: EmulationArgs) {
    this.startRequest.getArgs()?.setEmulationArgs(v);
  }
  public set ws_program_id(v: number) {
    this.startRequest.getArgs()?.setWsProgramId(v);
  }
  public get ws_program_id(): number | undefined {
    return this.startRequest.getArgs()?.getWsProgramId();
  }

  // Constructor
  constructor(request: InitializeTraceRequest, program: Program) {
    this.startRequest = request;
    this.program = program;
    this.traceAppSessionArgs =
      this.startRequest.getArgs() as TraceAppSessionArgs;
    this.traceAppSessionArgsDisplay = new TraceAppSessionArgsDisplay(
      this.traceAppSessionArgs,
      this.program
    );
  }

  public get modeDescription(): string {
    if (
      this.traceAppSessionArgs.getMode() ==
      TraceAppSessionArgs.TraceMode.EMULATED
    ) {
      return `New emulation using ${this.traceAppSessionArgs.getPid()?.getName()} `;
    } else if (
      this.startRequest.getArgs()?.getMode() ==
      TraceAppSessionArgs.TraceMode.RAW
    ) {
      return (
        `Trace raw file: ${this.traceAppSessionArgs.getTraceFilepath()} ` +
        `emitted by ${this.traceAppSessionArgs.getPid()?.getName()}`
      );
    } else {
      return "Expand to select inputs";
    }
  }

  validate(): boolean {
    if (!this.startRequest.getArgs()) return false;
    if (!this.startRequest.getArgs()?.getPid()) return false;
    const mode = this.startRequest.getArgs()?.getMode();
    if (mode == undefined) return false;

    if (mode == TraceAppSessionArgs.TraceMode.SRB) {
      throw Error("TraceMode.SRB is not supported yet");
    } else if (mode == TraceAppSessionArgs.TraceMode.RAW) {
      const rawTraceArgs = this.startRequest.getArgs()?.getRawTraceArgs();
      if (!rawTraceArgs) return false;
      return true;
    } else if (mode == TraceAppSessionArgs.TraceMode.EMULATED) {
      const emulationArgs = this.startRequest.getArgs()?.getEmulationArgs();
      if (!emulationArgs) return false;
      return true;
    }
    return false;
  }
}
