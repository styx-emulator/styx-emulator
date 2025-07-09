import {
  EmulationArgs,
  ProgramIdentifierArgs,
  RawEventLimits,
  RawTraceArgs,
  SymbolSearchOptions,
  TraceAppSessionArgs
} from "src/generated/args_pb";
import { Program } from "src/generated/symbolic_pb";
import { EmulationState } from "src/generated/utils_pb";
import { TraceSession, TraceSessionState } from "src/generated/workspace_pb";
import { ITraceAppSessionArgs } from "./styx-idl.interface";
import { getEndianDesc } from "./trace.service";

export interface ITraceAppSessionArgsDisplay extends ITraceAppSessionArgs {
  modeDisplay: string;
  archDisplay: string;
  pidDisplay: string;
  id: number;

  msg: TraceAppSessionArgs;
  program: Program;
  session?: TraceSession;
}

export class TraceAppSessionArgsDisplay implements ITraceAppSessionArgsDisplay {
  msg: TraceAppSessionArgs;
  program: Program;

  constructor(msg: TraceAppSessionArgs, program: Program) {
    this.program = program;
    this.msg = msg;
  }
  public get id(): number {
    return this.msg.getId();
  }

  getId(): number {
    return this.msg.getId();
  }
  getMode(): TraceAppSessionArgs.TraceMode {
    return this.msg.getMode();
  }
  getSessionId(): string {
    return this.msg.getSessionId();
  }
  getResume(): boolean {
    return this.msg.getResume();
  }
  getPid(): ProgramIdentifierArgs | undefined {
    return this.msg.getPid();
  }
  hasPid(): boolean {
    return this.msg.hasPid();
  }
  getTraceFilepath(): string {
    return this.msg.getTraceFilepath();
  }
  getRawTraceArgs(): RawTraceArgs | undefined {
    return this.msg.getRawTraceArgs();
  }
  hasRawTraceArgs(): boolean {
    return this.msg.hasRawTraceArgs();
  }
  getEmulationArgs(): EmulationArgs | undefined {
    return this.msg.getEmulationArgs();
  }
  hasEmulationArgs(): boolean {
    return this.msg.hasEmulationArgs();
  }
  getLimits(): RawEventLimits | undefined {
    return this.msg.getLimits();
  }
  hasLimits(): boolean {
    return this.msg.hasLimits();
  }
  getSymbolOptions(): SymbolSearchOptions | undefined {
    return this.msg.getSymbolOptions();
  }
  hasSymbolOptions(): boolean {
    return this.msg.hasSymbolOptions();
  }

  public get archDisplay(): string {
    if (this.program.hasPid() && this.program.hasArchitecture()) {
      return (
        `${this.program.getArchitecture()?.getProcessor()} ` +
        `${this.program.getArchitecture()?.getBits()} ` +
        `${getEndianDesc(this.program.getArchitecture()?.getEndian())} `
      );
    } else {
      return "";
    }
  }

  public get pidDisplay(): string {
    if (this.msg.hasPid()) {
      const pid = <ProgramIdentifierArgs>this.msg.getPid();
      return pid.getName();
    } else {
      return "---";
    }
  }

  public get modeDisplay(): string {
    switch (this.msg.getMode()) {
      case TraceAppSessionArgs.TraceMode.RAW:
        return "RAW";
      case TraceAppSessionArgs.TraceMode.EMULATED:
        return "EMULATED";
      case TraceAppSessionArgs.TraceMode.SRB:
        return "SRB";
      default:
        return "";
    }
  }
}

export function traceAppSessionStateToString(state: TraceSessionState): string {
  switch (state) {
    case TraceSessionState.UNKNOWN:
      return "UNKNOWN";
    case TraceSessionState.ERROR:
      return "ERROR";
    case TraceSessionState.CREATING:
      return "CREATING";
    case TraceSessionState.CREATED:
      return "CREATED";
    case TraceSessionState.INITIALIZING:
      return "INITIALIZING";
    case TraceSessionState.INITIALIZED:
      return "INITIALIZED";
    case TraceSessionState.STARTING:
      return "STARTING";
    case TraceSessionState.RUNNING:
      return "RUNNING";
    case TraceSessionState.STOPPING:
      return "STOPPING";
    case TraceSessionState.STOPREQUESTRECEIVED:
      return "STOPREQUESTRECEIVED";
    case TraceSessionState.STOPPED:
      return "STOPPED";
    case TraceSessionState.PAUSED:
      return "PAUSED";
    case TraceSessionState.DROPPING:
      return "DROPPING";
    case TraceSessionState.DROPPED:
      return "DROPPED";
  }
}

export function traceAppSessionStateFromEmulationState(
  state: EmulationState
): TraceSessionState {
  switch (state) {
    case EmulationState.UNKNOWN:
      return TraceSessionState.UNKNOWN;
    case EmulationState.CREATING:
      return TraceSessionState.CREATING;
    case EmulationState.CREATED:
      return TraceSessionState.CREATED;
    case EmulationState.INITIALIZING:
      return TraceSessionState.INITIALIZING;
    case EmulationState.INITIALIZED:
      return TraceSessionState.INITIALIZED;
    case EmulationState.STARTING:
      return TraceSessionState.STARTING;
    case EmulationState.RUNNING:
      return TraceSessionState.RUNNING;
    case EmulationState.STOPPING:
      return TraceSessionState.STOPPING;
    case EmulationState.STOPPED:
      return TraceSessionState.STOPPED;
    case EmulationState.PAUSED:
      return TraceSessionState.PAUSED;
    case EmulationState.FINALIZING:
      return TraceSessionState.DROPPING;
    case EmulationState.KILLING:
      return TraceSessionState.DROPPING;
    case EmulationState.DROPPED:
      return TraceSessionState.DROPPED;
  }
  return TraceSessionState.UNKNOWN;
}
