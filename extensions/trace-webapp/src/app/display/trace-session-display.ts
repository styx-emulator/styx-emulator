import {
  TraceSession,
  TraceSessionState
} from "../../../src/generated/workspace_pb";
import { TraceAppSessionArgs } from "../../generated/args_pb";
import { ProgramIdentifier } from "../../generated/symbolic_pb";
import {
  InitializeTraceRequest,
  MemoryChange
} from "../../generated/traceapp_pb";
import {
  TraceAppSessionArgsDisplay,
  traceAppSessionStateToString
} from "../styx-idl";

import { TraceRequestDisplay } from "./trace-request-display";

/**
 * UI Wrapper for
 *  TraceSession and TraceRequestDisplay:
 *    - TraceRequestDisplay wraps InitializeTraceRequest,
 *                                TraceAppSessionArgs,
 *                                TraceAppSessionArgs
 * that adds Stats, State, and other persistable UI properties
 */
export class TraceSessionDisplay {
  _id: number;

  _traceRequest: TraceRequestDisplay;
  _stats: TraceServiceStats;
  _state: TraceSessionState;
  _dbSession?: TraceSession;

  public errorString: string = "";
  public warningString: string = "";
  public emuStart = Date.now();
  public emuEnd = Date.now();
  public emuElapsed = 0;

  mergeLocalData(other: TraceSessionDisplay) {
    this._stats = other._stats;
    this._state = other._state;
    this.errorString = other.errorString;
    this.warningString = other.warningString;
    this.emuStart = other.emuStart;
    this.emuEnd = other.emuEnd;
    this.emuElapsed = other.emuElapsed;
  }

  // Constructor for TraceSessionDisplay
  constructor(id: number, r: TraceRequestDisplay, dbSession?: TraceSession) {
    this._id = id;
    this._traceRequest = r;
    this._stats = new TraceServiceStats();

    this._dbSession = dbSession;

    if (this._dbSession) {
      this._state = this._dbSession.getTsState();
      this._sessionID = this._dbSession.getSessionId();
    } else {
      this._state = TraceSessionState.CREATED;
    }
  }

  public get traceRequest(): TraceRequestDisplay {
    return this._traceRequest;
  }

  public get traceAppSessionArgsDisplay(): TraceAppSessionArgsDisplay {
    return this._traceRequest.traceAppSessionArgsDisplay;
  }

  public get traceAppSessionArgs(): TraceAppSessionArgs {
    return this._traceRequest.traceAppSessionArgs;
  }

  public get msgId(): number {
    return (<TraceAppSessionArgs>(
      this._traceRequest.startRequest.getArgs()
    )).getId();
  }

  public get cumInstPerSec(): number {
    return this._stats.cumInstPerSec;
  }

  public set cumInstPerSec(v: number) {
    this._stats.cumInstPerSec = v;
  }

  public get cumInstCount(): number {
    return this._stats.cumInstCount;
  }

  public set cumInstCount(v: number) {
    this._stats.cumInstCount = v;
  }

  public get program(): string {
    if (this._traceRequest.traceAppSessionArgs.getPid()?.getName()) {
      return (<ProgramIdentifier>(
        this._traceRequest.traceAppSessionArgs.getPid()
      )).getName();
    } else {
      return "";
    }
  }
  public get architectureDesc(): string {
    return this._traceRequest.traceAppSessionArgsDisplay.archDisplay;
  }

  public get initializable(): boolean {
    switch (this.state) {
      case TraceSessionState.UNKNOWN:
        return true;
      case TraceSessionState.CREATING:
        return true;
      case TraceSessionState.CREATED:
        return true;
      default:
        return false;
    }
  }

  public get startable(): boolean {
    switch (this.state) {
      case TraceSessionState.INITIALIZED:
      case TraceSessionState.STOPPED:
      case TraceSessionState.PAUSED:
        return true;
      default:
        return false;
    }
  }

  public get stoppable(): boolean {
    switch (this.state) {
      case TraceSessionState.RUNNING:
        return true;
      default:
        return false;
    }
  }

  public get pauseable(): boolean {
    return this.startable;
  }

  public get droppable(): boolean {
    return true;
  }

  public get modeName(): string {
    if (this.isEmulated) return "EMU";
    else if (this.isRaw) return "RAW";
    else return "UKN";
  }
  public get request(): InitializeTraceRequest {
    return this._traceRequest.startRequest;
  }

  public get isLocal(): boolean {
    return this._state == TraceSessionState.CREATED;
  }

  public get stateString(): string {
    return traceAppSessionStateToString(this._state);
  }

  public get state(): TraceSessionState {
    return this._state;
  }
  public set state(v: TraceSessionState) {
    this._state = v;
  }

  public get isRaw(): boolean {
    return (
      this.request.getArgs()?.getMode() == TraceAppSessionArgs.TraceMode.RAW
    );
  }
  public get isEmulated(): boolean {
    return (
      this.request.getArgs()?.getMode() ==
      TraceAppSessionArgs.TraceMode.EMULATED
    );
  }

  public get id(): number {
    return this._id;
  }
  public set id(v: number) {
    this._id = v;
  }

  public get stats(): TraceServiceStats {
    return this._stats;
  }

  private _sessionID: string = "";
  public get sessionID(): string {
    return this._sessionID;
  }
  public set sessionID(v: string) {
    this._sessionID = v;
  }

  addMemoryEvent(e: MemoryChange) {
    this._stats.memoryChangeEvents.push(e);
  }
}

export class TraceServiceStats {
  isrEnterCount: number = 0;
  isrExitCount: number = 0;
  insnCount: number = 0;
  memoryChangeCount: number = 0;
  setInsnNumber(insn: number) {
    if (insn > this.insnCount) {
      this.insnCount = insn;
    }
  }
  memoryChangeEvents: MemoryChange[] = [];
  watchList: MemoryChange[] = [];
  cumInstCount = 0;
  cumInstPerSec = 0;
}
