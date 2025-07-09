// SPDX-License-Identifier: BSD-2-Clause
import { Injectable } from "@angular/core";
import { Observable } from "rxjs";
import {
  RawEventLimits,
  RawTraceArgs,
  SymbolSearchOptions,
  TraceAppSessionArgs
} from "src/generated/args_pb";
import {
  GetJoinedTraceSessionsRequest,
  JoinedTraceSession,
  TraceSession
} from "src/generated/workspace_pb";

import { Program } from "src/generated/symbolic_pb";
import { InitializeTraceRequest } from "src/generated/traceapp_pb";

import { ServiceResponse } from "src/generated/utils_pb";
import { TraceRequestDisplay } from "../display/trace-request-display";
import { TraceSessionDisplay } from "../display/trace-session-display";
import {
  ITraceAppSessionArgsDisplay,
  TraceAppSessionArgsDisplay
} from "../styx-idl";
import { TraceService } from "../trace.service";

@Injectable({
  providedIn: "root"
})
export class SessionMgrService {
  _sessions = new Map<number, TraceSessionDisplay>();
  // _nextId: number = 0;
  _selectedId: number = -1;

  // Constructor
  constructor(private traceService: TraceService) {}

  public get sessions(): Map<number, TraceSessionDisplay> {
    return this._sessions;
  }
  getByLocalId(localId: number): TraceSessionDisplay | undefined {
    return this._sessions.get(localId);
  }

  upsertLocal(id: number, traceSessionDisplay: TraceSessionDisplay) {
    const existingSession = this._sessions.get(id);
    if (existingSession) {
      traceSessionDisplay.mergeLocalData(existingSession);
    }
    this._sessions.set(id, traceSessionDisplay);
  }

  drop(session: TraceSessionDisplay) {
    // delete from database
    const request = session._traceRequest.startRequest;
    if (request.hasArgs()) {
      const args = <TraceAppSessionArgs>request.getArgs();
      if (args.getId() > 0) {
        this.traceService.workspace
          .deleteTraceAppSessionArgsById(args.getId())
          .subscribe((response) => console.log(response));
      }
    }

    if (this._sessions.has(session.id)) {
      this._sessions.delete(session.id);
    }
  }

  public get sessionList(): TraceSessionDisplay[] {
    return Array.from(this._sessions.values());
  }

  public get selected(): TraceSessionDisplay | undefined {
    return this._selectedId == -1
      ? undefined
      : this._sessions.get(this._selectedId);
  }

  // create new TraceRequest from a TraceAppSessionArgs
  createTraceRequestDisplayFromSaved(
    savedArgs: TraceAppSessionArgs,
    savedProgram: Program,
    savedSession: TraceSession | undefined
  ): void {
    const traceRequestDisplay = new TraceRequestDisplay(
      new InitializeTraceRequest().setArgs(savedArgs),
      savedProgram
    );
    const sessionDisplay = new TraceSessionDisplay(
      traceRequestDisplay.traceAppSessionArgs.getId(),
      traceRequestDisplay,
      savedSession
    );
    this.upsertLocal(sessionDisplay.id, sessionDisplay);
  }

  // Save the request
  saveTraceRequest(
    traceRequest: TraceRequestDisplay
  ): Observable<TraceRequestDisplay> {
    console.info("Saving item: ", traceRequest);
    const request: InitializeTraceRequest = traceRequest.startRequest;
    if (!request.hasArgs()) {
      return new Observable<TraceRequestDisplay>((subscriber) => {
        subscriber.error("Malformed input: no args");
      });
    }
    // we only expect one message/result
    return new Observable<TraceRequestDisplay>((subscriber) => {
      const args = <TraceAppSessionArgs>request.getArgs();
      const program = traceRequest.program;
      this.traceService.workspace.upsertTraceAppSess([args]).subscribe({
        next: (serviceResponse) => {
          console.debug("Service Response: ", serviceResponse.toObject());
          const svcResult = serviceResponse.getResponsesList()[0];
          if (svcResult.getResult() == ServiceResponse.Result.ERR) {
            subscriber.error(svcResult.getMessage());
          } else {
            if (svcResult.getResult() == ServiceResponse.Result.WARN) {
              console.warn(svcResult.getMessage());
            }
            const savedItem = serviceResponse.getTraceAppSessionArgsList()[0];
            console.log("Saved item ", savedItem.toObject());
            // replace the original trace request
            request.setArgs(savedItem);
            const tr = new TraceRequestDisplay(request, program);
            const session = new TraceSessionDisplay(savedItem.getId(), tr);
            this.upsertLocal(session.id, session);
            subscriber.next(tr);
          }
        },
        error: (error) => {
          subscriber.error(error);
        },
        complete: () => {
          subscriber.complete();
        }
      });
    });
  }

  // Create TraceRequest from the provided args
  createTraceRequest(
    mode: TraceAppSessionArgs.TraceMode,
    trace_dir: string,
    trace_file: string,
    waitForTrace: boolean,
    symbol_search_options: SymbolSearchOptions.AsObject,
    program: Program
  ): TraceRequestDisplay {
    const request = new InitializeTraceRequest().setArgs(
      new TraceAppSessionArgs()
        .setMode(mode)
        .setRawTraceArgs(
          new RawTraceArgs()
            .setTraceDirectory(trace_dir)
            .setTraceWaitFile(waitForTrace)
        )
        .setTraceFilepath(trace_file)
        .setLimits(new RawEventLimits())
        .setSymbolOptions(
          new SymbolSearchOptions()
            .setRegexInclude(symbol_search_options.regexInclude)
            .setRegexExclude(symbol_search_options.regexExclude)
            .setMemWrites(symbol_search_options.memWrites)
            .setAnonReads(symbol_search_options.anonReads)
            .setAnonWrites(symbol_search_options.anonWrites)
        )
    );

    const tr = new TraceRequestDisplay(request, program);
    return tr;
  }

  /**
   * Get Trace Sessions (Observable<JoinedTraceSession[]>) from persistent data store.
   */
  public fetchJoinedTraceSessions(): Observable<JoinedTraceSession[]> {
    const items: JoinedTraceSession[] = [];
    const session$ = this.traceService.workspace.getJoinedTraceSessions(
      new GetJoinedTraceSessionsRequest()
    );

    return new Observable<JoinedTraceSession[]>((subsciber) => {
      session$.subscribe({
        next: (msg) => {
          items.push(msg);
        },
        error: (error) => {
          subsciber.error(error);
        },
        complete: () => {
          subsciber.next(items);
          subsciber.complete();
        }
      });
    });
  }

  /**
   * Fetch all TraceAppSessionArgs and Programs, return a merged Array
   * of ITraceAppSessionArgsDisplay
   * todo: replace this with fetchJoinedTraceSessions
   */
  public deprecatedFetchTraceAppSessionDisplays(): Observable<
    ITraceAppSessionArgsDisplay[]
  > {
    const new_items: ITraceAppSessionArgsDisplay[] = [];
    const fetchJoined: Observable<JoinedTraceSession[]> =
      this.fetchJoinedTraceSessions();
    return new Observable<ITraceAppSessionArgsDisplay[]>((subsciber) => {
      fetchJoined.subscribe({
        next: (value) => {
          for (const item of value) {
            new_items.push(
              new TraceAppSessionArgsDisplay(
                <TraceAppSessionArgs>item.getArgs(),
                <Program>item.getProgram()
              )
            );
          }
        },
        complete: () => {
          console.log(new_items);
          subsciber.next(new_items);
          subsciber.complete();
        }
      });
    });
  }
}
