// SPDX-License-Identifier: BSD-2-Clause
import {
  AfterViewInit,
  Component,
  ElementRef,
  EventEmitter,
  OnChanges,
  OnInit,
  Output,
  SimpleChanges,
  ViewChild
} from "@angular/core";
import { ActivatedRoute, Router } from "@angular/router";
import {
  AppSession,
  SessionStats,
  TraceSessionStateChange
} from "src/generated/traceapp_pb";
import { EmulationState, ResponseStatus } from "src/generated/utils_pb";
import { TraceSessionState } from "src/generated/workspace_pb";
import { Alert } from "../alert";
import { Rts } from "../app-routing.module";
import { TraceSessionDisplay } from "../display/trace-session-display";
import { SessionMgrService } from "../session-mgr/session-mgr.service";
import { traceAppSessionStateFromEmulationState } from "../styx-idl";
import { TraceService } from "../trace.service";
import { VarTableComponentOptions } from "../var-table/var-table.component";

@Component({
  selector: "app-emulate[traceSession]",
  templateUrl: "emulate.component.html",
  styleUrls: ["./emulate.component.css"]
})
export class EmulateComponent implements OnInit, OnChanges, AfterViewInit {
  alerts: Alert[] = [];
  public Rts = Rts;
  strTraceSessionId = "Not Set";
  options: VarTableComponentOptions = { scrollToBottom: false };
  traceSession: TraceSessionDisplay | undefined = undefined;

  @Output() onSessionDropped = new EventEmitter<TraceSessionDisplay>();
  @ViewChild("maxEventsViewChild") maxEventsInputField?: ElementRef = undefined;

  constructor(
    private traceService: TraceService,
    private sessionService: SessionMgrService,
    private route: ActivatedRoute,
    private router: Router
  ) {}

  ngAfterViewInit(): void {}

  ngOnInit() {
    this.route.paramMap.subscribe((params) => {
      const strTraceSessionId = params.get("traceSessionId");
      let theId = 0;
      if (strTraceSessionId) {
        theId = parseInt(strTraceSessionId);
      }

      const traceSession = this.sessionService.getByLocalId(theId);
      if (!traceSession) {
        console.error("NO ID!!!");
      }
      this.traceSession = <TraceSessionDisplay>traceSession;
    });
  }

  ngOnChanges(changes: SimpleChanges) {
    this.traceSession = changes["traceSession"]?.currentValue;
  }

  // Return the value from the HTML <input> for max events
  getMaxEvents(): number {
    let value = 0;
    if (this.maxEventsInputField) {
      value = this.maxEventsInputField.nativeElement.valueAsNumber;
      if (Number.isNaN(value)) {
        value = 0;
      }
    }
    return value;
  }

  onInitializeSession(): void {
    const session = this.traceSession;
    if (!session) {
      return;
    }
    const request = session._traceRequest;
    const args = request.traceAppSessionArgs;
    args.setResume(args.getSessionId().length > 0);
    args.getLimits()?.setMaxInsn(this.getMaxEvents());
    // const stats = session.stats;
    session.errorString = session.warningString = "";
    this.traceService.traceapp.initialize(session.request).subscribe({
      next: (response) => {
        if (response.hasStateChange()) {
          session.state = (<TraceSessionStateChange>(
            response.getStateChange()
          )).getState();
          console.log(`StateChange: ${session.stateString}`);
        }
        if (response.getSessionId().length > 0) {
          session.sessionID = response.getSessionId();
          args.setSessionId(response.getSessionId());
        }
      },

      error: (error) => {
        session.errorString = error;
        this.alerts.push({
          type: "danger",
          message: error.toString()
        });
        console.log(error);
      },

      complete: () => {
        console.log("initialize complete");
      }
    });
  }

  // start reporting on trace
  onStartSession(): void {
    const session = this.traceSession;
    if (!session) {
      return;
    }
    const request = session._traceRequest;
    const args = request.traceAppSessionArgs;
    args.getLimits()?.setMaxInsn(this.getMaxEvents());
    session.errorString = session.warningString = "";
    session.emuStart = Date.now();
    console.info(session.request.toObject().args);
    this.traceService.traceapp.start(session.request).subscribe({
      next: (response) => {
        // set emuEnd to display elapsed time
        session.emuEnd = Date.now();
        if (response.hasStateChange()) {
          session.state = (<TraceSessionStateChange>(
            response.getStateChange()
          )).getState();
          console.log(`StateChange: ${session.stateString}`);
        }

        if (response.getSessionId().length > 0) {
          session.sessionID = response.getSessionId();
          args.setSessionId(response.getSessionId());
        }

        if (response.hasCumSessionStats()) {
          const cumSessionStats = <SessionStats>response.getCumSessionStats();
          session.stats.cumInstPerSec = cumSessionStats.getRate();
          session.stats.cumInstCount = cumSessionStats.getInsnCount();
        }
        if (response.hasTimeout()) {
          session.state = TraceSessionState.RUNNING;
          const last_inst = response.getTimeout()?.getInsnNum();
          session.warningString =
            "[" + last_inst + "] Timeout waiting for raw trace events";
        }
        for (const e of response.getInstructionsList()) {
          session.stats.setInsnNumber(e.getInsnNum());
        }

        for (const e of response.getMemoryWritesList()) {
          session.stats.setInsnNumber(e.getInsnNum());
          session.stats.memoryChangeCount += 1;
          session.addMemoryEvent(e);
        }

        for (const e of response.getInterruptsList()) {
          session.stats.setInsnNumber(e.getInsnNum());
          if (e.getEntered()) {
            session.stats.isrEnterCount++;
          } else {
            session.stats.isrExitCount++;
          }
        }

        // EndOfEvents
        for (const e of response.getEndOfEventsList()) {
          session.stats.setInsnNumber(e.getInsnNum());
          session.warningString = "There are no more raw trace events";
        }
      },

      error: (error) => {
        session.state = TraceSessionState.UNKNOWN;
        session.errorString = error;
        console.log(error);
        session.emuEnd = Date.now();
      },

      complete: () => {
        session.state = TraceSessionState.PAUSED;
        console.log("start complete");
        session.emuEnd = Date.now();
      }
    });
  }

  onStopSession(): void {
    const session = this.traceSession;
    if (!session) {
      return;
    }
    const appSession = new AppSession().setSessionId(session.sessionID);
    this.traceService.traceapp.stop(appSession).subscribe({
      next: (response) => {
        if (response.getState()) {
          session.state = traceAppSessionStateFromEmulationState(
            <EmulationState>response.getState()
          );
        }
        const message = response.getMessage();
        if (response.getResult()) {
          switch (<ResponseStatus.Result>response.getResult()) {
            case ResponseStatus.Result.OK:
              break;
            case ResponseStatus.Result.WARN:
              session.warningString = message;
              break;
            case ResponseStatus.Result.ERR:
              session.errorString = message;
              break;
          }
        }
      },

      error: (error) => {
        session.state = TraceSessionState.UNKNOWN;
        console.log("stop(error): ", error.toObject());
        session.errorString = error;
      },
      complete: () => {
        session.state = TraceSessionState.STOPPED;
        console.log("stop complete");
        session.emuEnd = Date.now();
      }
    });
  }

  onDropSession(): void {
    if (!this.traceSession) {
      return;
    }

    const session = this.traceSession;
    const appSession = new AppSession().setSessionId(session.sessionID);
    session.warningString = "";

    if (session.stoppable) {
      session.warningString =
        "Session running - stopping, drop again when status is DROPPED";
      this.onStopSession();
    } else {
      session.state = TraceSessionState.DROPPING;
      this.traceService.traceapp.disconnect(appSession).subscribe({
        next: (response) => {
          if (response.getState()) {
            session.state = traceAppSessionStateFromEmulationState(
              <EmulationState>response.getState()
            );
          }
          const message = response.getMessage();
          if (response.getResult()) {
            switch (<ResponseStatus.Result>response.getResult()) {
              case ResponseStatus.Result.OK:
                break;
              case ResponseStatus.Result.WARN:
                session.warningString = message;
                break;
              case ResponseStatus.Result.ERR:
                session.errorString = message;
                break;
            }
          }
        },

        error: (error) => {
          session.state = TraceSessionState.ERROR;
          session.errorString = error;
          console.error(error);
        },

        complete: () => {
          console.info("disconnect() complete");
          session.state = TraceSessionState.DROPPED;
          this.sessionService.drop(session);
          this.router.navigate([Rts.SessionList]);
        }
      });
    }
  }

  close(alert: Alert) {
    this.alerts.splice(this.alerts.indexOf(alert), 1);
  }
}
