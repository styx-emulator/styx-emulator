// SPDX-License-Identifier: BSD-2-Clause
import { Component } from "@angular/core";
import { Router } from "@angular/router";
import {
  EmulationArgs,
  SymbolSearchOptions,
  Target,
  TraceAppSessionArgs,
  TracePluginArgs
} from "src/generated/args_pb";
import { Program, ProgramIdentifier } from "src/generated/symbolic_pb";
import { WsProgram } from "src/generated/workspace_pb";
import { Alert, ErrorAlert } from "../alert";
import { Rts } from "../app-routing.module";
import { TraceRequestDisplay } from "../display/trace-request-display";
import { SessionMgrService } from "../session-mgr/session-mgr.service";
import { TraceService } from "../trace.service";

export enum State {
  NotBusy = "NotBusy",
  Loading = "Loading",
  Deleting = "Deleting"
}

@Component({
  selector: "app-list-workspace-program",
  templateUrl: "./list-workspace-program.component.html",
  styleUrl: "./list-workspace-program.component.css"
})
export class ListWorkspaceProgramComponent {
  public State = State;
  public Rts = Rts;
  alerts: Alert[] = [];
  state: State = State.Loading;
  wsPrograms: Array<WsProgram> = [];

  constructor(
    private traceService: TraceService,
    private sessionService: SessionMgrService,
    private router: Router
  ) {
    this.refreshData();
  }

  refreshData() {
    this.state = State.Loading;
    this.traceService.workspace
      .getAllWsPrograms()
      .subscribe({
        next: (wsPrograms) => {
          this.wsPrograms = wsPrograms;
          this.state = State.NotBusy;
        },
        error: (error) => {
          this.state = State.NotBusy;
          this.alerts.push(new ErrorAlert(error.toString()));
        }
      })
      .add(() => {
        this.state = State.NotBusy;
      });
  }

  onDelete(wsProgram: WsProgram) {
    this.state = State.Deleting;
    this.traceService.workspace
      .deleteWsProgram(wsProgram.getId())
      .subscribe({
        error: (error) => {
          this.alerts.push(new ErrorAlert(error.toString()));
        }
      })
      .add(() => {
        this.refreshData();
        this.state = State.NotBusy;
      });
  }

  onEmulate(wsProgram: WsProgram) {
    this.saveAsTraceSession(wsProgram);
  }

  onEdit(wsProgram: WsProgram) {
    this.router.navigate([Rts.WspEdit, "edit", wsProgram.getId()]);
  }

  saveAsTraceSession(wsProgram: WsProgram) {
    // const newRequest = this.getInitializeTraceRequest();
    const program = <Program>wsProgram.getSymProgram();
    const traceRequest: TraceRequestDisplay =
      this.sessionService.createTraceRequest(
        TraceAppSessionArgs.TraceMode.EMULATED,
        "/tmp",
        "",
        true,
        new SymbolSearchOptions()
          .setRegexInclude(".")
          .setMemWrites(true)
          .setMemReads(false)
          .setAnonReads(false)
          .setAnonWrites(false)
          .toObject(),
        program
      );
    traceRequest.pid = <ProgramIdentifier>program.getPid();
    // set ws_program_id
    traceRequest.ws_program_id = wsProgram.getId();
    const firmwarePath = "/firmware/k21-1.bin";

    traceRequest.emulation_args = new EmulationArgs()
      .setTarget(Target.KINETIS21)
      .setFirmwarePath(firmwarePath)
      .setTracePluginArgs(
        new TracePluginArgs()
          .setInsnEvent(true)
          .setInterruptEvent(true)
          .setWriteMemoryEvent(true)
          .setReadMemoryEvent(true)
      );
    let hasErr = false;
    this.sessionService.saveTraceRequest(traceRequest).subscribe({
      error: (e) => {
        hasErr = true;
        this.alerts.push({
          type: "danger",
          message: e.toString()
        });
        console.error("Error saving data:", e);
      },
      complete: () => {
        if (!hasErr) {
          this.router.navigate([Rts.SessionList]);
        }
      }
    });
  }
}
