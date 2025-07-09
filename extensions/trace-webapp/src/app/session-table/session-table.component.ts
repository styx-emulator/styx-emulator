import { SelectionModel } from "@angular/cdk/collections";
import { ChangeDetectorRef, Component, ViewChild } from "@angular/core";
import { MatTable, MatTableDataSource } from "@angular/material/table";
import { Router } from "@angular/router";
import { TraceAppSessionArgs } from "src/generated/args_pb";
import { Program } from "src/generated/symbolic_pb";
import { JoinedTraceSession } from "src/generated/workspace_pb";
import { Rts } from "../app-routing.module";
import { TraceSessionDisplay } from "../display/trace-session-display";
import { SessionMgrService } from "../session-mgr/session-mgr.service";
import { TraceService } from "../trace.service";

/******************** class SessionsTable **************************************
 *
 * Component AppComponent ()
 *
 * Class to manage the session list table
 *******************************************************************************
 */
class SessionsTable {
  public columnNames: string[] = [
    "deleteSession",
    "localSessionId",
    "msgId",
    "sessionState",
    "traceModeName",
    "targetDesc",
    "program",
    "sessionId"
  ];
  private htmlTable: MatTable<TraceSessionDisplay> | undefined;

  dataSource: MatTableDataSource<TraceSessionDisplay>;
  selection: SelectionModel<TraceSessionDisplay>;

  public setHtmlTable(matTable: MatTable<TraceSessionDisplay> | undefined) {
    if (matTable && !this.htmlTable) {
      this.htmlTable = matTable;
    }
  }
  public isHtmlTableSet(): boolean {
    return !this.htmlTable === undefined;
  }
  constructor(private sessionService: SessionMgrService) {
    this.dataSource = new MatTableDataSource<TraceSessionDisplay>(
      this.sessionService.sessionList
    );
    this.selection = new SelectionModel<TraceSessionDisplay>(
      false,
      this.dataSource.data
    );
  }

  // Get the selected TraceSessionDisplay
  public get selected(): TraceSessionDisplay | undefined {
    return this.selection.selected[0];
  }

  // Select the last TraceSessionDisplay
  selectLast() {
    const len = this.dataSource.data.length;
    if (len > 0) {
      this.selection.select(this.dataSource.data[len - 1]);
    }
  }

  refreshTable() {
    this.dataSource.data = this.sessionService.sessionList;
    if (this.htmlTable) {
      this.htmlTable.renderRows();
    }
  }

  isEmpty(): boolean {
    return this.dataSource.data.length == 0;
  }
}

@Component({
  selector: "app-session-table",
  templateUrl: "./session-table.component.html",
  styleUrl: "./session-table.component.css"
})
export class SessionTableComponent {
  public Rts = Rts;
  sessionTable: SessionsTable = new SessionsTable(this.sessionService);
  @ViewChild(MatTable) sessionsHtmlTable!: MatTable<TraceSessionDisplay>;

  // constructor
  constructor(
    private changeDetectorRef: ChangeDetectorRef,
    private sessionService: SessionMgrService,
    private traceService: TraceService,
    private router: Router
  ) {}

  // AfterViewInit
  ngAfterViewInit() {
    this.sessionTable.setHtmlTable(this.sessionsHtmlTable);
    this.getSessions();
  }

  // Fetch new items, update SessionTable
  getSessions() {
    let joinedTraceSessions: JoinedTraceSession[] = [];
    this.sessionService.fetchJoinedTraceSessions().subscribe({
      next: (items) => {
        joinedTraceSessions = items;
      },
      complete: () => {
        for (const item of joinedTraceSessions) {
          this.sessionService.createTraceRequestDisplayFromSaved(
            <TraceAppSessionArgs>item.getArgs(),
            <Program>item.getProgram(),
            item.getSession()
          );
        }
        this.sessionTable.refreshTable();
      }
    });
  }

  // A sessions status was set to Dropped, remove it from the view
  onSessionDropped(session: TraceSessionDisplay) {
    this.sessionService.drop(session);
    this.sessionTable.refreshTable();
    // this.tabGroup.selectedIndex = 0;
  }

  // session list double click
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  onSessionDoubleClick(session: TraceSessionDisplay) {
    this.router.navigate([Rts.Trace, session.id]);
  }
}
