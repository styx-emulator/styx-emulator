import { Component, Input, OnInit, ViewChild } from "@angular/core";
import { MatTable } from "@angular/material/table";
import { TraceAppSessionArgs } from "src/generated/args_pb";
import { SessionMgrService } from "../session-mgr/session-mgr.service";
import { ITraceAppSessionArgsDisplay } from "../styx-idl";
import { TraceConfigsDataSource } from "./trace-configs-datasource";

interface ColumnDef {
  id: number;
  prop: string;
  label: string;
  display: boolean;
}

export const COLUMNS: ColumnDef[] = [
  { id: 0, prop: "id", label: "ID", display: true },
  { id: 1, prop: "mode", label: "Mode", display: false },
  { id: 1, prop: "modeDisplay", label: "Mode", display: true }
];

@Component({
  selector: "app-trace-configs",
  templateUrl: "./trace-configs.component.html",
  styleUrl: "./trace-configs.component.css"
})
export class TraceConfigsComponent implements OnInit {
  @Input() traceMode: TraceAppSessionArgs.TraceMode =
    TraceAppSessionArgs.TraceMode.EMULATED;

  @ViewChild(MatTable) table!: MatTable<ITraceAppSessionArgsDisplay>;
  public columnsDef = COLUMNS;

  dataSource: TraceConfigsDataSource;
  displayedColumns: string[] = [];

  constructor(private sessionService: SessionMgrService) {
    this.dataSource = new TraceConfigsDataSource(this.sessionService);
    this.displayedColumns = ["id", "modeDisplay", "archDisplay"];
  }

  ngOnInit() {
    console.debug("TraceConfigsComponent.ngOnInit()");
    this.dataSource.loadItems(this.traceMode);
  }
}
