// SPDX-License-Identifier: BSD-2-Clause
import { SelectionModel } from "@angular/cdk/collections";
import {
  AfterViewInit,
  Component,
  EventEmitter,
  Input,
  OnInit,
  Output,
  ViewChild
} from "@angular/core";
import { MatPaginator } from "@angular/material/paginator";
import { MatRadioChange } from "@angular/material/radio";
import { MatSort } from "@angular/material/sort";
import { MatTable } from "@angular/material/table";
import { ProgramFilter } from "src/generated/symbolic_pb";
import { ProgramWithSymbolsDisplay } from "../display/program-display";
import { TraceService } from "../trace.service";
import { ProgramsDataSource } from "./programs-datasource";

export enum ProgramColumns {
  Select = "select",
  Arch = "archStr",
  Source = "pidSource",
  Name = "pidName",
  SymbolCount = "symbolCount",
  DataTypeCount = "dataTypeCount"
}
const DefaultDisplayedColumns: string[] = [
  ProgramColumns.Arch,
  ProgramColumns.Source,
  ProgramColumns.Name
];

@Component({
  selector: "app-programs",
  templateUrl: "./programs.component.html",
  styleUrl: "./programs.component.css"
})
export class ProgramsComponent implements OnInit, AfterViewInit {
  public Columns = ProgramColumns;
  public DisplayedColumns = DefaultDisplayedColumns;
  public ProgramColumns = ProgramColumns;
  ngColumnContainers = [
    { name: ProgramColumns.Name, title: "Name" },
    { name: ProgramColumns.Source, title: "Source" },
    { name: ProgramColumns.Arch, title: "Arch" },
    { name: ProgramColumns.SymbolCount, title: "#sym" },
    { name: ProgramColumns.DataTypeCount, title: "#dt" }
  ];

  selectedProgram: SelectionModel<ProgramWithSymbolsDisplay>;

  @ViewChild(MatPaginator) paginator!: MatPaginator;
  @ViewChild(MatSort) sort!: MatSort;
  @ViewChild(MatTable) table!: MatTable<ProgramWithSymbolsDisplay>;

  @Input() selectable: boolean = false;
  @Input() columns: string[] | undefined = undefined;
  dataSource = new ProgramsDataSource();
  displayedColumns: string[] = [];
  @Output() onProgramSelectedEvent =
    new EventEmitter<ProgramWithSymbolsDisplay>();

  /**
   * Constructor
   * @param traceService for fetching programs
   */
  constructor(private traceService: TraceService) {
    this.selectedProgram = new SelectionModel<ProgramWithSymbolsDisplay>(
      false,
      this.dataSource.data
    );
  }

  radioSelected(item: MatRadioChange) {
    const selected = <ProgramWithSymbolsDisplay>item.value;
    this.onProgramSelectedEvent.emit(selected);
  }

  onProgramSelected(event: Event) {
    const element = event.currentTarget as HTMLInputElement;
    const source = element.id as string;
    const name = element.value as string;
    this.dataSource.data.forEach((data) => {
      if (data.pidName == name && data.pidSource == source) {
        const pws = data as ProgramWithSymbolsDisplay;
        this.onProgramSelectedEvent.emit(pws);
      }
    });
  }

  tooltip(item: ProgramWithSymbolsDisplay): string {
    return `${item.pidSource}, ${item.pidName},
    ${item.symbols.length} symbols,
    ${item.datatypes.length} data types`;
  }

  ngOnInit(): void {
    // displayedColumns is initially empty
    const addColumns: string[] = [];
    if (this.selectable) {
      addColumns.push(ProgramColumns.Select);
    }
    if (!this.columns) {
      for (const column of DefaultDisplayedColumns) {
        addColumns.push(column);
      }
    } else {
      for (const column of this.columns) {
        addColumns.push(column);
      }
    }
    for (const column of addColumns) {
      this.displayedColumns.push(column);
    }
  }

  ngAfterViewInit(): void {
    const items: ProgramWithSymbolsDisplay[] = [];
    this.traceService.typhunix
      .getProgramsWithSymbolsList(new ProgramFilter())
      .subscribe({
        next: (pgws) => {
          pgws.forEach((pws) => {
            items.push(new ProgramWithSymbolsDisplay(pws));
          });
        },
        error: (error) => {
          const message =
            "Error getting ghidra programs. Is typhunix running? " +
            "Error message: " +
            `${error.message} `;
          console.error(message);
        },
        complete: () => {
          this.dataSource.data = items;
          this.dataSource.sort = this.sort;
          this.dataSource.paginator = this.paginator;
          this.table.dataSource = this.dataSource;
        }
      });
  }
}
