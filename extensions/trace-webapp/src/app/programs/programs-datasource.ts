// SPDX-License-Identifier: BSD-2-Clause
import { DataSource } from "@angular/cdk/collections";
import { MatPaginator } from "@angular/material/paginator";
import { MatSort } from "@angular/material/sort";
import { merge, Observable, of as observableOf } from "rxjs";
import { map } from "rxjs/operators";
import { ProgramWithSymbolsDisplay } from "../display/program-display";
import { ProgramColumns } from "./programs.component";

/**
 * Data source for the Programs view. This class should
 * encapsulate all logic for fetching and manipulating the displayed data
 * (including sorting, pagination, and filtering).
 */
export class ProgramsDataSource extends DataSource<ProgramWithSymbolsDisplay> {
  data: ProgramWithSymbolsDisplay[] = [];
  paginator: MatPaginator | undefined;
  sort: MatSort | undefined;

  constructor() {
    super();
  }

  /**
   * Connect this data source to the table. The table will only update when
   * the returned stream emits new items.
   * @returns A stream of the items to be rendered.
   */
  connect(): Observable<ProgramWithSymbolsDisplay[]> {
    if (this.paginator && this.sort) {
      // Combine everything that affects the rendered data into one update
      // stream for the data-table to consume.
      return merge(
        observableOf(this.data),
        this.paginator.page,
        this.sort.sortChange
      ).pipe(
        map(() => {
          return this.getPagedData(this.getSortedData([...this.data]));
        })
      );
    } else {
      throw Error(
        "Please set the paginator and sort on the data source before connecting."
      );
    }
  }

  /**
   *  Called when the table is being destroyed. Use this function, to clean up
   * any open connections or free any held resources that were set up during connect.
   */
  disconnect(): void {}

  /**
   * Paginate the data (client-side). If you're using server-side pagination,
   * this would be replaced by requesting the appropriate data from the server.
   */
  private getPagedData(
    data: ProgramWithSymbolsDisplay[]
  ): ProgramWithSymbolsDisplay[] {
    if (this.paginator) {
      const startIndex = this.paginator.pageIndex * this.paginator.pageSize;
      return data.splice(startIndex, this.paginator.pageSize);
    } else {
      return data;
    }
  }

  /**
   * Sort the data (client-side). If you're using server-side sorting,
   * this would be replaced by requesting the appropriate data from the server.
   */
  private getSortedData(
    data: ProgramWithSymbolsDisplay[]
  ): ProgramWithSymbolsDisplay[] {
    if (!this.sort || !this.sort.active || this.sort.direction === "") {
      return data;
    }

    return data.sort(
      (a: ProgramWithSymbolsDisplay, b: ProgramWithSymbolsDisplay) => {
        const isAsc = this.sort?.direction === "asc";
        switch (this.sort?.active as ProgramColumns) {
          case ProgramColumns.Name:
            return compare(
              a[ProgramColumns.Name],
              b[ProgramColumns.Name],
              isAsc
            );
          case ProgramColumns.Arch:
            return compare(
              a[ProgramColumns.Arch],
              b[ProgramColumns.Arch],
              isAsc
            );

          case ProgramColumns.Source:
            return compare(
              a[ProgramColumns.Source],
              b[ProgramColumns.Source],
              isAsc
            );
          case ProgramColumns.SymbolCount:
            return compare(
              a[ProgramColumns.SymbolCount],
              b[ProgramColumns.SymbolCount],
              isAsc
            );
          case ProgramColumns.DataTypeCount:
            return compare(
              a[ProgramColumns.DataTypeCount],
              b[ProgramColumns.DataTypeCount],
              isAsc
            );
          case ProgramColumns.Select:
            return 0;
        }
      }
    );
  }
}

/** Simple sort comparator for example ID/Name columns (for client-side sorting). */
function compare(
  a: string | number,
  b: string | number,
  isAsc: boolean
): number {
  return (a < b ? -1 : 1) * (isAsc ? 1 : -1);
}
