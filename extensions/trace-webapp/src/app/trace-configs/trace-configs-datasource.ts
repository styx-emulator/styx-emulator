// SPDX-License-Identifier: BSD-2-Clause
import { CollectionViewer, DataSource } from "@angular/cdk/collections";
import {
  BehaviorSubject,
  Observable,
  catchError,
  finalize,
  of as observableOf
} from "rxjs";
import { TraceAppSessionArgs } from "src/generated/args_pb";
import { SessionMgrService } from "../session-mgr/session-mgr.service";
import { ITraceAppSessionArgsDisplay } from "../styx-idl";

export class TraceConfigsDataSource
  implements DataSource<ITraceAppSessionArgsDisplay>
{
  // paginator: MatPaginator | undefined;
  // sort: MatSort | undefined;
  private data: ITraceAppSessionArgsDisplay[] = [];

  // BehaviorSubject to hold the data
  private itemsSubject = new BehaviorSubject<ITraceAppSessionArgsDisplay[]>([]);

  // BehaviorSubject to track loading state
  private loadingSubject = new BehaviorSubject<boolean>(false);

  // Observable for the loading state, with a dollar sign to indicate it's an Observable
  public loading$ = this.loadingSubject.asObservable();

  constructor(private sessionService: SessionMgrService) {}

  // Fetch the items
  loadItems(mode: TraceAppSessionArgs.TraceMode) {
    this.loadingSubject.next(true);
    this.sessionService
      .deprecatedFetchTraceAppSessionDisplays()
      .pipe(
        catchError(() => observableOf([])),
        finalize(() => this.loadingSubject.next(false))
      )
      .subscribe((items) => {
        this.itemsSubject.next(items.filter((item) => item.getMode() === mode));
      });
  }

  // Connects the DataSource to the table, returning the data Observable
  connect(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    collectionViewer: CollectionViewer
  ): Observable<ITraceAppSessionArgsDisplay[]> {
    // this.itemsSubject.subscribe(items => this.data = items);
    return this.itemsSubject.asObservable();
  }

  // Disconnects the DataSource, completing the subjects
  disconnect(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    collectionViewer: CollectionViewer
  ): void {
    this.itemsSubject.complete();
    this.loadingSubject.complete();
  }
}
