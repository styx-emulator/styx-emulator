import { Injectable } from "@angular/core";
import { from as rpcToGrpc } from "grpc-web-rx";
import { map, Observable, Subject } from "rxjs";

import { WebApiUrlService } from "src/app/web-api-url.service";
import { TraceAppSessionArgs } from "src/generated/args_pb";
import { DbId } from "src/generated/db_pb";
import { Program } from "src/generated/symbolic_pb";

import {
  DeleteWsProgramResponse,
  FileRef,
  GetJoinedTraceSessionsRequest,
  GetWorkspaceRequest,
  GetWsProgramsRequest,
  JoinedTraceSession,
  TraceAppSessRequest,
  TraceAppSessResponse,
  UpsertWsProgramRequest,
  UpsertWsProgramResponse,
  Workspace,
  WsProgram
} from "src/generated/workspace_pb";
import { WorkspaceSvcClient } from "src/generated/WorkspaceServiceClientPb";

@Injectable({
  providedIn: "root"
})
export class WorkspaceService {
  grpcServiceName = "WorkspaceSvc";
  url: string;
  cli: WorkspaceSvcClient;
  wsProgramsCache: WsProgram[] = [];

  constructor(private webApiUrlService: WebApiUrlService) {
    this.url = webApiUrlService.baseUrl;
    this.cli = new WorkspaceSvcClient(this.url, null, null);
  }

  upsertTraceAppSess(
    tasa: Array<TraceAppSessionArgs>
  ): Observable<TraceAppSessResponse> {
    const request = new TraceAppSessRequest()
      .setWithMsg(true)
      .setTraceAppSessionArgsList(tasa);
    return rpcToGrpc(() => this.cli.upsertTraceAppSess(request, null));
  }

  getAllTraceAppSess(): Observable<TraceAppSessResponse> {
    const request = new TraceAppSessRequest();
    return rpcToGrpc(() => this.cli.getTraceAppSess(request, null));
  }

  getTraceAppSessions(): Observable<TraceAppSessionArgs> {
    return rpcToGrpc(() =>
      this.cli.getTraceAppSessStreaming(new TraceAppSessRequest())
    );
  }

  deleteTraceAppSessionArgsById(id: number): Observable<TraceAppSessResponse> {
    return rpcToGrpc(() =>
      this.cli.delTraceAppSess(
        new TraceAppSessRequest().setDbidsList([new DbId().setId(id)]),
        null
      )
    );
  }

  getJoinedTraceSessions(
    request: GetJoinedTraceSessionsRequest
  ): Observable<JoinedTraceSession> {
    return rpcToGrpc(() => this.cli.getJoinedTraceSessions(request));
  }

  isConcreteFile(obj: object) {
    return (
      obj &&
      "lastModifiedDate" in obj &&
      "name" in obj &&
      "size" in obj &&
      "type" in obj &&
      "webkitRelativePath" in obj
    );
  }

  /**
   * Create/save WsProgram
   *
   */
  upsertWsProgram(
    wsProgram: WsProgram,
    file: File
  ): Observable<UpsertWsProgramResponse> {
    const obs = new Observable<UpsertWsProgramResponse>((subscriber) => {
      const wsProgram$ = new Subject<WsProgram>();
      wsProgram$.subscribe((wsProgram) => {
        const request = new UpsertWsProgramRequest().setProgram(wsProgram);
        const xfer = rpcToGrpc(() => this.cli.upsertWsProgram(request));
        let response: UpsertWsProgramResponse = new UpsertWsProgramResponse();
        xfer.subscribe({
          next: (value) => {
            response = value;
            subscriber.next(response);
          },
          error: (err) => {
            subscriber.error(err);
          },
          complete() {
            subscriber.complete();
          }
        });
      });

      const reader = new FileReader();
      // setting the function IDs to 1 is compensation for a bug
      console.warn("setting function IDs to 1");
      const program = <Program>wsProgram.getSymProgram();
      program.getFunctionsList().forEach((f) => {
        f.setId(1);
      });

      if (this.isConcreteFile(file)) {
        reader.onloadend = () => {
          const content = reader.result as ArrayBuffer;
          console.log(`file size: ${content.byteLength} bytes`);
          console.log("done");
          wsProgram.setData(new Uint8Array(content));
          wsProgram.setFile(
            new FileRef().setSize(file.size).setPath(file.name)
          );
          wsProgram$.next(wsProgram);
        };

        reader.onerror = (error) => {
          subscriber.error(error);
        };

        reader.readAsArrayBuffer(file);
      } else {
        wsProgram$.next(wsProgram);
      }
    });
    return obs;
  }

  getWsProgramById(id: number): Observable<WsProgram | undefined> {
    return new Observable<WsProgram>((subscriber) => {
      for (const wsp of this.wsProgramsCache) {
        if (wsp.getId() === id) {
          subscriber.next(wsp);
          subscriber.complete();
        }
      }
    });
  }

  fetchFullWsProgramById(id: number): Observable<WsProgram | undefined> {
    const svc = rpcToGrpc(() =>
      this.cli.getWsPrograms(
        new GetWsProgramsRequest().setWithData(true).setWsProgramDbId(id)
      )
    );
    return new Observable<WsProgram | undefined>((subscriber) => {
      let result: WsProgram | undefined = undefined;
      svc.subscribe({
        next(value) {
          result = value.getProgramsList().at(0);
        },
        error(err) {
          subscriber.error(err);
        },
        complete() {
          subscriber.next(result);
          subscriber.complete();
        }
      });
    });
  }

  private getWsPrograms(
    request: GetWsProgramsRequest
  ): Observable<WsProgram[]> {
    return rpcToGrpc(() => this.cli.getWsPrograms(request)).pipe(
      map((response) => response.getProgramsList())
    );
  }

  getAllWsPrograms(): Observable<WsProgram[]> {
    const cache = this.wsProgramsCache;
    let programs: WsProgram[] = [];

    return new Observable<WsProgram[]>((subscriber) => {
      this.getWsPrograms(new GetWsProgramsRequest()).subscribe({
        next(value: WsProgram[]) {
          programs = value;
        },
        error(err) {
          subscriber.error(
            `Error getting Workspace Programs, ` +
              `while calling getWsPrograms. The error was: ${err}`
          );
        },
        complete() {
          cache.length = 0;
          programs.map((w) => cache.push(w));
          subscriber.next(programs);
          subscriber.complete();
        }
      });
    });
  }

  deleteWsProgram(id: number): Observable<DeleteWsProgramResponse> {
    const svc = rpcToGrpc(() => this.cli.deleteWsProgram(new DbId().setId(id)));
    return new Observable<DeleteWsProgramResponse>((subscriber) => {
      svc.subscribe({
        next(value) {
          subscriber.next(value);
        },
        error(err) {
          subscriber.error(err);
        },
        complete() {
          subscriber.complete();
        }
      });
    });
  }

  getWorkspaces(): Observable<Workspace[]> {
    return rpcToGrpc(() =>
      this.cli.getWorkspaces(new GetWorkspaceRequest())
    ).pipe(map((response) => response.getWorkspacesList()));
  }
}
