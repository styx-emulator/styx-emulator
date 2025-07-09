import { Injectable } from "@angular/core";
import { Observable } from "rxjs";
import { TraceAppSessionArgs, TracePluginArgs } from "src/generated/args_pb";

import {
  Architecture,
  Program,
  ProgramFilter
} from "src/generated/symbolic_pb";

import { TraceAppService } from "src/app/grpc-services/trace-app.service";
import { TyphunixService } from "src/app/grpc-services/typhunix.service";
import { WorkspaceService } from "src/app/grpc-services/workspace.service";
import { WebApiUrlService } from "./web-api-url.service";

export const APP_ARM_TARGET = "ARM";
export const APP_PowerQUICC_TARGET = "PowerQUICC";
export const APP_DEFAULT_TARGET = APP_ARM_TARGET;

@Injectable({
  providedIn: "root"
})
export class TraceService {
  grpcServiceName = "TraceService";
  url: string;

  /**
   * Service to communicate with `GRPC` services.
   *
   * This is an aggregate of all the available services (at least those that
   * are needed for the webapp.)
   *
   * Each service has a generated Client class. The client classes have methods
   * that return `RPC`. For the web, we want to convert the `RPC` to
   * `Observable`s by calling: `from` in the `grpc-web-rx` package.
   * For disambiguation, `from` is aliased to `rpcToGrpc`.
   *
   * Eacn `GRPC` service has a property, the creates a new instance of the client
   * class.
   *
   * @constructor
   */
  constructor(
    private webApiUrlService: WebApiUrlService,
    private typhunixService: TyphunixService,
    private traceAppService: TraceAppService,
    private workspaceService: WorkspaceService
  ) {
    this.url = webApiUrlService.baseUrl;
  }

  public get traceapp(): TraceAppService {
    return this.traceAppService;
  }

  public get typhunix(): TyphunixService {
    return this.typhunixService;
  }

  public get workspace(): WorkspaceService {
    return this.workspaceService;
  }

  // Return an Observable Array of TraceAppSessionArgs
  public fetchAllTraceAppSessions(): Observable<TraceAppSessionArgs[]> {
    const items: TraceAppSessionArgs[] = [];
    return new Observable<TraceAppSessionArgs[]>((subsciber) => {
      this.workspaceService.getTraceAppSessions().subscribe({
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

  // Return an Observable Array of Program
  public fetchAllPrograms(): Observable<Program[]> {
    const items: Program[] = [];
    return new Observable<Program[]>((subsciber) => {
      this.typhunixService.getPrograms(new ProgramFilter()).subscribe({
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
}

export function getEndianDesc(e: number | undefined): string {
  if (e != undefined) {
    switch (e) {
      case Architecture.EndianType.ENDIAN_BIG:
        return "Big-Endian";
      case Architecture.EndianType.ENDIAN_LITTLE:
        return "Little Endian";
      case Architecture.EndianType.ENDIAN_MIDDLE:
        return "Middle Endian";
      case Architecture.EndianType.ENDIAN_MIXED:
        return "Mixed Endian";
      default:
        return "Unknown Endian (" + e + ")";
    }
  } else {
    return "Endianess unknown";
  }
}

export const DEFAULT_TRACE_PLUGIN_ARGS = new TracePluginArgs()
  .setInsnEvent(true)
  .setInterruptEvent(true)
  .setReadMemoryEvent(false)
  .setWriteMemoryEvent(true);
