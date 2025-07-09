// SPDX-License-Identifier: BSD-2-Clause
import { Injectable } from "@angular/core";
import { from as rpcToGrpc } from "grpc-web-rx";
import { Observable, toArray } from "rxjs";

import {
  DataType,
  Symbol as GSymbol,
  Program,
  ProgramFilter,
  ProgramIdentifier,
  ProgramsWithSymbols
} from "src/generated/symbolic_pb";

import { TyphunixClient } from "src/generated/Ghidra_stateServiceClientPb";
import { WebApiUrlService } from "../web-api-url.service";

@Injectable({
  providedIn: "root"
})
export class TyphunixService {
  grpcServiceName = "TyphunixService";
  url: string;
  cli: TyphunixClient;

  constructor(private webApiUrlService: WebApiUrlService) {
    this.url = webApiUrlService.baseUrl;
    this.cli = new TyphunixClient(this.url, null, null);
  }

  getProgramsIdentifiers(filter: ProgramFilter): Observable<ProgramIdentifier> {
    return rpcToGrpc(() => this.cli.getProgramsIdentifiers(filter));
  }

  getPrograms(filter: ProgramFilter): Observable<Program> {
    return rpcToGrpc(() => this.cli.getPrograms(filter));
  }

  getSymbols(filter: Program): Observable<GSymbol> {
    return rpcToGrpc(() => this.cli.getSymbols(filter));
  }

  getDataTypes(filter: Program): Observable<DataType> {
    return rpcToGrpc(() => this.cli.getDataTypes(filter));
  }

  /**
   * Get a list of all programs from typhuniz with Program, Symbols, and
   * DataTypes combined in a ProgramsWithSymbols object.
   *
   * @param filter - down-select based on program identifier
   * @returns Observable<ProgramsWithSymbols>
   */
  getProgramsWithSymbols(
    filter: ProgramFilter
  ): Observable<ProgramsWithSymbols> {
    return rpcToGrpc(() => this.cli.getProgramsWithSymbols(filter));
  }

  /**
   * Get a list of all programs from typhuniz with Program, Symbols, and
   * DataTypes combined in a ProgramsWithSymbols object.
   *
   * @param filter - down-select based on program identifier
   * @returns Observable<ProgramsWithSymbols[]>
   */
  getProgramsWithSymbolsList(
    filter: ProgramFilter
  ): Observable<ProgramsWithSymbols[]> {
    return this.getProgramsWithSymbols(filter).pipe(toArray());
  }
}
