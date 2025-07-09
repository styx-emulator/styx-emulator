import { Injectable } from "@angular/core";
import { from as rpcToGrpc } from "grpc-web-rx";
import { catchError, map, Observable, of } from "rxjs";
import { WebApiUrlService } from "src/app/web-api-url.service";
import {
  ArchIdentity,
  IdentityMappingResponse,
  SupportedConfig,
  VariantIdentity
} from "src/generated/emulation_registry_pb";
import { EmulationRegistryServiceClient } from "src/generated/Emulation_registryServiceClientPb";

import {
  AppSession,
  InitializeTraceRequest,
  StartTraceAppSessionResponse
} from "src/generated/traceapp_pb";
import { TraceAppSessionServiceClient } from "src/generated/TraceappServiceClientPb";
import { Empty, ResponseStatus } from "src/generated/utils_pb";
import { filterError } from "../error.service";

@Injectable({
  providedIn: "root"
})
export class TraceAppService {
  grpcServiceName = "TraceAppSessionService";
  url: string;
  cli: TraceAppSessionServiceClient;

  constructor(private webApiUrlService: WebApiUrlService) {
    this.url = webApiUrlService.baseUrl;
    this.cli = new TraceAppSessionServiceClient(this.url, null, null);
  }

  initialize(
    request: InitializeTraceRequest
  ): Observable<StartTraceAppSessionResponse> {
    return (<Observable<StartTraceAppSessionResponse>>(
      rpcToGrpc(() => this.cli.initialize(request))
    )).pipe(
      catchError((e) => {
        throw filterError(e, "EmulationRegistryService");
      })
    );
  }

  start(
    request: InitializeTraceRequest
  ): Observable<StartTraceAppSessionResponse> {
    return rpcToGrpc(() => this.cli.start(request));
  }

  disconnect(request: AppSession): Observable<ResponseStatus> {
    return rpcToGrpc(() => this.cli.disconnect(request, null));
  }

  stop(request: AppSession): Observable<ResponseStatus> {
    return rpcToGrpc(() => this.cli.stop(request, null));
  }
}

@Injectable({
  providedIn: "root"
})
export class MetaService {
  grpcServiceName = "EmulationRegistryService";
  url: string;
  cli: EmulationRegistryServiceClient;
  cache: IdentityMappingResponse | undefined;

  constructor(private webApiUrlService: WebApiUrlService) {
    this.url = webApiUrlService.baseUrl;
    this.cli = new EmulationRegistryServiceClient(this.url, null, null);
  }

  getIdentityMapping(): Observable<IdentityMappingResponse> {
    if (this.cache) {
      return of(this.cache);
    } else {
      return rpcToGrpc(() => this.cli.getIdentityMapping(new Empty(), null)).pipe(
        catchError((e) => {
          throw filterError(e, "EmulationRegistryService");
        })
      );
    }
  }

  getIdentityRepo(): Observable<IdentityRepo> {
    return this.getIdentityMapping().pipe(
      map((m) => new IdentityRepo(m))
      // ,
      // catchError((e) => {
      //   throw filterError(e, e.message);
      // })
    );
  }
}

export interface INamedIdentifier {
  getId(): number;
  getName(): string;
}
export class IdentifierSet {
  // Array of all identifiers
  all: INamedIdentifier[];
  // map of identifier id to the identifier
  map: Map<number, INamedIdentifier>;
  // Uniq list of identifiers
  uniq: INamedIdentifier[];

  constructor(list: INamedIdentifier[]) {
    this.all = list;
    this.map = new Map();
    for (const i of this.all) {
      this.map.set(i.getId(), i);
    }
    this.uniq = Array.from(this.map.values());
  }

  getSameItemById(
    item: INamedIdentifier | undefined
  ): INamedIdentifier | undefined {
    return this.all.filter((i) => i.getId() == item?.getId()).at(0);
  }
}

export class VariantSelection {
  public arch: ArchIdentity;
  public variant: VariantIdentity;
  constructor(arch: ArchIdentity, variant: VariantIdentity) {
    this.arch = arch;
    this.variant = variant;
  }

  public get selectionString(): string {
    const v = this.variant.getName().split("::").slice(-1);
    return `${this.arch.getName()}: ${v}`;
  }
}

/**
 * Data structurs for using identities in UI Components. This is designed to be
 * constructed with the response from {@link MetaService#getIdentityMapping}
 *
 * @export
 * @class IdentityRepo
 * @typedef {IdentityRepo}
 */
export class IdentityRepo {
  data: IdentityMappingResponse;

  allArchIdens: IdentifierSet;
  variantIdens: IdentifierSet;
  endianIdens: IdentifierSet;
  loaderIdens: IdentifierSet;
  backendIdens: IdentifierSet;

  allVariantSelectsions: VariantSelection[] = [];
  archIdens: IdentifierSet;

  supportedConfigs: SupportedConfig[];

  /**
   * Creates an instance of IdentityRepo. This is designed to be constructed
   * with the response from {@link MetaService#getIdentityMapping}
   *
   * @constructor
   * @param {IdentityMappingResponse} data
   */
  constructor(data: IdentityMappingResponse) {
    this.data = data;
    this.allArchIdens = new IdentifierSet(data.getArchIdensList());
    this.variantIdens = new IdentifierSet(data.getVariantIdensList());
    this.endianIdens = new IdentifierSet(data.getEndianIdensList());
    this.loaderIdens = new IdentifierSet(data.getLoaderIdensList());
    this.backendIdens = new IdentifierSet(data.getBackendIdensList());
    this.supportedConfigs = data.getSupportedConfigsList();
    this.data.getArchitecturesList().forEach((compatArch) => {
      const archIden = compatArch.getArchIdentity();
      if (archIden) {
        compatArch.getVariantsList().forEach((variantIden) => {
          const item = new VariantSelection(archIden, variantIden);
          this.allVariantSelectsions.push(item);
        });
      }
    });

    this.archIdens = new IdentifierSet(
      this.allVariantSelectsions
        .map((arch) => arch.arch)
        .filter((arch) => arch !== undefined)
    );
  }

  public variantsByArchName(archName: string): VariantSelection[] {
    const results: VariantSelection[] = [];
    this.allVariantSelectsions.forEach((s) => {
      if (archName == s.arch.getName()) {
        results.push(s);
      }
    });
    return results;
  }
}
