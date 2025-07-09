import { AfterViewInit, Component, OnDestroy, OnInit } from "@angular/core";
import {
  FormBuilder,
  FormControl,
  FormGroup,
  Validators
} from "@angular/forms";
import { MatRadioChange } from "@angular/material/radio";
import { ActivatedRoute, ParamMap, Router } from "@angular/router";
import { NgbTypeaheadSelectItemEvent } from "@ng-bootstrap/ng-bootstrap";
import { Observable, OperatorFunction, Subject } from "rxjs";
import {
  debounceTime,
  distinctUntilChanged,
  finalize,
  map
} from "rxjs/operators";
import {
  EmulationArgs,
  EmuRunLimits,
  RawEventLimits,
  SymbolSearchOptions,
  TracePluginArgs
} from "src/generated/args_pb";
import {
  ArchIdentity,
  BackendIdentity,
  Config,
  EndianIdentity,
  IdentityMappingResponse,
  LoaderIdentity,
  VariantIdentity
} from "src/generated/emulation_registry_pb";

import { ProgramsWithSymbols } from "src/generated/symbolic_pb";
import { FileRef, WsProgram } from "src/generated/workspace_pb";
import { Alert, ErrorAlert } from "../alert";
import { Rts } from "../app-routing.module";
import { ProgramWithSymbolsDisplay } from "../display/program-display";
import {
  IdentifierSet,
  IdentityRepo,
  INamedIdentifier,
  MetaService,
  VariantSelection
} from "../grpc-services/trace-app.service";
import { ProgramColumns } from "../programs/programs.component";
import { SessionMgrService } from "../session-mgr/session-mgr.service";
import { TraceService } from "../trace.service";

export const DEFAULT_SymbolSearchOptions = new SymbolSearchOptions()
  .setRegexInclude(".")
  .setMemReads(true)
  .setMemWrites(true);
export function symbolSearchOptionsFromObject(
  obj: SymbolSearchOptions.AsObject | undefined
): SymbolSearchOptions {
  return obj
    ? new SymbolSearchOptions()
        .setRegexInclude(obj.regexInclude)
        .setRegexExclude(obj.regexExclude)
        .setMemReads(obj.memReads)
        .setMemWrites(obj.memWrites)
        .setAnonReads(obj.anonReads)
        .setAnonWrites(obj.anonWrites)
    : DEFAULT_SymbolSearchOptions;
}
export const DEFAULT_RawEventLimits = new RawEventLimits();
export function rawEventLimitsFromObject(
  obj: RawEventLimits.AsObject | undefined
): RawEventLimits {
  return obj
    ? new RawEventLimits()
        .setId(obj.id)
        .setMaxInsn(obj.maxInsn)
        .setMaxMemReadEvents(obj.maxMemReadEvents)
        .setMaxMemWriteEvents(obj.maxMemWriteEvents)
    : DEFAULT_RawEventLimits;
}

export const DEFAULT_TracePluginArgs = new TracePluginArgs()
  .setInsnEvent(true)
  .setBlockEvent(false)
  .setInterruptEvent(false)
  .setReadMemoryEvent(false)
  .setWriteMemoryEvent(true);
export function tracePluginArgsFromObject(
  obj: TracePluginArgs.AsObject | undefined
): TracePluginArgs {
  return obj
    ? new TracePluginArgs()
        .setInsnEvent(obj.insnEvent)
        .setBlockEvent(obj.blockEvent)
        .setInterruptEvent(obj.interruptEvent)
        .setReadMemoryEvent(obj.readMemoryEvent)
        .setWriteMemoryEvent(obj.writeMemoryEvent)
    : DEFAULT_TracePluginArgs;
}

export const DEFAULT_EmuRunLimits = new EmuRunLimits()
  .setEmuMaxInsn(0)
  .setEmuSeconds(0);
export function emuRunLimitsFromObject(
  obj: EmuRunLimits.AsObject | undefined
): EmuRunLimits {
  return obj
    ? new EmuRunLimits()
        .setEmuMaxInsn(obj.emuMaxInsn)
        .setEmuSeconds(obj.emuSeconds)
    : DEFAULT_EmuRunLimits;
}

export enum FormControls {
  File = "file",
  WsProgramName = "wsProgramName", //y
  ArchIdentity = "architecture", //y
  VariantSelectionModel = "model", //y
  Endian = "endianIdent", //y
  Loader = "loaderIdent", //y
  Backend = "backendIdent", //y
  ProgramWithSymbols = "programsWithSymbols" //y
}

@Component({
  selector: "app-edit-program",
  templateUrl: "./edit-program.component.html",
  styleUrl: "./edit-program.component.css"
})
export class EditProgramComponent implements OnInit, AfterViewInit, OnDestroy {
  public Rts = Rts;
  public DEFAULT_TracePluginArgs = DEFAULT_TracePluginArgs;
  public DEFAULT_SymbolSearchOptions = DEFAULT_SymbolSearchOptions;
  public DEFAULT_RawEventLimits = DEFAULT_RawEventLimits;
  public DEFAULT_EmuRunLimits = DEFAULT_EmuRunLimits;
  tracePluginArgsVisible = false;
  symbolSearchOptionsVisible = false;
  rawEventLimitsVisible = false;
  emuRunLimitsVisible = false;

  busy = false;
  alerts: Alert[] = [];
  programForm: FormGroup;
  operation: "new" | "edit" = "new";
  editWsProgramId: number = 0;
  public FormControls = FormControls;
  public ProgramColumns = ProgramColumns;
  wsProgram = new WsProgram();
  loadingIdentities$ = new Subject();
  formatter = (result: VariantSelection) => result.selectionString;
  filteredArchs: VariantSelection[] = [];

  public get formFileName(): string {
    const file: File = this.programForm.get(FormControls.File)?.value;
    return file ? file.name : "";
  }

  identityRepo = new IdentityRepo(new IdentityMappingResponse());
  symbolSearchOptionsModelObj = DEFAULT_SymbolSearchOptions.toObject();
  rawEventLimitsModelObj = new RawEventLimits().toObject();
  tracePluginArgsModelObj = DEFAULT_TracePluginArgs.toObject();
  emuRunLimitsModelObj = DEFAULT_EmuRunLimits.toObject();

  /**
   * Constructor - get a list of architectures from metaService
   * @param traceService
   * @param metaService
   */
  constructor(
    private traceService: TraceService,
    private sessionService: SessionMgrService,
    private metaService: MetaService,
    private formBuilder: FormBuilder,
    private router: Router,
    private route: ActivatedRoute
  ) {
    this.programForm = this.formBuilder.group({
      [FormControls.File]: new FormControl<File | undefined>(undefined, [
        Validators.required
      ]),
      [FormControls.ArchIdentity]: new FormControl<ArchIdentity | undefined>(
        undefined,
        [Validators.required]
      ),
      [FormControls.WsProgramName]: new FormControl<string>("", [
        Validators.required
      ]),

      [FormControls.VariantSelectionModel]: new FormControl<
        VariantSelection | undefined
      >(undefined, [Validators.required]),
      // Endian
      [FormControls.Endian]: new FormControl<EndianIdentity | undefined>(
        undefined,
        [Validators.required]
      ),
      // Loader
      [FormControls.Loader]: new FormControl<LoaderIdentity | undefined>(
        undefined,
        [Validators.required]
      ),
      // Backend
      [FormControls.Backend]: new FormControl<BackendIdentity | undefined>(
        undefined,
        [Validators.required]
      ),
      [FormControls.ProgramWithSymbols]: new FormControl<
        ProgramWithSymbolsDisplay | undefined
      >(undefined, [Validators.required])
    });
  }

  ngOnDestroy(): void {}

  getIdentyRepo() {
    const alerts = this.alerts;
    this.metaService
      .getIdentityRepo()
      .pipe(
        finalize(() => {
          this.loadingIdentities$.complete();
        })
      )
      .subscribe({
        next: (idenRepo) => {
          this.identityRepo = idenRepo;
          this.filteredArchs = this.identityRepo.allVariantSelectsions;
        },
        error(err) {
          console.log(err.message);
          alerts.push(new ErrorAlert(err));
        },
        complete: () => {
          console.log("complete");
        }
      });
  }

  _parse(paramMap: ParamMap) {
    let editWsProgramId = 0;
    const op = paramMap.get("op");
    const id = paramMap.get("id");
    if (!op) {
      this.operation = "new";
    } else if (op === "new") {
      this.operation = "new";
    } else if (op === "edit" && id) {
      this.operation = "edit";
      editWsProgramId = parseInt(id);
      if (Number.isNaN(editWsProgramId)) {
        editWsProgramId = 0;
      }
    } else {
      this.operation = "new";
    }
    this.editWsProgramId = editWsProgramId;
  }

  isNew(): boolean {
    return !this.isEdit;
  }
  isEdit(): boolean {
    return this.editWsProgramId > 0;
  }
  isDirty(): boolean {
    return false;
  }

  parseUrlParams() {
    this.route.paramMap
      .pipe(
        finalize(() => {
          console.log(`finalize, service count:`);
        })
      )
      .subscribe({
        next: (params) => {
          try {
            this._parse(params);
          } catch (e) {
            this.alerts.push(new ErrorAlert(e as Error));
            console.error(e);
          }
        },
        error: (err) => console.log(err),
        complete: () => console.log("complete")
      });
  }

  ngOnInit() {
    this.getIdentyRepo();
    this.parseUrlParams();
  }

  ngAfterViewInit(): void {
    this.loadingIdentities$.subscribe({
      complete: () => {
        if (this.operation === "edit" && this.editWsProgramId > 0) {
          // We are editing a saved workspace program. Fetch the wsProgram to
          // get a full / fresh up-to-date copy
          let wsProgram: WsProgram | undefined = undefined;
          this.traceService.workspace
            .fetchFullWsProgramById(this.editWsProgramId)
            .subscribe({
              next: (w) => {
                wsProgram = w;
              },
              complete: () => {
                if (wsProgram) {
                  this.wsProgram = wsProgram;
                  this.doEdit();
                }
              }
            });
        }
      }
    });
  }

  public set formProgramsWithSymbols(
    value: ProgramWithSymbolsDisplay | null | undefined
  ) {
    this.programForm.get(FormControls.ProgramWithSymbols)?.setValue(value);
  }

  public set formVariantSelection(value: VariantSelection | null | undefined) {
    this.programForm.get(FormControls.VariantSelectionModel)?.setValue(value);
  }

  public get formVariantSelection(): VariantSelection {
    return this.programForm.get(FormControls.VariantSelectionModel)?.value;
  }

  public set formWsProgramName(value: string) {
    this.programForm.get(FormControls.WsProgramName)?.setValue(value);
  }

  setFormFileFromFileRef(file: FileRef | undefined) {
    if (file) {
      const name = file.getPath();
      const size = file.getSize();
      if (name && size) {
        this.programForm
          .get(FormControls.File)
          ?.setValue({ name: name, size: size });
      }
    }
  }

  /**
   * We have been routed to the page and we are editing a saved WsProgram,
   * now stored in this.wsProgram. Sychronize state.
   */
  doEdit() {
    this.formProgramsWithSymbols = new ProgramWithSymbolsDisplay(
      new ProgramsWithSymbols().setProgram(this.wsProgram.getSymProgram())
    );
    this.formVariantSelection = new VariantSelection(
      <ArchIdentity>this.wsProgram.getConfig()?.getArchIden(),
      <VariantIdentity>this.wsProgram.getConfig()?.getVariantIden()
    );
    this.formWsProgramName = this.wsProgram.getName();

    this.syncVariantSelection(this.formVariantSelection);
    const rawEventLimits = this.wsProgram.getLimits();
    this.rawEventLimitsModelObj = rawEventLimits
      ? rawEventLimits.toObject()
      : DEFAULT_RawEventLimits.toObject();
    const emuRunLimits = this.wsProgram.getEmulationArgs()?.getEmuRunLimits();
    this.emuRunLimitsModelObj = emuRunLimits
      ? emuRunLimits.toObject()
      : DEFAULT_EmuRunLimits.toObject();
    const tracePluginArgs = this.wsProgram
      .getEmulationArgs()
      ?.getTracePluginArgs();
    this.tracePluginArgsModelObj = tracePluginArgs
      ? tracePluginArgs.toObject()
      : DEFAULT_TracePluginArgs.toObject();
    const symbolSearchOptions = this.wsProgram.getSymbolOptions();
    this.symbolSearchOptionsModelObj = symbolSearchOptions
      ? symbolSearchOptions.toObject()
      : DEFAULT_SymbolSearchOptions.toObject();

    const config = this.wsProgram.getConfig();
    if (config) {
      this.setFormIdentity(
        FormControls.ArchIdentity,
        config.getArchIden(),
        this.identityRepo.archIdens
      );
      this.setFormIdentity(
        FormControls.Backend,
        config.getBackendIden(),
        this.identityRepo.backendIdens
      );
      this.setFormIdentity(
        FormControls.Endian,
        config.getEndianIden(),
        this.identityRepo.endianIdens
      );
      this.setFormIdentity(
        FormControls.Loader,
        config.getLoaderIden(),
        this.identityRepo.loaderIdens
      );
    }
    this.setFormFileFromFileRef(this.wsProgram.getFile());
  }

  close(alert: Alert) {
    this.alerts.splice(this.alerts.indexOf(alert), 1);
  }

  /**
   * typeahead search for selecting architecture
   * @param text$
   * @returns
   */
  architectureSearch: OperatorFunction<string, readonly VariantSelection[]> = (
    text$: Observable<string>
  ) =>
    text$.pipe(
      debounceTime(200),
      distinctUntilChanged(),
      map((term) =>
        term.length < 1
          ? []
          : this.filteredArchs
              .filter(
                (v) =>
                  v.arch.getName().toLowerCase().indexOf(term.toLowerCase()) >
                    -1 ||
                  v.variant
                    .getName()
                    .toLowerCase()
                    .indexOf(term.toLowerCase()) > -1
              )
              .slice(0, 1000)
      )
    );

  public get fileInfo(): string {
    const file: File = this.programForm.get(FormControls.File)?.value;
    return file ? `${file.name} ${file.size}` : "";
  }

  onProgramSelected(program: ProgramWithSymbolsDisplay) {
    this.programForm.get(FormControls.ProgramWithSymbols)?.setValue(program);
  }

  setFormIdentity(
    ctrlName: string,
    value: INamedIdentifier | undefined,
    idens: IdentifierSet
  ) {
    this.programForm.get(ctrlName)?.setValue(idens.getSameItemById(value));
  }

  public get selectedProgram(): ProgramWithSymbolsDisplay | undefined {
    return this.programForm.get(FormControls.ProgramWithSymbols)?.value;
  }

  syncVariantSelection(v: VariantSelection) {
    this.setFormIdentity(
      FormControls.ArchIdentity,
      v.arch,
      this.identityRepo.archIdens
    );
  }

  /**
   * Arch/variant control is chosen (VariantSelection)
   */
  onSelect($event: NgbTypeaheadSelectItemEvent) {
    this.syncVariantSelection($event.item);
  }

  /**
   *  event from selecting the architecture
   */
  onArchtectureSelected($event: MatRadioChange) {
    this.filteredArchs = this.identityRepo.variantsByArchName(
      <string>$event.value.getName()
    );
    this.programForm
      .get(FormControls.VariantSelectionModel)
      ?.setValue(undefined);
  }

  cancelUpload() {
    // this.uploadSub.unsubscribe();
    this.reset();
  }

  onFileSelected(event: Event) {
    const target = event.target as HTMLInputElement;
    if (target.files?.length) {
      this.programForm.get(FormControls.File)?.setValue(target.files[0]);
    }
  }

  get architecture(): VariantSelection {
    const a = this.programForm.get(FormControls.VariantSelectionModel);
    return a ? a.value : {};
  }

  reset() {
    this.programForm.get(FormControls.File)?.setValue(undefined);
  }

  onSubmit() {
    console.log("submit...");
    if (this.programForm?.valid) {
      this.busy = true;
      const archIden: ArchIdentity = this.programForm.get(
        FormControls.ArchIdentity
      )?.value;
      const variantIden: VariantIdentity = this.programForm.get(
        FormControls.VariantSelectionModel
      )?.value.variant;
      const endianIden: EndianIdentity = this.programForm.get(
        FormControls.Endian
      )?.value;
      const loaderIden: LoaderIdentity = this.programForm.get(
        FormControls.Loader
      )?.value;
      const backendIden: BackendIdentity = this.programForm.get(
        FormControls.Backend
      )?.value;

      const file = this.programForm.get(FormControls.File)?.value;
      const pws = <ProgramWithSymbolsDisplay>(
        this.programForm.get(FormControls.ProgramWithSymbols)?.value
      );

      pws.program
        .getArchitecture()
        ?.setProcessor(archIden.getName())
        .setVariant(variantIden.getName());
      pws.program.getPid()?.setName(file.name);
      pws.program
        .getMetadata()
        ?.setName(file.name)
        .setPath("")
        .setFileSize(file.size);

      this.wsProgram
        .setConfig(
          new Config()
            .setArchIden(archIden)
            .setEndianIden(endianIden)
            .setVariantIden(variantIden)
            .setLoaderIden(loaderIden)
            .setBackendIden(backendIden)
        )
        .setSymProgram(pws.program)
        .setSymbolsList(pws.symbols)
        .setDataTypesList(pws.datatypes)
        .setName(this.programForm.get(FormControls.WsProgramName)?.value)
        .setEmulationArgs(
          new EmulationArgs()
            .setTracePluginArgs(
              tracePluginArgsFromObject(this.tracePluginArgsModelObj)
            )
            .setEmuRunLimits(emuRunLimitsFromObject(this.emuRunLimitsModelObj))
        )
        .setLimits(rawEventLimitsFromObject(this.rawEventLimitsModelObj))
        .setSymbolOptions(
          symbolSearchOptionsFromObject(this.symbolSearchOptionsModelObj)
        );

      if (file) {
        let hasErr = false;
        this.traceService.workspace
          .upsertWsProgram(this.wsProgram, file)
          .subscribe({
            next: (response) => {
              this.alerts.push(new Alert("success", response.toString()));
            },
            error: (e) => {
              hasErr = true;
              this.alerts.push({
                type: "danger",
                message: e.toString()
              });
              this.busy = false;
              console.error("Error saving data:", e);
            },
            complete: () => {
              this.busy = false;
              if (!hasErr) {
                this.router.navigate([Rts.WspList]);
              }
            }
          });
      } else {
        this.busy = false;
      }
    }
  }
}
