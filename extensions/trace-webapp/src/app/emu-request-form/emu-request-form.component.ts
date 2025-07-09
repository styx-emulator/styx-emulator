// SPDX-License-Identifier: BSD-2-Clause
import { Location } from "@angular/common";
import {
  AfterViewInit,
  ChangeDetectorRef,
  Component,
  EventEmitter,
  OnInit,
  Output
} from "@angular/core";
import { ActivatedRoute, Router } from "@angular/router";

import { MatRadioChange } from "@angular/material/radio";
import {
  EmulationArgs,
  SymbolSearchOptions,
  Target,
  TracePluginArgs
} from "src/generated/args_pb";
import { Architecture as ArchEnum } from "src/generated/emulation_pb";
import {
  Program,
  ProgramFilter,
  ProgramIdentifier
} from "src/generated/symbolic_pb";
import { Alert, ALERT_OK } from "../alert";
import { Rts } from "../app-routing.module";
import {
  TRACE_MODE_EMULATED,
  TRACE_MODE_RAW,
  TRACE_MODE_SRB
} from "../app-session-interface";
import { TraceRequestDisplay } from "../display/trace-request-display";
import { FirmwareService, Variants } from "../firmware.service";
import { SessionMgrService } from "../session-mgr/session-mgr.service";
import {
  DEFAULT_TRACE_PLUGIN_ARGS,
  getEndianDesc,
  TraceService
} from "../trace.service";

export class TargetChoiceModel {
  target: Target;
  architecture: ArchEnum;
  variant: string;

  // Firmware lists
  private _firmwares: Array<string> = [];
  public get firmwares(): Array<string> {
    return this._firmwares;
  }
  public set firmwares(v: Array<string>) {
    this._firmwares = v;
  }

  // Ghidra Programs
  private _ghidraPrograms: Array<Program> = [];
  public get ghidraPrograms(): Array<Program> {
    return this._ghidraPrograms;
  }

  // Selections
  private _selectedFirmwarePath: string = "";
  public get selectedFirmwarePath(): string {
    return this._selectedFirmwarePath;
  }
  public set selectedFirmwarePath(v: string) {
    this._selectedFirmwarePath = v;
  }

  private _selectedGhidraProgram: Program | undefined;
  public get selectedGhidraProgram(): Program | undefined {
    return this._selectedGhidraProgram;
  }
  public set selectedGhidraProgram(v: Program) {
    this._selectedGhidraProgram = v;
  }

  toString(): string {
    switch (this.target) {
      case Target.KINETIS21:
        return "KINETIS21 (" + this.variant + ")";
      case Target.POWERQUICC:
        return "PowerQUICC (" + this.variant + ")";
      case Target.STM32F107:
        return "STM32F107 (" + this.variant + ")";
      case Target.CYCLONEV:
        return "CYCLONE V (" + this.variant + ")";
      case Target.BLACKFIN512:
        return "BLACKFIN (" + this.variant + ")";
    }
  }

  constructor(target: Target) {
    this.target = target;
    const fwsvc = new FirmwareService();

    this.variant = fwsvc.getVariant(this.target);
    this.architecture = fwsvc.getArchitecture(this.target);

    this._firmwares = fwsvc.getAvailableFirmwares(this.variant);
  }

  populateFromGhidraPrograms(ghidraPrograms: Array<Program>): void {
    const result = new Array<Program>();
    ghidraPrograms.forEach((gp) => {
      if (gp.getArchitecture()?.getVariant() == this.variant) {
        result.push(gp);
      }
    });

    this._ghidraPrograms = result;
    if (this._ghidraPrograms.length >= 0)
      this.selectedGhidraProgram = this._ghidraPrograms[0];
    if (this._firmwares.length > 0)
      this.selectedFirmwarePath = this._firmwares[0];
  }
}

@Component({
  selector: "app-emu-request-form",
  templateUrl: "./emu-request-form.component.html",
  styleUrls: ["./emu-request-form.component.css"]
})
export class EmuRequestFormComponent implements OnInit, AfterViewInit {
  public Rts = Rts;
  EMULATED = TRACE_MODE_EMULATED;
  RAW = TRACE_MODE_RAW;
  SRB = TRACE_MODE_SRB;
  alerts: Alert[] = [];

  @Output() newRequestSaveEvent = new EventEmitter<TraceRequestDisplay>();

  // list of ghidra programs (from typhunix)
  ghidraPrograms: Array<Program> = [];

  waitForTraceFile = false;
  traceFilename = "/tmp/sample2.raw";
  traceDirectory = "/tmp";

  // traceMode: "file" | "emu" | "srb" = "emu";
  traceMode = TRACE_MODE_EMULATED;

  targetChoiceModels = new Array<TargetChoiceModel>();

  targetModel: TargetChoiceModel | undefined;

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  onTargetChange(_e: MatRadioChange): void {}

  tracePluginArgsModel = new TracePluginArgs().toObject();
  symbolOptionsModel = new SymbolSearchOptions()
    .setRegexInclude(".")
    .setMemWrites(true)
    .setAnonWrites(false)
    .setMemReads(false)
    .setAnonWrites(false)
    .toObject();

  constructor(
    private sessionService: SessionMgrService,
    private traceService: TraceService,
    private changeDetectorRef: ChangeDetectorRef,
    private route: ActivatedRoute,
    private location: Location,
    private router: Router
  ) {
    const TCM_KINETIS21 = new TargetChoiceModel(Target.KINETIS21);
    const TCM_POWERQUICC = new TargetChoiceModel(Target.POWERQUICC);
    const TCM_STM32F107 = new TargetChoiceModel(Target.STM32F107);
    const TCM_CYCLONEV = new TargetChoiceModel(Target.CYCLONEV);
    const TCM_BLACKFIN512 = new TargetChoiceModel(Target.BLACKFIN512);
    this.targetChoiceModels.push(TCM_KINETIS21);
    this.targetChoiceModels.push(TCM_POWERQUICC);
    this.targetChoiceModels.push(TCM_STM32F107);
    this.targetChoiceModels.push(TCM_CYCLONEV);
    this.targetChoiceModels.push(TCM_BLACKFIN512);
  }

  // Get a list of ghidra program from typhunix
  // For now, ghidra programs are required, so its an error if we
  // can't connect to typhunix or if the list is zero
  getAllPrograms(): Array<Program> {
    // const filter = new ProgramFilter();
    const programs: Array<Program> = [];
    this.traceService.typhunix.getPrograms(new ProgramFilter()).subscribe({
      next: (program) => {
        this.hackTheMissingVariant(program);
        programs.push(program);
        this.ghidraPrograms.push(program);
      },
      error: (error) => {
        console.log(error);
      },
      complete: () => {
        this.targetChoiceModels.forEach((tcm) => {
          tcm.populateFromGhidraPrograms(this.ghidraPrograms);
        });
      }
    });

    return programs;
  }

  hackTheMissingVariant(p: Program) {
    // (3524872547775184128, xxxxxxx.bin), Symbol count: 6401, DataType count: 329
    //  Architecture { processor: "ARM", variant: "", endian: EndianLittle, bits: 32 }
    //  Loader: Raw Binary
    if (p.getPid()?.getSourceId() == "3524872547775184128") {
      p.getArchitecture()?.setVariant(Variants.ArmCortexM4);
    }

    // (3566400022545058101, arm_stm32f107_blink_gpio.elf), Symbol count: 1426, DataType count: 425
    //  Architecture { processor: "ARM", variant: "", endian: EndianLittle, bits: 32 }
    //  Loader: Executable and Linking Format(ELF)
    if (p.getPid()?.getSourceId() == "3566400022545058101") {
      p.getArchitecture()?.setVariant(Variants.ArmCortexM3);
    }

    // (3564241829337339496, xxxxxxxxxxxxxxxxxxxxx.bin), Symbol count: 16190, DataType count: 138
    //  Architecture { processor: "PowerPC", variant: "", endian: EndianBig, bits: 32 }
    //  Loader: Raw Binary
    if (p.getPid()?.getSourceId() == "3564241829337339496") {
      p.getArchitecture()?.setVariant(Variants.Mpc852T);
    }

    // ** using ELF symbols **
    // (3583431914863969652,application.axf), Symbol count: 3737, DataType count: 962
    // Architecture { processor: "ARM", variant: "", endian: EndianLittle, bits: 32 }
    // Loader: Executable and Linking Format (ELF)
    // ** using ELF symbols **
    if (p.getPid()?.getSourceId() == "3583431914863969652") {
      p.getArchitecture()?.setVariant(Variants.ArmCortexA9);
    }

    // Blackfin bf512
    if (p.getPid()?.getSourceId() == "3610965975498840604") {
      p.getArchitecture()?.setVariant(Variants.Bf512);
    }
  }

  ngOnInit(): void {
    const dflt = DEFAULT_TRACE_PLUGIN_ARGS.toObject();
    this.tracePluginArgsModel.insnEvent = dflt.insnEvent;
    this.tracePluginArgsModel.interruptEvent = dflt.interruptEvent;
    this.tracePluginArgsModel.readMemoryEvent = dflt.readMemoryEvent;
    this.tracePluginArgsModel.writeMemoryEvent = dflt.writeMemoryEvent;
    this.getAllPrograms();
  }

  ngAfterViewInit(): void {
    this.changeDetectorRef.detectChanges();
  }

  /**
   * The user saved the emulation inputs
   * Persist the TraceRequest (locally, a TraceRequestDisplay)
   * On success, route to sessions list.
   */
  // user saved emulation inputs
  save(): void {
    const newRequest = this.getInitializeTraceRequest();
    if (newRequest) {
      let hasErr = false;
      this.sessionService.saveTraceRequest(newRequest).subscribe({
        next: (savedRequest) => {
          // this is the persisted database entity
          this.newRequestSaveEvent.emit(savedRequest);
          this.alerts.push(ALERT_OK);
        },
        error: (e) => {
          hasErr = true;
          this.alerts.push({
            type: "danger",
            message: e.toString()
          });
          console.error("Error saving data:", e);
        },
        complete: () => {
          if (!hasErr) {
            this.resetForm();
            this.router.navigate([Rts.SessionList]);
          }
        }
      });
    }
  }

  resetForm() {
    this.targetModel = undefined;
  }

  getProgramLabel(p: Program) {
    return (
      `${p.getArchitecture()?.getProcessor()} ` +
      `${p.getArchitecture()?.getBits()} ` +
      `${getEndianDesc(p.getArchitecture()?.getEndian())} ` +
      `(${p.getPid()?.getName()})`
    );
  }

  // construct a tooltip for the Program
  programToolTip(p: Program) {
    return (
      `Source ID: ${p.getPid()?.getSourceId()},  ` +
      `#Functions: ${p.getFunctionsList().length},  ` +
      `Loader: ${p.getMetadata()?.getLoader()}`
    );
  }

  // Collect data from the form, construct a TraceRequest
  getInitializeTraceRequest(): TraceRequestDisplay | undefined {
    if (this.targetModel?.selectedGhidraProgram) {
      const program = <Program>this.targetModel?.selectedGhidraProgram;
      const traceRequest: TraceRequestDisplay =
        this.sessionService.createTraceRequest(
          this.traceMode.enumVal,
          this.traceDirectory,
          this.traceFilename,
          this.waitForTraceFile,
          this.symbolOptionsModel,
          program
        );
      traceRequest.pid = <ProgramIdentifier>program.getPid();
      if (this.traceMode == TRACE_MODE_EMULATED) {
        if (this.targetModel && this.targetModel?.selectedGhidraProgram) {
          const firmwarePath = this.targetModel.selectedFirmwarePath;
          if (firmwarePath) {
            traceRequest.emulation_args = new EmulationArgs()
              .setTarget(this.targetModel.target)
              .setFirmwarePath(firmwarePath)
              .setTracePluginArgs(
                new TracePluginArgs()
                  .setInsnEvent(this.tracePluginArgsModel.insnEvent)
                  .setInterruptEvent(this.tracePluginArgsModel.interruptEvent)
                  .setWriteMemoryEvent(
                    this.tracePluginArgsModel.writeMemoryEvent
                  )
                  .setReadMemoryEvent(this.tracePluginArgsModel.readMemoryEvent)
              );
          }
        }
      }

      if (traceRequest.validate()) {
        return traceRequest;
      }
    }
    return undefined;
  }

  validateRequest(): boolean {
    if (this.targetModel) {
      if (this.traceMode == TRACE_MODE_RAW)
        return this.targetModel?.selectedGhidraProgram != undefined;
      else if (this.traceMode == TRACE_MODE_EMULATED) {
        return (
          this.targetModel?.selectedGhidraProgram != undefined &&
          this.targetModel?.selectedFirmwarePath != undefined
        );
      }
    }
    return false;
  }

  close(alert: Alert) {
    this.alerts.splice(this.alerts.indexOf(alert), 1);
  }

  onCancel() {
    this.resetForm();
    this.router.navigate([Rts.SessionList]);
  }
}
