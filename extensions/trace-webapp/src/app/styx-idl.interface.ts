// SPDX-License-Identifier: BSD-2-Clause
import {
  EmuRunLimits,
  EmulationArgs,
  ProgramIdentifierArgs,
  RawEventLimits,
  RawLoaderArgs,
  RawTraceArgs,
  SymbolSearchOptions,
  Target,
  TraceAppSessionArgs,
  TracePluginArgs
} from "src/generated/args_pb";

export interface ITraceAppSessionArgs {
  getId(): number;
  getMode(): TraceAppSessionArgs.TraceMode;
  getSessionId(): string;
  getResume(): boolean;
  getPid(): ProgramIdentifierArgs | undefined;
  hasPid(): boolean;
  getTraceFilepath(): string;
  getRawTraceArgs(): RawTraceArgs | undefined;
  hasRawTraceArgs(): boolean;
  getEmulationArgs(): EmulationArgs | undefined;
  hasEmulationArgs(): boolean;
  getLimits(): RawEventLimits | undefined;
  hasLimits(): boolean;
  getSymbolOptions(): SymbolSearchOptions | undefined;
  hasSymbolOptions(): boolean;
}

export interface IEmulationArgs {
  getId(): number;
  getTarget(): Target;
  getFirmwarePath(): string;
  getTracePluginArgs(): TracePluginArgs | undefined;
  hasTracePluginArgs(): boolean;
  getEmuRunLimits(): EmuRunLimits | undefined;
  hasEmuRunLimits(): boolean;
  getRawLoaderArgs(): RawLoaderArgs | undefined;
  hasRawLoaderArgs(): boolean;
  getIpcPort(): number;
}

export interface IRawEventLimits {
  getId(): number;
  getMaxInsn(): number;
  getMaxMemReadEvents(): number;
  getMaxMemWriteEvents(): number;
}

export interface IProgramIdentifierArgs {
  getName(): string;
  getSourceId(): string;
}

export interface IRawTraceArgs {
  getTraceDirectory(): string;
  getTraceWaitFile(): boolean;
}

export interface ITracePluginArgs {
  getInsnEvent(): boolean;
  getWriteMemoryEvent(): boolean;
  getReadMemoryEvent(): boolean;
  getInterruptEvent(): boolean;
  getBlockEvent(): boolean;
}

export interface IGdbPluginArgs {
  getRemotePort(): number;
}

export interface IRawLoaderArgs {
  getBaseAddr(): number;
  getValidRangeMin(): number;
  getValidRangeMax(): number;
}

export interface IEmuRunLimits {
  getEmuMaxInsn(): number;
  getEmuSeconds(): number;
}
