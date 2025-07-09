// SPDX-License-Identifier: BSD-2-Clause
import { TraceAppSessionArgs } from "src/generated/args_pb";

export class TraceModeExt {
  private _enumVal: TraceAppSessionArgs.TraceMode;

  public get enumVal(): TraceAppSessionArgs.TraceMode {
    return this._enumVal;
  }

  constructor(enum_val: TraceAppSessionArgs.TraceMode) {
    this._enumVal = enum_val;
  }
  toString(): string {
    switch (this._enumVal) {
      case TraceAppSessionArgs.TraceMode.RAW:
        return "RAW";
      case TraceAppSessionArgs.TraceMode.EMULATED:
        return "EMULATED";
      case TraceAppSessionArgs.TraceMode.SRB:
        return "SRB";
    }
  }

  public get isSrb(): boolean {
    return this._enumVal == TraceAppSessionArgs.TraceMode.SRB;
  }
  public get isRaw(): boolean {
    return this._enumVal == TraceAppSessionArgs.TraceMode.RAW;
  }
  public get isEmulation(): boolean {
    return this._enumVal == TraceAppSessionArgs.TraceMode.EMULATED;
  }
}

export const TRACE_MODE_EMULATED = new TraceModeExt(
  TraceAppSessionArgs.TraceMode.EMULATED
);
export const TRACE_MODE_RAW = new TraceModeExt(
  TraceAppSessionArgs.TraceMode.RAW
);
export const TRACE_MODE_SRB = new TraceModeExt(
  TraceAppSessionArgs.TraceMode.SRB
);
