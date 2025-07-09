import {
  Architecture,
  DataType,
  FileMetadata,
  // eslint-disable-next-line no-new-symbol
  Symbol as GSymbol,
  Program,
  ProgramIdentifier,
  ProgramsWithSymbols
} from "../../generated/symbolic_pb";

/**
 * UI Wrapper class for {@link ProgramsWithSymbols}
 */
export class ProgramWithSymbolsDisplay {
  programWithSymbols: ProgramsWithSymbols;

  private _program: Program;
  private _pid: ProgramIdentifier;
  private _architecture: Architecture;
  private _fileMetadata: FileMetadata;

  /**
   * Constructor
   * @param programWithSymbols a {@link ProgramsWithSymbols} message that
   * - must have a Program
   * - the program must have ProgramIdentifier, Architecture, FileMetadata
   */
  constructor(programWithSymbols: ProgramsWithSymbols) {
    if (!programWithSymbols.getProgram()) {
      throw new Error("ProgramsWithSymbols has no Program");
    }
    this._program = programWithSymbols.getProgram() as Program;

    const _architecture = this._program.getArchitecture();
    const _pid = this._program.getPid();
    const _fileMetadata = this._program.getMetadata();
    if (!_architecture) {
      throw new Error("Program has no Architecture");
    }
    if (!_pid) {
      throw new Error("Program has no ProgramIdentifier (Pid)");
    }
    if (!_fileMetadata) {
      throw new Error("Program has no FileMetadata");
    }
    this._pid = _pid;
    this._architecture = _architecture;
    this._fileMetadata = _fileMetadata;
    this.programWithSymbols = programWithSymbols;
  }

  public get program(): Program {
    return this._program;
  }

  public get symbols(): GSymbol[] {
    return this.programWithSymbols.getSymbolsList();
  }

  public get datatypes(): DataType[] {
    return this.programWithSymbols.getDataTypesList();
  }

  public get symbolCount(): number {
    return this.symbols.length;
  }
  public get dataTypeCount(): number {
    return this.datatypes.length;
  }

  public get architecture(): Architecture {
    return this._architecture;
  }

  public get pid(): ProgramIdentifier {
    return this._pid;
  }

  public get archStr(): string {
    return (
      `${this.architecture.getProcessor()} ` +
      `${this.architecture.getVariant()}` +
      `${this.endian} ` +
      `${this.architecture.getBits()} `
    );
  }

  public get endian(): string {
    switch (this._architecture.getEndian()) {
      case Architecture.EndianType.ENDIAN_LITTLE:
        return "LE";
      case Architecture.EndianType.ENDIAN_BIG:
        return "BE";
      case Architecture.EndianType.ENDIAN_MIDDLE:
        return "DE";
      case Architecture.EndianType.ENDIAN_MIXED:
        return "MX";
    }
  }

  public get pidName(): string {
    return this._pid.getName();
  }

  public get pidSource(): string {
    return this._pid.getSourceId();
  }
}
