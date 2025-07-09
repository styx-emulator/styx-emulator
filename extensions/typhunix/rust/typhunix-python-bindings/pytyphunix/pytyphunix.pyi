from enum import Enum

uint64 = int
int64 = int
int32 = int
uint32 = int

from . import pytyphunix  # noqa

class EndianType(Enum): ...  # noqa E701
class RefType(Enum): ...  # noqa E701
class MetaType(Enum): ...  # noqa E701
class SymbolType(Enum): ...  # noqa E701

class Architecture:  # noqa E302:
    processor: str
    variant: str
    endian: EndianType
    bits: int32

class FunctionParameter:  # noqa E302:
    name: str
    data_type_name: str
    reg_source: str
    stack_source: int32

class FunctionSymbol:  # noqa E302
    last_insn: int64
    parameters: list[FunctionParameter]

class ProgramIdentifier:  # noqa E302
    name: str
    source_id: str

class FileMetadata:  # noqa E302
    name: str
    path: str
    sha256: bytes
    file_size: int64
    loader: str

class Segment:  # noqa E302
    id: uint64
    name: str
    address: int64
    size: int64
    address_size: int32
    alignment: uint32
    endian: EndianType
    read: bool
    write: bool
    execute: bool
    external: bool
    data: bytes

class CrossReference:  # noqa E302
    id: uint64
    src: uint64
    dst: uint64
    type: RefType

class BasicBlock:  # noqa E302
    id: uint64
    address: uint64
    size: uint32
    predecessors: list[CrossReference]
    successors: list[CrossReference]

class Function:  # noqa E302
    id: uint64
    symbol: Symbol
    callers: list[CrossReference]
    blocks: list[BasicBlock]

class Program:  # noqa E302
    pid: ProgramIdentifier
    unused01: str
    architecture: Architecture
    functions: list[Function]
    metadata: list[FileMetadata]
    segments: list[Segment]

class DataType:  # noqa E302
    id: uint64
    name: str
    size: int32
    type: MetaType
    alignment: uint32
    base_data_type_name: str
    offset: int32

class Symbol:  # noqa E302
    id: uint64
    name: str
    address: int64
    namespace: str
    type: SymbolType
    datatype_name: str
    data_size: int64
    FunctionSymbol: FunctionSymbol
    pid: ProgramIdentifier

def __dummy(): ...  # noqa E302
def pids(name: str, source_id: str) -> list[ProgramIdentifier]: ...
def data_types(name: str, source_id: str) -> list[DataType]: ...
def symbols(name: str, source_id: str) -> list[Symbol]: ...
def symbols_json(name: str, source_id: str) -> list[str]: ...
def data_types_json(name: str, source_id: str) -> list[str]: ...
def is_running() -> bool: ...
