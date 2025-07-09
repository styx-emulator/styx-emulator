# SPDX-License-Identifier: BSD-2-Clause
from .pytyphunix import *  # noqa F403
from enum import Enum
import json
from typing import Any, Dict, List, Union
import sys
from os import getenv

from packaging.version import Version


TyphunixSymbolDict = Dict[str, Union[str, int, List]]
"""TyphunixSymbol"""

TyphunixDataTypeDict = Dict[str, Union[str, int, List]]
"""TyphunixDataType"""

DragonStateDataTypeDict = Dict[str, Union[str, int, List]]
"""DragonStateDataTypeDict"""

DragonStateSymbolDict = Dict[str, Union[str, int, List]]
"""DragonStateDataTypeDict"""


class _MetaType(Enum):
    """Typhunix DataType types"""

    TYPE_BASIC = 0
    TYPE_STRUCT = 1
    TYPE_ARRAY = 2
    TYPE_UNION = 3
    TYPE_ENUM = 4
    TYPE_BITFIELD = 5


def type_int_to_str(sym_type: int) -> str:
    """Convert int from enum (0-9) to a lower case string to
    be consistent with the `create_symbol` factory.

    Returns
    -------
    str
        lowercase str corresponding to the int value

    Exceptions
    ----------
    KeyError if the int is not a recognized type enum#

    """
    return {
        0: "CLASS".lower(),
        1: "FUNCTION".lower(),
        2: "GLOBAL".lower(),
        3: "GLOBAL_VAR".lower(),
        4: "LABEL".lower(),
        5: "LIBRARY".lower(),
        6: "LOCAL_VAR".lower(),
        7: "NAMESPACE".lower(),
        8: "PARAMETER".lower(),
    }[sym_type]


class TyphunixServer:
    """Helper class for connecting using python to comminicate with the
    Typhunix server using the :class:`TyphunixServer` class.
    Environment Variables
    ---------------------
    `TYPHUNIX_URL` - the `http` URL where the server is running

    Example: `TYPHUNIX_URL=http://172.22.244.151:50051`

    Parameters
    ----------
    :param name: The name of the program, for example
        `umodem2_2.0.33466_20220726-173655.bin`

    :param source_id: The source_id of the program, for example
        `3504416731729177575`

    Examples
    --------
    if the server is running, print all fetch symbols and data_types for
    each :class:`ProgramIdentifier`

    >>> from pytyphunix import TyphunixServer, ProgramIdentifier
    >>> from pytyphunix import Symbol, DataType
    >>> TyphunixServer.is_running():
    >>> all_pids: list[ProgramIdentifier]
    >>  all_pids = TyphunixServer.pids()
    >>> for pid in all_pids:
    >>>     cnx = TyphunixServer(pid.name, pid.source_id)
    >>>     all_symbols: list[Symbol] = cnx.symbols()
    >>>     all_datypes: list[DataType] = cnx.data_types()
    >>>     ...
    """

    name: str
    source_id: str

    def __init__(self, name: str, source_id: str):
        """Constructor for ``TyphunixServer``

        :param name: the name of the program
        :param source_id: the source_id of the program
        """
        self.name = name
        self.source_id = source_id
        self.host = TyphunixServer.TYPHUNIX_URL

    def symbols_dict(
        self, version: Version, exclude_new_fields: bool = True
    ) -> List[Dict[str, Any]]:
        """Retrieve and returns a list of symbols dicts, one per symbol.
        Parameters
        ----------
        version: :class:`Version`
            The version of the data. If `version < 1.0.0`, the "DragonState"
            version of the dict is returned
        exclude_new_fields: bool
            Only applcable when `version < 1.0.0`, new fields will be included
            in the return dicts
        """
        v2_dicts = pytyphunix.symbols_json(self.name, self.source_id)
        return (
            [
                TyphunixServer.symbol_to_v0(
                    json.loads(r), exclude_new_fields=exclude_new_fields
                )
                for r in v2_dicts
            ]
            if version < Version("1.0.0")
            else [json.loads(r) for r in v2_dicts]
        )

    def data_types_dict(
        self, version: Version, exclude_new_fields: bool = True
    ) -> List[Dict[str, Any]]:
        """Retrieve and returns a list of data_type dicts, one per data type.
        Parameters
        ----------
        version: :class:`Version`
            The version of the data. If `version < 1.0.0`, the "DragonState"
            version of the dict is returned
        exclude_new_fields: bool
            Only applcable when `version < 1.0.0`, new fields will be included
            in the return dicts
        """
        v2_dicts = pytyphunix.data_types_json(self.name, self.source_id)
        return (
            [
                TyphunixServer.data_type_to_v0(
                    json.loads(r), exclude_new_fields=exclude_new_fields
                )
                for r in v2_dicts
            ]
            if version < Version("1.0.0")
            else [json.loads(r) for r in v2_dicts]
        )

    def symbols(self) -> List[pytyphunix.Symbol]:
        return pytyphunix.symbols(self.name, self.source_id)

    def data_types(self) -> List[pytyphunix.DataType]:
        return pytyphunix.data_types(self.name, self.source_id)

    @classmethod
    def symbol_to_v0(
        cls, symb_dict: TyphunixSymbolDict, exclude_new_fields=True
    ) -> DragonStateSymbolDict:
        """convert symbol data from typhunix version to a version
        compatible with the SymbolManager/create_symbol factory

        Parameters
        ----------
        sym : a typhunix symbol dict

        exclude_new_fields : bool=True
            If True, do not convert fields that the symbol manager does not
            use. If False, the fields will be placed on the converted
            symbol data.

        Returns
        -------
        DragonStateSymbolDict
            dict compatible with the SymbolManager/create_symbol factory
        """
        # covert type enum into to str
        symb_dict["type"] = type_int_to_str(symb_dict.get("type"))

        # data_size ==> len
        symb_dict["len"] = symb_dict.get("data_size")

        # "function_symbol.parameters" ==> "args"
        symb_dict["args"] = []
        function_symbol = symb_dict.get("function_symbol")
        if function_symbol is not None:
            symb_dict["last_insn"] = function_symbol.get("last_insn")
            for p in function_symbol.get("parameters"):
                p["type"] = p.get("data_type_name")
                stack_src = p.get("stack_source")
                reg_src = p.get("reg_source")
                p["source"] = f"sp + {stack_src}" if stack_src > 0 else reg_src
            symb_dict["args"] = function_symbol.get("parameters")
        else:
            symb_dict["type"] = symb_dict.get("datatype_name")

        # if the record does not yet have a type, tag it as "label"
        if not symb_dict["type"]:
            symb_dict["type"] = "label"

        if exclude_new_fields:
            for fld in (
                "datatype_name",
                "pid",
                "namespace",
                "id",
                "data_size",
                "function_symbol",
            ):
                if fld in symb_dict:
                    del symb_dict[fld]

        return symb_dict

    @classmethod
    def data_type_to_v0(
        cls, dtyp_dict: TyphunixDataTypeDict, exclude_new_fields=True
    ) -> DragonStateDataTypeDict:
        """convert DataType data from typhunix version to a version
        compatible with the DataTypeManager/create_data_type factory

        Parameters
        ----------
        exclude_new_fields : bool=True
            If True, do not convert fields that the symbol manager does not
            use. If False, the fields will be placed on the converted
            symbol data.

        Returns
        -------
        DragonStateDataTypeDict
            dict compatible with the DataTypeManager/create_symbol factory
        """
        # Rename children => attributes
        if "children" in dtyp_dict:
            dtyp_dict["attributes"] = dtyp_dict.get("children")

        # Convert type to is_* vernacular
        typeval = _MetaType(dtyp_dict.get("type"))
        tmap = {
            _MetaType.TYPE_BASIC: dict(is_basic=1, is_struct=0),
            _MetaType.TYPE_STRUCT: dict(is_struct=1),
            _MetaType.TYPE_ARRAY: dict(is_array=1, is_struct=0),
            _MetaType.TYPE_UNION: dict(is_union=1, is_struct=1),
            _MetaType.TYPE_ENUM: dict(is_enum=1, is_struct=0),
            _MetaType.TYPE_BITFIELD: dict(is_basic=1, is_struct=0),
        }
        dtyp_dict.update(tmap[typeval])

        if dtyp_dict.get("is_struct", 0) == 1:
            # if its a struct, rename the attributes
            old_attrs = dtyp_dict.get("children")
            dtyp_dict["attributes"] = []
            for attr in old_attrs:
                # Rename attributes
                dtyp_dict["attributes"].append(
                    dict(
                        name=attr["name"],
                        offset=attr["offset"],
                        size=attr["size"],
                        data_type=attr.get("base_data_type_name"),
                    )
                )

        if exclude_new_fields:
            # remove fields not currently used by bfin-sim
            for fld in (
                "alignment",
                "array_elem_type_name",
                "base_data_type_name",
                "bitfld_base_type",
                "bitfld_num_bits",
                "bitfld_offset",
                "enums",
                "id",
                "num_elements",
                "type",
                "pid",
                "offset",
                "is_union",
                "is_array",
                "is_enum",
                "is_basic",
                "children",
            ):
                if fld in dtyp_dict:
                    del dtyp_dict[fld]
        return dtyp_dict

    @classmethod
    def TYPHUNIX_URL(cls) -> str:
        return getenv("TYPHUNIX_URL")

    @classmethod
    def is_running(cls) -> bool:
        return pytyphunix.is_running()

    @classmethod
    def show_module_items(cls, file=sys.stderr):
        moditems = [i for i in dir(pytyphunix) if not i.startswith("__")]
        for m in moditems:
            print(f"    - {m}", file=file)

    @classmethod
    def pids(cls) -> List[pytyphunix.ProgramIdentifier]:
        return pytyphunix.pids()


__all__ = [
    # rust structs (classes)
    "ProgramIdentifier",
    "Program",
    "DataType",
    "Symbol",
    # rust Enums
    "MetaType",
    "SymbolType",
    # rust functions
    "pids",
    "data_types",
    "symbols",
    "symbols_json",
    "data_types_json",
    "is_running",
    # python code
    "TyphunixServer",
    "TyphunixDataTypeDict",
    "TyphunixSymbolDict",
]
