/**
 *
 */
package typhunix_plugin;

import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;

/**
 * Class to convert Ghidra model items to Typhunix proto items
 *
 */

public class GhidraToProto {
	public static final Object CLS = GhidraToProto.class;

	public static typhunix.symbolic.Symbolic.Architecture.EndianType convertEndian(Endian e) {
		return e.isBigEndian() ? typhunix.symbolic.Symbolic.Architecture.EndianType.ENDIAN_BIG
				: typhunix.symbolic.Symbolic.Architecture.EndianType.ENDIAN_LITTLE;
	}

	public static typhunix.symbolic.Symbolic.Symbol.SymbolType convertSymbolType(
			SymbolType symType) {
		// Note: SymbolType.CODE is not missing in the code below - it has
		// been deprecated since ghidra v9.1, a ghidra version that predates
		// the supported version range.

		if (symType == SymbolType.LABEL) {
			return typhunix.symbolic.Symbolic.Symbol.SymbolType.SYMBOL_LABEL;
		}

		else if (symType == SymbolType.LIBRARY) {
			return typhunix.symbolic.Symbolic.Symbol.SymbolType.SYMBOL_LIBRARY;
		}

		else if (symType == SymbolType.NAMESPACE) {
			return typhunix.symbolic.Symbolic.Symbol.SymbolType.SYMBOL_NAMESPACE;
		}
		else if (symType == SymbolType.CLASS) {
			return typhunix.symbolic.Symbolic.Symbol.SymbolType.SYMBOL_CLASS;
		}
		else if (symType == SymbolType.FUNCTION) {
			return typhunix.symbolic.Symbolic.Symbol.SymbolType.SYMBOL_FUNCTION;
		}
		else if (symType == SymbolType.PARAMETER) {
			return typhunix.symbolic.Symbolic.Symbol.SymbolType.SYMBOL_PARAMETER;
		}
		else if (symType == SymbolType.LOCAL_VAR) {
			return typhunix.symbolic.Symbolic.Symbol.SymbolType.SYMBOL_LOCAL_VAR;
		}
		else if (symType == SymbolType.GLOBAL_VAR) {
			return typhunix.symbolic.Symbolic.Symbol.SymbolType.SYMBOL_GLOBAL_VAR;
		}
		else if (symType == SymbolType.GLOBAL) {
			return typhunix.symbolic.Symbolic.Symbol.SymbolType.SYMBOL_GLOBAL;
		}
		return null;
	}

	/**
	 * Converts / transformas a SymbolDTO to a GhidraState symbol
	 *
	 * @param symbolDTO
	 * @return a GhidraState Symbol
	 */
	public static typhunix.symbolic.Symbolic.Symbol convertSymbol(SymbolDTO symbolDTO) {
		typhunix.symbolic.Symbolic.ProgramIdentifier pid =
			typhunix.symbolic.Symbolic.ProgramIdentifier.newBuilder()
					.setSourceId(symbolDTO.getProgramID())
					.setName(symbolDTO.getProgramName())
					.build();
		var builder = typhunix.symbolic.Symbolic.Symbol.newBuilder()
				.setId(symbolDTO.getID())
				.setName(symbolDTO.getName())
				.setAddress(symbolDTO.getAddress().getOffset())
				.setNamespace(symbolDTO.getSymbol().getParentNamespace().getName(true))
				.setType(GhidraToProto.convertSymbolType(symbolDTO.getSymbolType()))
				.setPid(pid)
				.setDataSize(symbolDTO.getSize());

		if (!symbolDTO.isData() && symbolDTO.isFunc()) {
			// Add a fleshed out function symbol
			ArrayList<typhunix.symbolic.Symbolic.FunctionParameter> params =
				new ArrayList<typhunix.symbolic.Symbolic.FunctionParameter>();

			long func_last_insn = symbolDTO.getLastInstructionAddr();
			symbolDTO.getFunctionParameters()
					.forEach(
						(fp) -> params.add(typhunix.symbolic.Symbolic.FunctionParameter.newBuilder()
								.setName(fp.getName())
								.setDataTypeName(fp.getDataType().getName())
								.setRegSource(
									fp.isRegisterVariable() ? fp.getRegister().getName() : "")
								.setStackSource(fp.isStackVariable() ? fp.getStackOffset() : -1)

								.build()));

			builder = builder.setFunctionSymbol(
				typhunix.symbolic.Symbolic.FunctionSymbol.newBuilder()
						.addAllParameters(params)
						.setLastInsn(func_last_insn)
						.build());
		}

		if (symbolDTO.isData()) {
			String dtn = symbolDTO.getDataTypeName();
			if (dtn != null && !dtn.isEmpty()) {
				builder = builder.setDatatypeName(symbolDTO.getDataTypeName());
			}
		}

		typhunix.symbolic.Symbolic.Symbol symbolOut = builder.build();

		return symbolOut;
	}

	public static typhunix.symbolic.Symbolic.DataType.MetaType getMetaType(DataType dt) {

		if (dt instanceof Union)
			return typhunix.symbolic.Symbolic.DataType.MetaType.TYPE_UNION;
		if (dt instanceof Structure)
			return typhunix.symbolic.Symbolic.DataType.MetaType.TYPE_STRUCT;
		if (dt instanceof Array)
			return typhunix.symbolic.Symbolic.DataType.MetaType.TYPE_ARRAY;
		if (dt instanceof Enum)
			return typhunix.symbolic.Symbolic.DataType.MetaType.TYPE_ENUM;
		if (dt instanceof BitFieldDataType)
			return typhunix.symbolic.Symbolic.DataType.MetaType.TYPE_ENUM;

		// Default to BASIC
		return typhunix.symbolic.Symbolic.DataType.MetaType.TYPE_BASIC;
	}

	public static typhunix.symbolic.Symbolic.DataType convertDTO(DataTypeDTO dto) {
		typhunix.symbolic.Symbolic.ProgramIdentifier pid =
			typhunix.symbolic.Symbolic.ProgramIdentifier.newBuilder()
					.setSourceId(dto.getProgramID())
					.setName(dto.getProgramName())
					.build();

		ArrayList<typhunix.symbolic.Symbolic.DataType> fields =
			new ArrayList<typhunix.symbolic.Symbolic.DataType>();
		ArrayList<typhunix.symbolic.Symbolic.EnumNameValue> enums =
			new ArrayList<typhunix.symbolic.Symbolic.EnumNameValue>();
		typhunix.symbolic.Symbolic.DataType.MetaType metaType =
			getMetaType(dto.getDataTypeObject());

		for (SimpleEntry<String, Long> item : dto.getEnumValues()) {
			typhunix.symbolic.Symbolic.EnumNameValue e =
				typhunix.symbolic.Symbolic.EnumNameValue.newBuilder()
						.setName(item.getKey())
						.setValue(item.getValue())
						.build();
			enums.add(e);

		}
		for (DataTypeComponentDTO childDTO : dto.getDataTypeComponents()) {
			typhunix.symbolic.Symbolic.DataType.MetaType componentMetaType =
				getMetaType(childDTO.getDataTypeObject());
			typhunix.symbolic.Symbolic.DataType child =
				typhunix.symbolic.Symbolic.DataType.newBuilder()
						.setId(childDTO.getID())
						.setName(childDTO.getName())
						.setSize(childDTO.getSize())
						.setType(componentMetaType)
						.setAlignment(dto.getAlignment()) // Same as parent
						.setBaseDataTypeName(childDTO.getDataTypeName())
						.setOffset(childDTO.getOffset())

						// Bit Fields
						.setBitfldNumBits(childDTO.getNumBits())
						.setBitfldOffset(childDTO.getBitOffset())
						.setBitfldBaseType(childDTO.getDataTypeName())

						.build();
			fields.add(child);
		}

		return typhunix.symbolic.Symbolic.DataType.newBuilder()
				// All DataType's
				.setId(dto.getID())
				.setName(dto.getName())
				.setSize(dto.getSize())
				.setType(metaType)
				.setAlignment(dto.getAlignment())
				.setBaseDataTypeName(dto.getBaseDataTypeName())

				// DataTypeComponents on Stucture / Union
				.setOffset(dto.getOffset())

				// Arrays
				.setNumElements(dto.getArrayNumElements())
				.setArrayElemTypeName(dto.getArrayElementTypeName())

				// Stucture/Union
				.addAllChildren(fields)

				// Enumerations
				.addAllEnums(enums)

				// Program IDentifier
				.setPid(pid)
				.build();
	}

	public static typhunix.symbolic.Symbolic.DataType convertDataType(DataType obj, Program p) {
		typhunix.symbolic.Symbolic.DataType outDataType = null;
		// make sure this is a valid object
		if (obj.getLength() < 0) {
			Msg.warn(CLS, "Invalid datatype: " + obj.getClass().getName() + " " + obj.toString());
			return outDataType;
		}
		DataTypeDTO dto = null;

		try {
			dto = new DataTypeDTO(obj, p);
		}
		catch (Throwable t) {
			t.printStackTrace();
		}
		if (dto != null) {
			outDataType = GhidraToProto.convertDTO(dto);
			System.out.println(dto.toString());
			return outDataType;
		}
		return null;
	}
}
