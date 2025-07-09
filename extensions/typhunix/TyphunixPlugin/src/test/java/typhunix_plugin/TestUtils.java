// SPDX-License-Identifier: BSD-2-Clause
package typhunix_plugin;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.UniversalID;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class TestUtils {

	public static final Set<String> DEFAULT_DATAMGRS =
		new HashSet<String>(Arrays.asList("BuiltInTypes", "generic_clib"));

	public static ProgramDB buildProgram(String name, Object consumer) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(name, ProgramBuilder._TOY, consumer);

		builder.createMemory(".text", "0x1001000", 0x100);
		CategoryPath miscPath = new CategoryPath("/MISC");
		builder.addCategory(miscPath);
		StructureDataType struct = new StructureDataType("ArrayStruct", 4);
		struct.setCategoryPath(miscPath);
		builder.addDataType(struct);
		UnionDataType union = new UnionDataType("ArrayUnion");
		union.setCategoryPath(miscPath);
		union.add(new ByteDataType());
		builder.addDataType(union);

		CategoryPath cat1Path = new CategoryPath("/Category1");
		builder.addCategory(cat1Path);
		CategoryPath cat2Path = new CategoryPath(cat1Path, "Category2");
		builder.addCategory(cat2Path);
		CategoryPath cat4Path = new CategoryPath(cat2Path, "Category4");
		builder.addCategory(cat4Path);
		builder.addCategory(new CategoryPath(cat2Path, "Category5"));

		CategoryPath cat3Path = new CategoryPath(cat2Path, "Category3");
		builder.addCategory(cat3Path);
		StructureDataType dt = new StructureDataType("IntStruct", 0);
		dt.add(new WordDataType());
		dt.setCategoryPath(cat3Path);
		builder.addDataType(dt);

		dt = new StructureDataType("CharStruct", 0);
		dt.add(new CharDataType());
		dt.setCategoryPath(cat4Path);
		builder.addDataType(dt);

		StructureDataType dllTable = new StructureDataType("DLL_Table", 0);
		dllTable.add(new WordDataType());
		builder.addDataType(dllTable);

		StructureDataType myStruct = new StructureDataType("MyStruct", 0);
		myStruct.add(new ByteDataType(), "struct_field_names", null);
		myStruct.setCategoryPath(cat2Path);
		builder.addDataType(myStruct);

		return builder.getProgram();
	}

	public static boolean isBuiltDefaultDataMgr(String name) {
		return !DEFAULT_DATAMGRS.contains(name);
	}

	public static void createFunctionDefinition(ProgramDB program, String functionName,
			String... paramNames) {
		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		int id = dataTypeManager.startTransaction("test");
		FunctionDefinitionDataType dt = new FunctionDefinitionDataType(functionName);
		ParameterDefinition[] args = new ParameterDefinition[paramNames.length];
		for (int i = 0; i < paramNames.length; i++) {
			args[i] = new ParameterDefinitionImpl(paramNames[i], new ByteDataType(), null);
		}
		dt.setArguments(args);
		dataTypeManager.addDataType(dt, null);
		dataTypeManager.endTransaction(id, true);
	}

	public static void createAndAddDataTypes(Program program, CategoryPath path) {
		int txid = program.startTransaction("createAndAddDataTypes");
		UnionDataType union = new UnionDataType("ArrayUnion");
		union.setCategoryPath(path);
		union.add(new ByteDataType());
		program.endTransaction(txid, true);
	}

	public static void createAndAddDataType(Program program, DataType dt, CategoryPath path)
			throws DuplicateNameException {
		int txid = program.startTransaction("createAndAddDataTypes");
		dt.setCategoryPath(path);
		program.getDataTypeManager().addDataType(dt, null);
		program.endTransaction(txid, true);
	}

	public static void createAndAddLabel(Program program, String name, String address)
			throws InvalidInputException {
		Address addr = program.getAddressFactory().getAddress(address);
		String symbolName = name;
		int txid = program.startTransaction("Add symbol " + name);
		program.getSymbolTable()
				.createLabel(addr, symbolName, null, SourceType.USER_DEFINED);
		program.endTransaction(txid, true);
	}

	public static Iterator<DataType> getAllDataTypes(Program program) {
		return program.getDataTypeManager().getAllDataTypes();
	}

	public static ArrayList<String> getAllDataTypesToStrings(Program program) {
		ArrayList<String> results = new ArrayList<String>();
		program.getDataTypeManager()
				.getAllDataTypes()
				.forEachRemaining((dt) -> results.add(dataTypeKeyStr(dt)));
		return results;
	}

	public static String dataTypeKeyStr(DataType dataType) {
		UniversalID uid = dataType.getUniversalID();
		String univID = "NONE";

		if (uid != null) {
			univID = String.valueOf(uid.getValue());
		}

		String result = String.format("%20s: ", univID);
		result += dataType.getPathName() + " ";
		result += String.valueOf(dataType.getLength());
		return result;
	}

	public static void debugPrintDataTypeKeys(Program program, String prefix) {
		for (String dts : getAllDataTypesToStrings(program)) {
			Msg.debug(TestUtils.class, String.format("%s%s", prefix, dts));
		}
	}
}
