
package typhunix_plugin;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.FileNotFoundException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import org.junit.Test;

import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.app.plugin.core.datamgr.tree.ArchiveNode;
import ghidra.app.plugin.core.datamgr.tree.ArchiveRootNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import utilities.util.FileUtilities;

public class TyphunixPluginIntegrationTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String PROGRAM_FILENAME = "sample";

	private TestEnv env;
	private PluginTool tool;
	private ProgramBuilder builder;
	private ProgramDB program;
	private DataTypeManagerPlugin plugin;
	private DataTypeArchiveGTree tree;
	private ArchiveNode programNode;
	private DataTypesProvider provider;

	public void createAndOpenProgram() throws Exception {
		try {
			removeBinTestDir();
		}
		catch (Throwable t) {
			System.out.println(t);
		}

		env = new TestEnv();
		program = buildProgram();
		tool = env.launchDefaultTool(program);
		tool.addPlugin(TyphunixPlugin.class.getName());

		plugin = env.getPlugin(DataTypeManagerPlugin.class);

		provider = plugin.getProvider();
		tree = provider.getGTree();
		ArchiveRootNode archiveRootNode = (ArchiveRootNode) tree.getModelRoot();
		programNode = (ArchiveNode) archiveRootNode.getChild(PROGRAM_FILENAME);
		assertNotNull("Did not successfully wait for the program node to load", programNode);

		tool.showComponentProvider(provider, true);
	}

	private ProgramDB buildProgram() throws Exception {
		builder = new ProgramBuilder("sample", ProgramBuilder._X64, this); // ProgramBuilder._TOY, this);
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

	private File getClassesDirectory() throws FileNotFoundException {
		File file = getTestDataTypeFile();
		if (file == null) {
			throw new FileNotFoundException("Could not find resource TestDataType.txt");
		}
		File parent = file.getParentFile();
		String parentPath = parent.getAbsolutePath();
		int pos = parentPath.lastIndexOf("TyphunixPlugin");
		String destPath = parentPath.substring(0, pos - 1);
		String newpath =
			destPath + File.separator + "plugin" + File.separator + "test";
		return new File(newpath);
	}

	private void removeBinTestDir() {

		try {
			File binDir = getClassesDirectory();
			if (binDir.isDirectory()) {
				FileUtilities.deleteDir(binDir);
			}
		}
		catch (FileNotFoundException e) {
			System.err.println("Unable to delete test dir?: " + e.getMessage());
		}
	}

	private File getTestDataTypeFile() {
		URL url = getClass().getResource("/datatypes.txt");

		try {
			URI uri = new URI(url.toExternalForm());
			return new File(uri);
		}
		catch (URISyntaxException e) {
			throw new RuntimeException("Cannot find TestDataType.txt");
		}

	}

	public void tearDown() throws Exception {
		env.dispose();
		removeBinTestDir();
	}

	/**
	 * This test generates variouse ProgramChangeRecords that are processed by
	 * The Typhunix Plugin. Currently, the test passes as long as the plugin
	 * does not throw an exception. More assertions are needed to improve coverage.
	 *
	 * @throws Exception
	 */
	@Test
	public void testIntegrationTest() throws Exception {
		TyphunixPlugin.setDEFAULT_SEND_OUTBOUND_ENABLED(true);

		this.createAndOpenProgram();

		// Add a symbol
		TestUtils.createAndAddLabel(program, "Foo@0xF", "0xF");

		/// add a struct
		int txid = program.startTransaction("Add Struct Mystruct");
		CategoryPath categPath = new CategoryPath("/testdata");
		StructureDataType myStruct = new StructureDataType("MyStruct", 0);
		myStruct.add(new ByteDataType(), "byte1", null);
		myStruct.add(new WordDataType(), "word1", null);
		myStruct.setCategoryPath(categPath);
		program.getDataTypeManager().addDataType(myStruct, null);
		program.endTransaction(txid, true);

		/// rename the struct
		boolean commit = false;
		txid = program.startTransaction("Edit Struct Mystruct");
		DataType editMyStruct = program.getDataTypeManager().getDataType(categPath, "MyStruct");
		editMyStruct.setName("NEWNAME");
		program.endTransaction(txid, commit);

		/// Change a member
		commit = false;
		txid = program.startTransaction("Edit Struct Mystruct:field1");
		Composite composite =
			(Composite) program.getDataTypeManager().getDataType(categPath, "MyStruct");
		DataTypeComponent member1 = composite.getComponent(0);
		member1.setFieldName("new_member_1_field_name");
		program.endTransaction(txid, commit);

		this.tearDown();
	}
}
