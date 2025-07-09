// SPDX-License-Identifier: BSD-2-Clause
package typhunix_plugin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import generic.jar.ResourceFile;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.symbol.Symbol;
import ghidra.python.PythonScript;
import ghidra.python.PythonScriptProvider;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import typhunix_interop.GhidraState;

public class TyphunixPluginTest extends AbstractGhidraHeadedIntegrationTest {
	public static final Object CLS = TyphunixPluginTest.class;
	private static final String PROGRAM_NAME = "sample_program";

	private TestEnv env;
	private PluginTool codeBrowserTool;
	private ProgramBuilder programBuilder;
	private CategoryPath categoryPath = new CategoryPath("/testdata");
	private ProgramDB program;

	private int mockHitCount = 0;
	String programDir;

	@BeforeClass
	public static void beforeAllTestMethods() {
		TyphunixPlugin.setDEFAULT_SEND_OUTBOUND_ENABLED(false);
		Msg.debug(CLS, "Running Tests ...");
	}

	@AfterClass
	public static void afterAllTestMethods() {
		Msg.debug(CLS, "Finished");
	}

	@Before
	public void beforeEachTestMethod() throws Exception {
		env = new TestEnv();
		program = buildProgram(PROGRAM_NAME);
		programDir = env.getGhidraProject()
				.getProjectManager()
				.getActiveProject()
				.getProjectLocator()
				.getProjectDir()
				.getAbsolutePath();

		Msg.debug(CLS, "PROJECT LOCATION: " + programDir);
		codeBrowserTool = env.launchDefaultTool(program);
	}

	@After
	public void afterEachTestMethod() throws Exception {
		env.dispose();
	}

	private ProgramDB buildProgram(String name) throws Exception {
		programBuilder = new ProgramBuilder(name, ProgramBuilder._X64, this); // ProgramBuilder._TOY, this);

		programBuilder.createMemory(".text", "0x1001000", 0x100);
		programBuilder.addCategory(categoryPath);

		// Add struct
		StructureDataType struct = new StructureDataType("ArrayStruct", 4);

		struct.setCategoryPath(categoryPath);
		programBuilder.addDataType(struct);

		return programBuilder.getProgram();
	}

	boolean waitForMockHits(int num) {
		long cumMs = 0;
		long maxWaitMs = 2000;
		long cycleWaitMs = 100;
		program.flushEvents();
		while (mockHitCount < num) {
			program.flushEvents();
			sleep(cycleWaitMs);
			cumMs += cycleWaitMs;
			if (cumMs >= maxWaitMs) {
				Msg.warn(CLS, "timed out waiting for events");
				break;
			}
		}
		return mockHitCount >= num;
	}

	TyphunixPlugin getMockedPlugin() {
		TyphunixPlugin.setDEFAULT_SEND_OUTBOUND_ENABLED(true);
		TyphunixPlugin plugin = Mockito.spy(new TyphunixPlugin(codeBrowserTool));
		Mockito.doNothing().when(plugin).postConnectMessage((GhidraState.ConnectMessage) any());
		return plugin;
	}

	void addPluginWithOutboundEnabled(TyphunixPlugin plugin) throws PluginException {
		assertNotNull(plugin);
		plugin.setSendOutboundEnabled(true);
		codeBrowserTool.addPlugin(plugin);
		assertTrue(plugin.isSendOutboundEnabled());
		assertNotNull(env.getPlugin(plugin.getClass()));
	}

	/**
	 * Ensures that the plugin registers with the GRPC service when a Program
	 * is opened
	 *
	 * @throws CancelledException
	 * @throws Exception
	 */
	@Test
	public void testProgramOpened() throws CancelledException, Exception {
		TyphunixPlugin plugin = getMockedPlugin();
		int expEventCount = 1;
		String programID = String.format("%d", program.getUniqueProgramID());

		Mockito.doAnswer(new Answer<Object>() {
			@Override
			public Object answer(InvocationOnMock arg1) throws Throwable {
				mockHitCount += 1;
				GhidraState.ConnectMessage connMsg = arg1.getArgument(0);
				assertTrue(connMsg.hasProgram());
				assertTrue(connMsg.getProgram().hasArchitecture());
				assertTrue(connMsg.getProgram().hasMetadata());
				assertEquals(programID, connMsg.getProgram().getPid().getSourceId());
				assertEquals(PROGRAM_NAME, connMsg.getProgram().getPid().getName());
				assertEquals("Number of Symbols should match",
					program.getSymbolTable().getNumSymbols(),
					connMsg.getSymbolsCount());
				assertEquals(
					"Number of DataTypes should match",
					program.getDataTypeManager()
							.getDataTypeCount(TyphunixPlugin.DT_INCLUDE_POINTERS_AND_ARRAYS),
					connMsg.getDataTypesCount());

				assertEquals("Number of Functions should match",
					program.getFunctionManager().getFunctionCount(),
					connMsg.getProgram().getFunctionsCount());
				return connMsg;
			}
		}).when(plugin).postConnectMessage((GhidraState.ConnectMessage) any());

		// Add the plugin
		addPluginWithOutboundEnabled(plugin);

		assertTrue("Got expected events", waitForMockHits(expEventCount));
	}

	/**
	 * Ensures that a Symbol update is sent when a Label is created
	 *
	 * @throws CancelledException
	 * @throws Exception
	 */
	@Test
	public void testSymbolAdded() throws CancelledException, Exception {
		TyphunixPlugin plugin = getMockedPlugin();

		int expEventCount = 1;
		Mockito.doAnswer(new Answer<Object>() {
			@Override
			public Object answer(InvocationOnMock arg1) throws Throwable {
				mockHitCount += 1;
				typhunix.symbolic.Symbolic.Symbol symbol = arg1.getArgument(0);
				return symbol;
			}
		}).when(plugin).postSymbol((typhunix.symbolic.Symbolic.Symbol) any());
		addPluginWithOutboundEnabled(plugin);
		// Add the symbol
		TestUtils.createAndAddLabel(program, "Foo@0xF", "0xF");

		assertTrue("Got expected events", waitForMockHits(expEventCount));
	}

	/**
	 * Ensures that a symbol update is sent when a symbol is renamed
	 *
	 * @throws CancelledException
	 * @throws Exception
	 */
	@Test
	public void testSymbolRenamed() throws CancelledException, Exception {
		// Add a symbol
		String addr = "0xFF";
		String oldSymName = "AAA";
		String newSymName = "BBB";
		TestUtils.createAndAddLabel(program, oldSymName, addr);
		Symbol symRefs[] =
			program.getSymbolTable().getSymbols(program.getAddressFactory().getAddress(addr));
		assertEquals(1, symRefs.length);
		Symbol oldSymbol = symRefs[0];
		assertEquals(oldSymbol.getName(), oldSymName);

		TyphunixPlugin plugin = getMockedPlugin();
		int expEventCount = 1;
		Mockito.doAnswer(new Answer<Object>() {
			@Override
			public Object answer(InvocationOnMock arg1) throws Throwable {
				mockHitCount += 1;
				typhunix.symbolic.Symbolic.Symbol symbol = arg1.getArgument(0);
				return symbol;
			}
		}).when(plugin).postSymbol((typhunix.symbolic.Symbolic.Symbol) any());
		addPluginWithOutboundEnabled(plugin);
		// Rename symbol
		int txid = program.startTransaction("Rename Symbol");
		oldSymbol.setName(newSymName, oldSymbol.getSource());
		program.endTransaction(txid, true);

		assertTrue("Got expected events", waitForMockHits(expEventCount));
	}

	/**
	 * Ensures that datatype update is emitted when stuct is added
	 *
	 * @throws CancelledException
	 * @throws Exception
	 */
	@Test
	public void testNewStructAdded() throws CancelledException, Exception {
		TyphunixPlugin plugin = getMockedPlugin();
		int numNewCmpTypes = 2;
		int expEventCount = 1 + numNewCmpTypes;
		Mockito.doAnswer(new Answer<Object>() {
			@Override
			public Object answer(InvocationOnMock arg1) throws Throwable {
				mockHitCount += 1;
				typhunix.symbolic.Symbolic.DataType dataType = arg1.getArgument(0);
				Msg.debug(CLS, "MOCK: postDataType " + dataType.getName());
				return dataType;
			}
		}).when(plugin).postDataType((typhunix.symbolic.Symbolic.DataType) any());
		// Add the plugin
		addPluginWithOutboundEnabled(plugin);
		// Add new Struct with 2 components, each a new data type
		StructureDataType myStruct = new StructureDataType("MyStruct", 0);
		myStruct.add(new ByteDataType(), "byte1", null);
		myStruct.add(new WordDataType(), "word1", null);
		TestUtils.createAndAddDataType(program, myStruct, categoryPath);
		// Make sure we got the expected events
		assertTrue("Got expected events", waitForMockHits(expEventCount));
	}

	/**
	 * Ensures that the DumpSymbols.py works (ie - dumps json to a file with the
	 * expected format and content.
	 *
	 * @throws CancelledException
	 * @throws Exception
	 * @throws IOException
	 * @throws InvalidInputException
	 */
	@Test
	public void testDumpSymbolsPythonScript()
			throws CancelledException, Exception, IOException,
			InvalidInputException {
		int expectedSymLen = 0;
		int expectedArgsLen = 0;
		String expectedSymTypeName = "label";
		String symbolName = "ABCDE";
		String addrStr = "0x22";
		TestUtils.createAndAddLabel(program, symbolName, addrStr);
		ConsoleService console = codeBrowserTool.getService(ConsoleService.class);
		File scriptFile = new File("ghidra_scripts/DumpSymbols.py").getAbsoluteFile();
		assertTrue(scriptFile.exists());
		ghidra.app.script.GhidraState state = new ghidra.app.script.GhidraState(env.getTool(),
			env.getProject(), program, null, null, null);
		File outfile = new File("build/dumpSymbols.json").getAbsoluteFile();
		state.addEnvironmentVar("OUTFILE", outfile.getAbsolutePath());
		PythonScriptProvider psp = new PythonScriptProvider();
		PrintWriter w = new PrintWriter(new ByteArrayOutputStream());

		PythonScript pyScript = (PythonScript) psp.getScriptInstance(
			new ResourceFile(scriptFile.getAbsolutePath()), w);
		pyScript.set(state, TaskMonitor.DUMMY, w);

		pyScript.run();

		String console_text = console.getText(0, console.getTextLength());
		String expConsoleOut = String.format("writing symbols to: %s", outfile.getAbsolutePath());
		assertTrue("Not in output: " + expConsoleOut,
			console_text.contains(expConsoleOut));

		String path = outfile.getAbsolutePath();
		BufferedReader bufferedReader = new BufferedReader(new FileReader(path));

		Gson gson = new Gson();
		JsonElement o = gson.fromJson(bufferedReader, JsonElement.class);
		assertTrue(o.isJsonArray());
		JsonObject x = o.getAsJsonArray().get(0).getAsJsonObject();
		assertEquals(expectedSymTypeName, x.get("type").getAsString());
		assertEquals(expectedSymLen, x.get("len").getAsInt());
		assertEquals(symbolName, x.get("name").getAsString());
		assertEquals(expectedArgsLen, x.get("args").getAsJsonArray().size());
		Msg.debug(CLS, "=====================================");
		for (String k : x.keySet()) {
			Msg.debug(CLS, "=   " + k + ": " + x.get(k));
		}
		Msg.debug(CLS, "=====================================");
	}

}
