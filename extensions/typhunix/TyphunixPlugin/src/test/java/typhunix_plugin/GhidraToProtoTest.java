// SPDX-License-Identifier: BSD-2-Clause
/**
 *
 */
package typhunix_plugin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import compatability.ChangeManagerBridge;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.model.Project;
import ghidra.program.database.IntRangeMap;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Integer16DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import typhunix.symbolic.Symbolic.DataType.MetaType;

/**
 * Primarily tests that the marshalling from Ghidra to protobuf works as
 * expected
 * for the items defined in the protocol. Also validates assumptions about how
 * Ghidra dispatches change events.
 *
 */
public class GhidraToProtoTest extends AbstractGhidraHeadedIntegrationTest {
	private static final Logger logger = Logger.getLogger(GhidraToProtoTest.class.getName());
	private TestEnv env;
	private Program program;
	private int transactionID;
	private int eventType;
	private String mapName;
	private ProgramBuilder programBuilder;
	private CategoryPath miscPath;

	private Program buildProgram(String programName) throws Exception {
		programBuilder = new ProgramBuilder(programName, ProgramBuilder._X64);
		programBuilder.createMemory("test1", Long.toHexString(0x1001000), 0x2000);
		CategoryPath miscPath = new CategoryPath("/MISC");
		programBuilder.addCategory(miscPath);
		return programBuilder.getProgram();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		program = buildProgram("notepad");
		transactionID = program.startTransaction("test");
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	private Address getAddr(int offset) {
		return program.getMinAddress().getNewAddress(offset);
	}

	private class MyDomainObjectListener implements DomainObjectListener {
		@Override
		public void domainObjectChanged(DomainObjectChangedEvent ev) {
			for (int i = 0; i < ev.numRecords(); i++) {
				DomainObjectChangeRecord rec = ev.getChangeRecord(i);
				eventType = ChangeManagerBridge.getInstance().asId(rec.getEventType());
				mapName = (String) rec.getNewValue();
			}
		}
	}

	/**
	 * Ensure we can correctly convert a struct from ghidra to typhunix
	 *
	 * @throws IOException
	 * @throws InvalidNameException
	 * @throws DuplicateNameException
	 */
	@Test
	public void testStruct() throws IOException, InvalidNameException, DuplicateNameException {
		String structName = "test_struct";
		StructureDataType ghidraStruct = new StructureDataType(structName, 0);
		ghidraStruct.setCategoryPath(miscPath);
		programBuilder.addDataType(ghidraStruct);
		typhunix.symbolic.Symbolic.DataType gsObjDt =
			GhidraToProto.convertDataType(ghidraStruct, this.program);

		assertEquals("Struct name unchanged", gsObjDt.getName(), structName);
		assertEquals("type is TYPE_STRUCT",
			typhunix.symbolic.Symbolic.DataType.MetaType.TYPE_STRUCT,
			gsObjDt.getType());
		assertEquals("No members", gsObjDt.getChildrenCount(), 0);
		var expects = new Object[][] {
			// Basic types
			{ new IntegerDataType(), 4, "m0_int1" },
			{ new Integer16DataType(), 16, "m1_int16" },
			{ new CharDataType(), 1, "m2_char" },
		};
		// Add each basic data type as a struct member
		for (int i = 0; i < expects.length; i++) {
			assertEquals("Num components == i", i, ghidraStruct.getNumComponents());
			gsObjDt = GhidraToProto.convertDataType(ghidraStruct, program);
			DataType field = (DataType) expects[i][0];
			String fieldName = (String) expects[i][2];
			// add the field, set its name
			ghidraStruct.add(field);
			ghidraStruct.getComponent(i).setFieldName(fieldName);
		}
		gsObjDt = GhidraToProto.convertDataType(ghidraStruct, this.program);
		assertEquals("Same member count", ghidraStruct.getNumComponents(),
			gsObjDt.getChildrenCount());
		for (int i = 0; i < expects.length; i++) {
			DataType field = (DataType) expects[i][0];
			int szBytes = (int) expects[i][1];
			String fieldName = (String) expects[i][2];
			logger.log(Level.FINE, field.toString());
			typhunix.symbolic.Symbolic.DataType gsobj = gsObjDt.getChildren(i);
			assertEquals("Same size (bytes)", szBytes, gsobj.getSize());
			assertEquals("Same field name", fieldName, gsobj.getName());
			assertEquals("Correct TYPE (basic)", MetaType.TYPE_BASIC, gsobj.getType());
		}
	}

	/**
	 * Test that updates are properly emitted when AddressSets change. This
	 * test needs assertions meaningful to proving that the plugin works.
	 *
	 * @throws Exception
	 */
	@Test
	public void testRemoveRange() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(getAddr(0x100), getAddr(0x200));
		set.addRange(getAddr(0x400), getAddr(0x500));
		set.addRange(getAddr(0x1000), getAddr(0x1001));

		IntRangeMap map = program.createIntRangeMap("MyMap");
		int value = 0x11223344;
		map.setValue(set, value);

		map.clearValue(getAddr(0x101), getAddr(0x105));
		AddressSet resultSet = map.getAddressSet();
		assertTrue(!resultSet.contains(getAddr(0x101), getAddr(0x105)));

		AddressSet s = set.subtract(new AddressSet(getAddr(0x101), getAddr(0x105)));
		assertEquals(s, resultSet);
	}

	/**
	 * Test that updates are properly emitted when a program is saved. This
	 * test needs assertions meaningful to proving that the plugin works.
	 *
	 * @throws Exception
	 */
	@Test
	public void testSaveProgram() throws Exception {
		Project project = env.getProject();
		DomainFolder rootFolder = project.getProjectData().getRootFolder();
		program.endTransaction(transactionID, true);
		transactionID = -1;

		DomainFile df = rootFolder.createFile("mynotepad", program, TaskMonitor.DUMMY);
		env.release(program);

		AddressSet set = new AddressSet();
		set.addRange(getAddr(0), getAddr(0x40));

		Program p = (Program) df.getDomainObject(this, true, false, TaskMonitor.DUMMY);
		int txID = p.startTransaction("test");
		int value = 0x11223344;
		int otherValue = 0x44332211;
		try {
			IntRangeMap map = p.createIntRangeMap("MyMap");
			map.setValue(set, value);
			map.setValue(getAddr(0x30), getAddr(0x40), otherValue);
		}
		finally {
			p.endTransaction(txID, true);
		}

		df.save(TaskMonitor.DUMMY);
		p.release(this);

		df = rootFolder.getFile("mynotepad");
		assertNotNull(df);

		p = (Program) df.getDomainObject(this, true, false, TaskMonitor.DUMMY);
		IntRangeMap map = p.getIntRangeMap("MyMap");
		assertNotNull(map);
		assertEquals(set, map.getAddressSet());

		assertEquals(new AddressSet(getAddr(0x0), getAddr(0x2f)), map.getAddressSet(value));
		assertEquals(new AddressSet(getAddr(0x30), getAddr(0x40)), map.getAddressSet(otherValue));

		p.release(this);
	}

	/**
	 * The TyphunixPlugin implmenents a DomainObjectListener interface. This
	 * test validates assumptions made about how Ghidra dispatches events, although
	 * we are not testing Typhunix directly, should any of these assertions
	 * change in future versions og Ghidra, this is a mechanism for early detection.
	 *
	 * @throws Exception
	 */
	@Test
	public void testEvents() throws Exception {
		MyDomainObjectListener dol = new MyDomainObjectListener();
		program.addListener(dol);
		IntRangeMap map = program.createIntRangeMap("MyMap");
		program.flushEvents();
		waitForPostedSwingRunnables();

		assertEquals(ChangeManagerBridge.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_ADDED_ID, eventType);
		assertEquals("MyMap", mapName);
		int value = 0x11223344;

		// map changed
		AddressSet set = new AddressSet();
		set.addRange(getAddr(0), getAddr(0x10));
		set.addRange(getAddr(0x20), getAddr(0x25));
		set.addRange(getAddr(0x26), getAddr(0x30));
		map.setValue(set, value);
		program.flushEvents();
		waitForPostedSwingRunnables();
		assertEquals(ChangeManagerBridge.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED_ID, eventType);
		assertEquals("MyMap", mapName);

		map.clearValue(getAddr(0), getAddr(0x15));
		program.flushEvents();
		waitForPostedSwingRunnables();
		assertEquals(ChangeManagerBridge.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED_ID, eventType);
		assertEquals("MyMap", mapName);

		set = new AddressSet();
		set.addRange(getAddr(20), getAddr(0x23));
		map.clearValue(set);
		program.flushEvents();
		waitForPostedSwingRunnables();
		assertEquals(ChangeManagerBridge.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED_ID, eventType);
		assertEquals("MyMap", mapName);

		map.clearAll();
		program.flushEvents();
		waitForPostedSwingRunnables();
		assertEquals(ChangeManagerBridge.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED_ID, eventType);
		assertEquals("MyMap", mapName);

		// map removed
		program.deleteIntRangeMap("MyMap");
		program.flushEvents();
		waitForPostedSwingRunnables();
		assertEquals(ChangeManagerBridge.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_REMOVED_ID, eventType);
		assertEquals("MyMap", mapName);
	}

}
