// SPDX-License-Identifier: BSD-2-Clause
// This script dumps all user defined data types to a json file.
// To dump all data types defined in ghidra, all you need to do
// is change the blacklist to an empty array
//@category Typhunix
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;

import com.google.gson.stream.JsonWriter;

import typhunix_plugin.DataTypeExporter;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;

/**
 * Dumps all custom DataTypes to a json file.
 *
 * Basic DataType
*        <pre>
*        [
*        {
*        	"name": "ADI_DCB_HANDLE",
*        	"universal_id": 3496630938141394400,
*        	"size": 4,
*        	"alignment": 4,
*        	"base_data_type": "void *",
*        	"is_struct": 0,
*        	"is_union": 0,
*        	"is_enum": 0,
*        	"is_array": 0,
*        	"attributes": []
*        },
*        ]
*        </pre>
*
* Array DataType adds
*        <pre>
*        	"is_array": 1,
*        	"elem_type": "CCCFG_param_struct",
*        	"num_elems": 333,
*        </pre>
*
* Enum DataDtype adds enum definitions
*        <pre>
*        	"is_enum": 1,
*        	"attributes": [
*        		{
*        			"name": "ADI_DEV_MODE_UNDEFINED",
*        			"value": 0
*        		},
*        		{
*        			"name": "ADI_DEV_MODE_CIRCULAR",
*        			"value": 1
*        		}]
*        </pre>
*
* Struct / Union adds fields as a list of attribs:
*
*        <pre>
*        	"is_struct": 1,
*        	"is_union": 1,
*        	</pre>
*        	"attributes": [
*        		{
*        		"name": "next_dma",
*        		"universal_id": -1,
*        		"offset": 0,
*        		"data_type": "ADI_DMA_CHANNEL *",
*        		"size": 4,
*        		"base_data_type": "ADI_DMA_CHANNEL",
*        		"is_bitfield": false
*        		},
*        		{
*        		"name": "field_0x4",
*        		"universal_id": 3516228337967082154,
*        		"offset": 4,
*        		"data_type": "undefined",
*        		"size": 1,
*        		"base_data_type": "undefined",
*        		"is_bitfield": false
*        	]
*        </pre>
*
* If struct / union member is a bit field, Adds to each member:
*        <pre>
*        	"is_bitfield": true,
*        	"bitfield_num_bits": 1,
*        	"bitfield_bit_offset": 0
*        </pre>
*/

public class DumpDataTypes extends GhidraScript {
	static final String OUTFILE_VAR_NAME = "DATATYPES_OUTFILE";

	/**
	 * Data type managers to omit from the survey of data types.
	 * These Managers are the ghidra defaults.
	 */
	private String[] dataTypeManagerBlacklist = { "BuiltInTypes", "generic_clib" };

	/**
	 * jsonwriter handle to use to serialize json chain
	 */
	private JsonWriter jsonWriter;

	/**
	 * looks through all the DataTypeManager's in the current tool and
	 * adds them to our list if not in the blacklist
	 */
	private void getDataTypeManagers() {
		PluginTool tool = state.getTool();
		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		DataTypeManager[] dataTypeManagers = service.getDataTypeManagers();

		for (DataTypeManager mgr : dataTypeManagers) {
			boolean found = false;

			// make sure this manager is not in our blacklist
			for (String name : this.dataTypeManagerBlacklist) {
				if (name.equals(mgr.getName())) {
					found = true;
				}
			}

			// is this manager not in our blacklist, if not then add to this.managers
			if (!found) {
				this.managers.add(mgr);
			}
		}
	}

	/**
	 * list of data type managers to query
	 */
	private ArrayList<DataTypeManager> managers = new ArrayList<DataTypeManager>();

	/**
	 * Check the Ghidra State environment and the process environment for the
	 * variable @varname.
	 *
	 * @param varName - the name of the variable
	 * @return the value, or null if not present. Give priority to Ghidra state.
	 */
	private String getPathFromEnv(String varName) {
		String val = (String) getState().getEnvironmentVar(varName);
		if (val != null && !val.isEmpty() && !val.isBlank()) {
			return val;
		}
		val = (String) System.getenv(varName);
		if (val != null && !val.isEmpty() && !val.isBlank()) {
			return val;
		}
		return null;
	}

	/**
	 * surveys all the active DataTypeManagers in the current tool session
	 * and dumps all of the user-defined DataType's. To dump all available
	 * DataType's change this.DataTypeManagerBlacklist to `[]`
	 *
	 * @throws Exception
	 */
	@Override
	public void run() throws Exception {
		// If DATATYPES_OUTFILE is set in script environment or process environment,
		// use it as the path,otherwise prompt for an output file.
		File outFile;
		String path = getPathFromEnv(OUTFILE_VAR_NAME);
		if (path != null) {
			outFile = new File(path).getAbsoluteFile();
		}
		else {
			// prompt for outfile
			outFile = askFile("Please Select Output File", "Choose");
			this.jsonWriter = new JsonWriter(new FileWriter(outFile));
		}

		// get all DataTypeManager's not in blacklist, add them to this.managers
		getDataTypeManagers();

		// get a json schema'd map of all the datatypes in all the managers
		// and write the map to file
		Program p = this.getCurrentProgram();
		DataTypeExporter exporter = new DataTypeExporter(this.jsonWriter, this.managers, p);
		exporter.dataTypesToFile();
		println("Dumped datatypes to " + outFile.toString());
		this.jsonWriter.close();
	}

}
