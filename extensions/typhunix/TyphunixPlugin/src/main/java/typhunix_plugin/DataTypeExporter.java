// SPDX-License-Identifier: BSD-2-Clause
package typhunix_plugin;

import java.io.IOException;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Iterator;

import com.google.gson.stream.JsonWriter;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
* Dumps all custom DataTypes to a json file. The json schema is:
* <pre>
* [
*     {
*         "name": "data type 1",
*         "size": 4,
*         "is_struct": 0,
*         "attributes":
*         [
*             {
*                 "offset": 0,
*                 "name": "field_3",
*                 "data_type": "int",
*                 "size": 4
*             }
*         ]
*     }
* ]
* </pre>
*
*/
public class DataTypeExporter {
	// BITFIELDS
	private static final String BITFIELD_BIT_OFFSET = "bitfield_bit_offset";
	private static final String BITFIELD_NUM_BITS = "bitfield_num_bits";

	// ARRAYS
	private static final String NUM_ELEMS = "num_elems";
	private static final String ELEM_TYPE = "elem_type";

	// DataTypes
	private static final String UNIVERSAL_ID = "universal_id";
	private static final String BASE_DATA_TYPE = "base_data_type";
	private static final String ALIGNMENT = "alignment";
	private static final String NAME = "name";
	private static final String VALUE = "value";
	private static final String SIZE = "size";
	private static final String OFFSET = "offset";
	private static final String DATA_TYPE = "data_type";
	private static final String ATTRIBUTES = "attributes";

	// FLAGS
	private static final String IS_BITFIELD = "is_bitfield";
	private static final String IS_STRUCT = "is_struct";
	private static final String IS_UNION = "is_union";
	private static final String IS_ENUM = "is_enum";
	private static final String IS_ARRAY = "is_array";

	/**
	 * jsonwriter handle to use to serialize json chain
	 */
	private JsonWriter jsonWriter;

	/**
	 * list of data type managers to query
	 */
	private ArrayList<DataTypeManager> managers = new ArrayList<DataTypeManager>();

	private DataTypeDTO currentDTO;

	// Current program
	Program program;

	public DataTypeExporter(JsonWriter writer, ArrayList<DataTypeManager> dataTypeManagers,
			Program program) {
		this.jsonWriter = writer;
		this.managers = dataTypeManagers;
		this.program = program;
	}

	/**
	 * writes the json map data to the selected file
	 */
	public void dataTypesToFile() throws IOException {
		this.jsonWriter.beginArray();
		for (DataTypeManager mgr : this.managers) {
			Iterator<DataType> dataTypes = mgr.getAllDataTypes();
			while (dataTypes.hasNext()) {
				DataType dt = dataTypes.next();
				writeDataType(this.jsonWriter, dt);
			}
		}
		this.jsonWriter.endArray();
	}

	/**
	 * converts the individual data type to json, will traverse structs
	 * @param writer
	 * @param dt
	 * @throws IOException
	 */
	private void writeDataType(JsonWriter writer, DataType dt) throws IOException {
		// make sure this is a valid object
		if (dt.getLength() < 0) {
			Msg.error(this, "Invalid datatype: " + dt.getClass().getName() + " " + dt.toString());
			return;
		}
		currentDTO = new DataTypeDTO(dt, this.program);

		writer.beginObject();

		writer.name(NAME).value(currentDTO.getName());
		writer.name(UNIVERSAL_ID).value(currentDTO.getID());
		writer.name(SIZE).value(currentDTO.getSize());
		writer.name(ALIGNMENT).value(currentDTO.getAlignment());
		writer.name(BASE_DATA_TYPE).value(currentDTO.getBaseDataTypeName());
		writer.name(IS_STRUCT).value(currentDTO.isStruct() ? 1 : 0);
		writer.name(IS_UNION).value(currentDTO.isUnion() ? 1 : 0);
		writer.name(IS_ENUM).value(currentDTO.isEnum() ? 1 : 0);
		writer.name(IS_ARRAY).value(currentDTO.isArray() ? 1 : 0);

		if (currentDTO.isArray()) {
			writer.name(ELEM_TYPE).value(currentDTO.getArrayElementTypeName());
			writer.name(NUM_ELEMS).value(currentDTO.getArrayNumElements());
		}

		// called regardless if struct or not
		writeChildArray(writer);

		// done, close object
		writer.endObject();
	}

	/**
	 * Writes the child attributes if the DataType is `Structure` or `Union`
	 * Writes enumeration name/values if DataType is Ghidra `Enum`
	 * @param writer
	 * @throws IOException
	 */
	private void writeChildArray(JsonWriter writer) throws IOException {
		writer.name(ATTRIBUTES);
		writer.beginArray();

		if (currentDTO.isComposite()) {
			// for Ghidra Structure and Ghidra Union, write details of the
			// DataType components (ie the fields of the struct or union
			for (DataTypeComponentDTO cmpDTO : currentDTO.getDataTypeComponents()) {
				writer.beginObject();
				writer.name(NAME).value(cmpDTO.getName());
				writer.name(UNIVERSAL_ID).value(cmpDTO.getID());
				writer.name(OFFSET).value(cmpDTO.getOffset());
				writer.name(DATA_TYPE).value(cmpDTO.getDataTypeName());
				writer.name(SIZE).value(cmpDTO.getSize());
				if (!cmpDTO.isBitField()) {
					writer.name(BASE_DATA_TYPE).value(cmpDTO.getBaseDataTypeName());
					writer.name(IS_BITFIELD).value(cmpDTO.isBitField());
				}
				else {
					writer.name(BASE_DATA_TYPE).value(cmpDTO.getBaseDataTypeName());
					writer.name(IS_BITFIELD).value(cmpDTO.isBitField());
					writer.name(BITFIELD_NUM_BITS).value(cmpDTO.getNumBits());
					writer.name(BITFIELD_BIT_OFFSET).value(cmpDTO.getBitOffset());
				}

				writer.endObject();
			}
		}

		else if (currentDTO.isEnum()) {
			// put the mappings of value to name
			ArrayList<SimpleEntry<String, Long>> enums = currentDTO.getEnumValues();
			for (SimpleEntry<String, Long> item : enums) {
				writer.beginObject();
				writer.name(NAME).value(item.getKey());
				writer.name(VALUE).value(item.getValue());
				writer.endObject();
			}

		}

		writer.endArray();
	}

}
