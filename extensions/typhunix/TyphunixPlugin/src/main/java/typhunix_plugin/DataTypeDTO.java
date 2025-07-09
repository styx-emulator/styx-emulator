// SPDX-License-Identifier: BSD-2-Clause
/**
 *
 */
package typhunix_plugin;

import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Program;

/**
 * Class to hold the relevant information from a Ghidra data type,
 * down-selected to just the data needed to convert to a typhunix
 * domain object
 *
 */
public class DataTypeDTO {
	public static final long NO_UNIVERSAL_ID = 0;
	public static final int NO_OFFSET = -1;

	// Underlying Ghidra DataType
	private DataType dtObj = null;

	private Program program;

	private ArrayList<DataTypeComponentDTO> dtComponents = new ArrayList<DataTypeComponentDTO>();

	// For Enum types
	private ArrayList<SimpleEntry<String, Long>> enums = new ArrayList<SimpleEntry<String, Long>>();
	// For Array types public String arrayElementTypeName = null;

	/**
	 * Constructor
	 * @param obj
	 */
	public DataTypeDTO(DataType obj, Program program) {
		this.program = program;
		dtObj = obj;
		if (dtObj instanceof Composite) {
			transformComponents();
		}

		else if (isEnum()) {
			Enum e = (Enum) dtObj;
			for (long value : e.getValues()) {
				enums.add(new SimpleEntry<String, Long>(e.getName(value), value));
			}
		}
	}

	/**
	 * @return the program name
	 */
	public String getProgramName() {
		return this.program != null ? this.program.getName() : "";
	}

	/**
	 * @return the program id, as a String
	 */
	public String getProgramID() {
		return this.program != null ? String.format("%s", this.program.getUniqueProgramID()) : "";
	}

	/**
	 * Return the underlying DataType or DataTypeComponent object
	 * @return the dtObj
	 */
	public DataType getDataTypeObject() {
		return dtObj;
	}

	public long getID() {
		long id = NO_UNIVERSAL_ID;
		if (dtObj.getUniversalID() != null) {
			id = dtObj.getUniversalID().getValue();
		}
		return id;
	}

	public ArrayList<DataTypeComponentDTO> getDataTypeComponents() {
		return dtComponents;
	}

	public int getOffset() {
		int offset = NO_OFFSET;
		if (dtObj instanceof DataTypeComponent)
			offset = ((DataTypeComponent) dtObj).getOffset();
		return offset;
	}

	public String getName() {
		return dtObj.getName();
	}

	public int getSize() {
		return dtObj.getLength();
	}

	public int getAlignment() {
		return dtObj.getAlignment();
	}

	public boolean isComposite() {
		return dtObj instanceof Composite;
	}

	public boolean isStruct() {
		return dtObj instanceof Structure;
	}

	public boolean isUnion() {
		return dtObj instanceof Union;
	}

	public boolean isArray() {
		return dtObj instanceof Array;
	}

	public boolean isEnum() {
		return dtObj instanceof Enum;
	}

	public boolean isTypeDef() {
		return dtObj instanceof TypeDef;
	}

	/**
	 * Transform the datatype's components to DataTypeComponentDTOs
	 */
	public void transformComponents() {
		if (dtObj instanceof Composite) {
			for (DataTypeComponent c : ((Composite) dtObj).getComponents()) {
				dtComponents.add(new DataTypeComponentDTO(c));
			}
		}

	}

	public String getBaseDataTypeName() {
		return this.getBaseDataTypeName(dtObj);
	}

	private String getBaseDataTypeName(DataType dt) {
		if (dt instanceof Array) {
			if (((Array) dt).getDataType() != null)
				return ((Array) dt).getDataType().getName();
		}
		else if (dt instanceof Pointer) {
			if (((Pointer) dt).getDataType() != null)
				return ((Pointer) dt).getDataType().getName();
		}
		else if (dt instanceof BitFieldDataType) {
			if (((BitFieldDataType) dt).getBaseDataType() != null)
				return ((BitFieldDataType) dt).getBaseDataType().getName();
		}
		else if (dt instanceof TypeDef) {
			if (((TypeDef) dt).getBaseDataType() != null)
				return ((TypeDef) dt).getBaseDataType().getName();
		}
		return dt.getName();
	}

	public String getArrayElementTypeName() {
		// Protobuf does not like null?
		return isArray() ? ((Array) dtObj).getDataType().getName() : "";
	}

	@Override
	public String toString() {
		StringBuffer buf = new StringBuffer();
		buf.append(String.format("%d, %s, ", getID(), getName()));
		buf.append(String.format("%d", getSize()));
		if (isEnum()) {
			buf.append("\n");
			for (SimpleEntry<String, Long> e : enums) {
				buf.append(String.format("    %s %d\n", e.getKey(), e.getValue()));
			}

		}
		if (isArray()) {
			buf.append("\n");
			buf.append(String.format("    Array<%s>[%d]\n", this.getArrayElementTypeName(),
				getArrayNumElements()));

		}
		else if (this.dtComponents != null) {
			buf.append("\n");
			for (DataTypeComponentDTO c : this.dtComponents) {
				buf.append(String.format("    > %s\n", c));
			}
		}
		return buf.toString();
	}

	public ArrayList<SimpleEntry<String, Long>> getEnumValues() {
		return enums;
	}

	public int getArrayNumElements() {
		return isArray() ? ((Array) dtObj).getNumElements() : 0;
	}

	public boolean containsBitFields(DataType dt) {
		boolean hasBitFields = false;
		if (dt instanceof Composite) {
			for (DataTypeComponent c : ((Composite) dt).getComponents()) {
				if (c.isBitFieldComponent()) {
					hasBitFields = true;
				}
			}
		}
		return hasBitFields;
	}

}
