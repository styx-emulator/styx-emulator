// SPDX-License-Identifier: BSD-2-Clause
/**
 *
 */
package typhunix_plugin;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;

/**
 * Class to hold the relevant information from a Ghidra `DataTypeComponent`
 * down-selected to just the data needed to convert to a typhunix
 * domain object
 *
 */
public class DataTypeComponentDTO {

	private DataTypeComponent dataTypeComponent;

	public DataTypeComponentDTO(DataTypeComponent component) {
		this.dataTypeComponent = component;
	}

	public DataType getDataTypeObject() {
		return dataTypeComponent.getDataType();
	}

	public String getDataTypeName() {
		return dataTypeComponent.getDataType().getName();
	}

	public int getNumBits() {
		return isBitField() ? ((BitFieldDataType) dataTypeComponent.getDataType()).getBitSize()
				: -1;
	}

	public long getID() {
		long id = DataTypeDTO.NO_UNIVERSAL_ID;

		if (dataTypeComponent.getDataType().getUniversalID() != null) {
			id = dataTypeComponent.getDataType().getUniversalID().getValue();
		}
		return id;
	}

	public int getBitOffset() {
		return isBitField() ? ((BitFieldDataType) dataTypeComponent.getDataType()).getBitOffset()
				: -1;
	}

	public String getBaseDataTypeName() {
		return isBitField()
				? ((BitFieldDataType) dataTypeComponent.getDataType()).getBaseDataType().getName()
				: getBaseDataTypeName(dataTypeComponent.getDataType());

	}

	public boolean isBitField() {
		return dataTypeComponent.isBitFieldComponent();
	}

	public int getOffset() {
		return dataTypeComponent.getOffset();
	}

	public int getSize() {
		return dataTypeComponent.getLength();
	}

	public String getName() {
		String fieldName = dataTypeComponent.getFieldName();

		if (fieldName == null || fieldName.equals("")) {
			fieldName = String.format("field_0x%X", dataTypeComponent.getOffset());
		}
		return fieldName;
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

	@Override
	public String toString() {
		StringBuffer buf = new StringBuffer();
		buf.append(String.format("%s, ", getName()));
		buf.append(String.format("%d, %d, ", getSize(), getOffset()));
		buf.append(String.format("%s", getDataTypeName()));
		if (isBitField()) {
			buf.append(String.format(" ==> BITFIELD: %d bits @ %d", getNumBits(), getBitOffset()));
		}
		return buf.toString();
	}
}
