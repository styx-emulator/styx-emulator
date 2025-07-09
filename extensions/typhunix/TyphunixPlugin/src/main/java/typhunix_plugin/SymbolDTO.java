package typhunix_plugin;

import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

public class SymbolDTO {
	/*
	 * Private
	 */
	private Program program;
	private Listing listing;
	private Symbol symbol;
	private String name;
	private Address address;
	private String dataTypeName = "";

	private long size = 0;
	private Boolean isData = false;
	private Boolean isFunc = false;
	private Boolean isGlob = false;
	private Function function = null;
	private ArrayList<Parameter> functionParameters = new ArrayList<Parameter>();

	/*
	 * Public
	 */
	public long getID() {
		return symbol.getID();
	}

	/** Return the symbol type. Note: Using legacy BFINSIM logic:
	 *	  If the symbol is not data, but is a function; tag it as a "Function"
	 *	  event if Ghidra tags it as a "Label"
	 *
	 * @return
	 */
	public SymbolType getSymbolType() {
		return (!isData() && isFunc()) ? SymbolType.FUNCTION : symbol.getSymbolType();
	}

	/**
	 * @return the symbol
	 */
	public Symbol getSymbol() {
		return symbol;
	}

	/**
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * @return the address
	 */
	public Address getAddress() {
		return address;
	}

	/**
	 * @return the program name
	 */
	public String getProgramName() {
		return this.program.getName();
	}

	/**
	 * @return the program id, as a String
	 */
	public String getProgramID() {
		return String.format("%s", this.program.getUniqueProgramID());
	}

	/**
	 * @return the dataTypeName
	 */
	public String getDataTypeName() {
		return dataTypeName;
	}

	/**
	 * @return the size
	 */
	public long getSize() {
		return size;
	}

	/**
	 * @return indication that the symbol is data
	 */
	public Boolean isData() {
		return isData;
	}

	/**
	 * @return indication that the symbol is a function
	 */
	public Boolean isFunc() {
		return isFunc;
	}

	/**
	 * @return indication that the symbol is global
	 */
	public Boolean isGlob() {
		return isGlob;
	}

	/**
	 * @return get function parameters
	 */
	public ArrayList<Parameter> getFunctionParameters() {
		return functionParameters;
	}

	/**
	 * Get the address of the last instruction in a function.
	 *
	 * @return long - the address of the last instruction for the function
	 */
	public long getLastInstructionAddr() {
		long result = 0;
		Instruction insn = (Instruction) listing.getCodeUnitAt(address);
		Instruction prev = null;
		long mxAddrOffset = address.getOffset() + size;
		while (insn != null) {
			prev = insn;
			insn = insn.getNext();
			if (insn != null) {
				Address iaddr = insn.getAddress();
				if (iaddr.getOffset() >= mxAddrOffset) {
					break;
				}
			}
		}
		insn = prev;
		if (insn != null) {
			result = insn.getAddress().getOffset();
		}
		return result;
	}

	/**
	 * Constructor
	 * @param symbol - a Ghidra model Symbol
	 */
	public SymbolDTO(Symbol symbol) {
		this.symbol = symbol;
		program = symbol.getProgram();
		listing = program.getListing();
		address = symbol.getAddress();
		name = symbol.getName(true);
		isGlob = symbol.isGlobal();

		Data data = listing.getDataAt(address);
		Function func = listing.getFunctionAt(address);
		if (data != null) {
			isData = true;
			dataTypeName = data.getBaseDataType().getName();
			size = data.getBaseDataType().getLength();
		}
		else if (func != null) {
			this.function = func;
			this.isFunc = true;
			// Set size for function
			long mx = function.getBody().getMaxAddress().getUnsignedOffset();
			long mn = function.getBody().getMinAddress().getUnsignedOffset();
			size = mx - mn;
			// Save parameters
			for (int i = 0; i < function.getParameterCount(); i++) {
				functionParameters.add(function.getParameter(i));
			}
		}
	}
}
