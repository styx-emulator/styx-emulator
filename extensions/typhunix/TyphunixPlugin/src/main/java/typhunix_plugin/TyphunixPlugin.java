/* ###
 Dragon State Plugin

 - Register/receive change notices for Ghidra Domain Objects
 - Filter for the changes we want
 - Send symbols, data types, and program/project information to consumers
 */
package typhunix_plugin;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import com.google.protobuf.ByteString;

import compatability.ChangeManagerBridge;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramOpenedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTableListener;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.util.Msg;
import typhunix_interop.GhidraState;
import typhunix_interop.TyphunixGRPCClient;

//@formatter:off
@PluginInfo(
	status           = PluginStatus.UNSTABLE,
	packageName      = "TyphunixPlugin",
	category         = PluginCategoryNames.ANALYSIS,
	shortDescription = "Ghidra / emulator interop",
	description      = "Interact with Ghidra and an emulator",
	eventsConsumed = {
			ProgramOpenedPluginEvent.class,
		    ProgramClosedPluginEvent.class,
	}
)
//@formatter:on
public class TyphunixPlugin extends ProgramPlugin
		implements DomainObjectListener, SymbolTableListener {

	/**
	 * static flag to control default behavior for whether or not to send events
	 * to the typhunix broker/grpc server.
	 */
	public static boolean DEFAULT_SEND_OUTBOUND_ENABLED = true;

	/**
	 * Getter method for {@TyphunixPlugin.DEFAULT_SEND_OUTBOUND_ENABLED}
	 *
	 * @return the current static value
	 */
	public static boolean isDEFAULT_SEND_OUTBOUND_ENABLED() {
		return DEFAULT_SEND_OUTBOUND_ENABLED;
	}

	/**
	 * Setter method for {@TyphunixPlugin.DEFAULT_SEND_OUTBOUND_ENABLED}
	 *
	 * @return the current static value
	 */
	public static void setDEFAULT_SEND_OUTBOUND_ENABLED(boolean dEFAULT_SEND_OUTBOUND_ENABLED) {
		DEFAULT_SEND_OUTBOUND_ENABLED = dEFAULT_SEND_OUTBOUND_ENABLED;
	}

	/**
	 * flag used when calling getAllDataTypes(flag) and getDataTypesCount(flag)
	 */
	public static final boolean DT_INCLUDE_POINTERS_AND_ARRAYS = true;

	/**
	 * static class variable that holds a map of all opened Programs
	 */
	private HashMap<Long, ArrayList<Program>> openedPrograms =
		new HashMap<Long, ArrayList<Program>>();

	private boolean sendOutboundEnabled = isDEFAULT_SEND_OUTBOUND_ENABLED();

	public boolean isSendOutboundEnabled() {
		return sendOutboundEnabled;
	}

	/**
	 * A mechanism for enabling/disabling sending of data to the typhunix
	 * broker/grpc server
	 *
	 * @param sendOutboundEnabled
	 */
	public void setSendOutboundEnabled(boolean sendOutboundEnabled) {
		this.sendOutboundEnabled = sendOutboundEnabled;
	}

	/**
	 * Constructor for TyphunixPlugin. Generally, its called from Ghidra
	 * if the plugin (aka Extension) is installed and enabled.
	 *
	 * @param tool
	 */
	@java.lang.SuppressWarnings("removal")
	public TyphunixPlugin(PluginTool tool) {

		super(tool, false, false);
		Msg.debug(this,
			String.format("Constructing %s with tool %s, outbound enabled=%s",
				this.getClass().getName(),
				tool.getName(), isSendOutboundEnabled()));
	}

	@Override
	protected void programOpened(Program program) {
		GhidraState.ConnectMessage connectMessage = getConnectMessage(program);

		if (!openedPrograms.containsKey(program.getUniqueProgramID())) {
			openedPrograms.put(program.getUniqueProgramID(), new ArrayList<Program>());
		}
		ArrayList<Program> plist = openedPrograms.get(program.getUniqueProgramID());
		plist.add(program);
		program.addListener(this);
		if (sendOutboundEnabled) {
			postConnectMessage(connectMessage);
		}
	}

	void postConnectMessage(GhidraState.ConnectMessage connectMessage) {
		try {
			var hostPort = TyphunixGRPCClient.getHostandPort();
			TyphunixGRPCClient cli = new TyphunixGRPCClient(hostPort.first, hostPort.second);
			cli.registerNew(connectMessage);
			cli.shutdown();
		}
		catch (Exception e) {
			Msg.error(this, e);
		}
	}

	@Override
	protected void programClosed(Program program) {
		if (openedPrograms.containsKey(program.getUniqueProgramID())) {
			ArrayList<Program> plist = openedPrograms.get(program.getUniqueProgramID());
			plist.remove(plist.size() - 1);
			if (plist.size() == 0) {
				program.removeListener(this);
			}
		}
	}

	void postSymbol(typhunix.symbolic.Symbolic.Symbol symbol) throws Exception {
		if (sendOutboundEnabled) {
			Msg.info(this, String.format("Send update [%s] %s/%s: %s",
				symbol.getClass().getName(),
				symbol.getPid().getSourceId(),
				symbol.getPid().getName(),
				symbol.getName()));
			var hostPort = TyphunixGRPCClient.getHostandPort();
			TyphunixGRPCClient cli = new TyphunixGRPCClient(hostPort.first, hostPort.second);
			cli.symbolUpdate(symbol);
			cli.shutdown();
		}
	}

	void postDataType(typhunix.symbolic.Symbolic.DataType dataType) throws Exception {
		if (sendOutboundEnabled) {
			var hostPort = TyphunixGRPCClient.getHostandPort();
			TyphunixGRPCClient cli = new TyphunixGRPCClient(hostPort.first, hostPort.second);
			Msg.info(this, String.format("Send update [%s] %s/%s: %s",
				dataType.getClass().getName(),
				dataType.getPid().getSourceId(),
				dataType.getPid().getName(),
				dataType.getName()));
			cli.dataTypeUpdate(dataType);
			cli.shutdown();
		}
	}

	private void emitChangeRecord(DomainObjectChangeRecord cr) throws Exception {
		Msg.info(this, String.format("DomainObjectChangeRecord: %s: %s[%d]",
			cr.getClass().getName(),
			ChangeManagerBridge.getInstance().codeToString(cr.getEventType()),
			ChangeManagerBridge.getInstance().asId(cr.getEventType())));

		if (cr instanceof ProgramChangeRecord) {
			ProgramChangeRecord pcr = (ProgramChangeRecord) cr;
			Object affectedObject = pcr.getObject();
			Object newValue = pcr.getNewValue();
			// Object oldValue = pcr.getOldValue();
			if (affectedObject == null) {
				affectedObject = newValue;
			}
			// Symbol
			if (affectedObject instanceof Symbol) {
				typhunix.symbolic.Symbolic.Symbol symbolOut = GhidraToProto
						.convertSymbol(new SymbolDTO((Symbol) affectedObject));
				postSymbol(symbolOut);
				Msg.info(this, "SYMBOL> \n" + symbolOut + "\n");
			}
			// DataType
			else if (affectedObject instanceof DataType) {
				typhunix.symbolic.Symbolic.DataType dataTypeOut = GhidraToProto.convertDataType(
					(DataType) cr.getNewValue(),
					this.getCurrentProgram());
				if (dataTypeOut != null) {
					postDataType(dataTypeOut);
				}
			}
			else {
				throw new Exception("Unhandled change record");
			}
		}
		else {
			String crCls = cr.getClass().getName();
			String msg = String.format("Encountered unknown change record: %s: %s",
				crCls, cr.toString());
			Msg.warn(this, msg);
		}

	}

	/**
	 * Get a summary string of the event contents, for debug messages
	 *
	 * @param event
	 * @return
	 */
	private String getDomObjChgEvtDebugSummary(DomainObjectChangedEvent event) {
		StringBuffer sb = new StringBuffer(
			String.format("EVENT[num_recs: %d]: ", event.numRecords()));
		boolean first = true;
		for (int i = 0; i < event.numRecords(); i++) {
			DomainObjectChangeRecord cr = event.getChangeRecord(i);
			if (!first) {
				sb.append(", ");
			}
			else {
				first = false;
			}

			String eventName = ChangeManagerBridge.getInstance().codeToString(cr.getEventType());
			int eventId = ChangeManagerBridge.getInstance().asId(cr.getEventType());
			sb.append(String.format("%s: %s[%d]",
				cr.getClass().getName(),
				eventName,
				eventId));
		}
		return sb.toString();
	}

	/*
	 * domainObjectChanged - process event from Ghidra
	 * the DomainObjectChangedEvent coontains 1..N DomainObjectChangeRecords
	 * For each ChangeRecord we care about (using filterChangeRecords), call
	 * emitChangeRecord.
	 */
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent event) {
		Msg.debug(this, getDomObjChgEvtDebugSummary(event));
		if (event.getSource() instanceof Program) {
			Program program = (Program) event.getSource();
			Msg.debug(this, String.format("DomainObjectEvent received for program %s %s",
				program.getUniqueProgramID(), program.getName()));
			// Get a list of change records we care about. For each record,
			// call emitChangeRecord...
			ArrayList<DomainObjectChangeRecord> recs =
				ChangeManagerBridge.getInstance().filterChangeRecords(event);
			for (DomainObjectChangeRecord cr : recs) {
				// Filtered list
				try {
					emitChangeRecord(cr);
				}
				catch (Exception e) {
					Msg.error(this, "Failed to emit event", e);
				}
			}
		}
	}

	private GhidraState.ConnectMessage getConnectMessage(Program p) {

		// Program/project metadata
		Map<String, String> md = p.getMetadata();
		for (String ky : md.keySet()) {
			Msg.info(this, String.format("%-30s: %s", ky, md.get(ky)));
		}

		// FUNCTIONS
		ArrayList<typhunix.symbolic.Symbolic.Function> functions =
			new ArrayList<typhunix.symbolic.Symbolic.Function>();
		FunctionIterator iter = p.getFunctionManager().getFunctions(true);
		while (iter.hasNext()) {
			Function f = iter.next();
			ArrayList<typhunix.symbolic.Symbolic.CrossReference> callers =
				new ArrayList<typhunix.symbolic.Symbolic.CrossReference>();
			ArrayList<typhunix.symbolic.Symbolic.BasicBlock> basicBlocks =
				new ArrayList<typhunix.symbolic.Symbolic.BasicBlock>();

			functions.add(typhunix.symbolic.Symbolic.Function.newBuilder()
					.setId(-1)
					.setSymbol(GhidraToProto.convertSymbol(new SymbolDTO(f.getSymbol())))
					.addAllCallers(callers)
					.addAllBlocks(basicBlocks)
					.build());
		}

		// Language
		Language lang = p.getLanguage();
		CompilerSpec cSpec = lang.getDefaultCompilerSpec();
		LanguageDescription langDesc = lang.getLanguageDescription();

		for (String ky : cSpec.getPropertyKeys()) {
			Msg.info(this, "compiler spec key: " + ky);
		}

		// todo: get segments
		ArrayList<typhunix.symbolic.Symbolic.Segment> segments =
			new ArrayList<typhunix.symbolic.Symbolic.Segment>();

		typhunix.symbolic.Symbolic.FileMetadata fileMetaData =
			typhunix.symbolic.Symbolic.FileMetadata.newBuilder()
					.setFileSize(0) // todo: ?
					.setLoader(p.getExecutableFormat()) // todo: Loader?
					.setName(p.getName())
					.setPath(p.getExecutablePath())
					.setSha256(ByteString.copyFromUtf8(p.getExecutableSHA256()))
					.build();

		typhunix.symbolic.Symbolic.Architecture arch =
			typhunix.symbolic.Symbolic.Architecture.newBuilder()
					.setProcessor(langDesc.getProcessor().toString())
					.setEndian(GhidraToProto
							.convertEndian(p.getLanguage().getLanguageDescription().getEndian()))
					.setBits(langDesc.getSize())
					.build();
		typhunix.symbolic.Symbolic.ProgramIdentifier pid =
			typhunix.symbolic.Symbolic.ProgramIdentifier.newBuilder()
					.setSourceId(String.format("%d", p.getUniqueProgramID()))
					.setName(p.getName())
					.build();
		typhunix.symbolic.Symbolic.Program proj = typhunix.symbolic.Symbolic.Program.newBuilder()
				.setPid(pid)
				.setArchitecture(arch)
				.setMetadata(fileMetaData)
				.addAllFunctions(functions)
				.addAllSegments(segments)
				.build();

		// Note, we are including Arrays and Pointers.
		// See DT_INCLUDE_POINTERS_AND_ARRAYS if this changes
		ArrayList<typhunix.symbolic.Symbolic.DataType> dataTypes =
			new ArrayList<typhunix.symbolic.Symbolic.DataType>();
		p.getDataTypeManager()
				.getAllDataTypes()
				.forEachRemaining(
					(dt) -> dataTypes.add(
						GhidraToProto.convertDTO(new DataTypeDTO(dt, p))));

		ArrayList<typhunix.symbolic.Symbolic.Symbol> symbols =
			new ArrayList<typhunix.symbolic.Symbolic.Symbol>();

		p.getSymbolTable()
				.getAllSymbols(true)
				.forEachRemaining(
					(sym) -> symbols.add(GhidraToProto.convertSymbol(new SymbolDTO(sym))));

		GhidraState.ConnectMessage connectMsg = GhidraState.ConnectMessage.newBuilder()
				.addAllDataTypes(dataTypes)
				.addAllSymbols(symbols)
				.setProgram(proj)
				.build();

		return connectMsg;
	}

	@Override
	protected void dispose() {
		Msg.info(this, "dispose():");
	}

	//////////////////////////////////////////////////////////////////////////
	//
	// SYMBOL TABLE CHANGES
	//
	//////////////////////////////////////////////////////////////////////////
	@Override
	public void symbolAdded(SourceType symbol) {
		StringBuilder s = new StringBuilder();
		s.append("Symbol Added: " + symbol);
		Msg.info(this, s.toString());
	}

	@Override
	public void symbolRemoved(Address addr, String name, boolean isLocal) {
		StringBuilder s = new StringBuilder();
		s.append("Symbol Removed: name: " + name);
		s.append(", addr: " + addr);
		s.append(", isLocal: " + isLocal);
		Msg.info(this, s.toString());

	}

	@Override
	public void symbolRenamed(SourceType symbol, String oldName) {
		StringBuilder s = new StringBuilder();
		s.append("Symbol Renamed: " + symbol);
		s.append(", FROM: [" + oldName + "]");
		Msg.info(this, s.toString());

	}

	@Override
	public void primarySymbolSet(SourceType symbol) {
		// noop
	}

	@Override
	public void symbolScopeChanged(SourceType symbol) {
		// noop
	}

	@Override
	public void externalEntryPointAdded(Address addr) {
		// noop
	}

	@Override
	public void externalEntryPointRemoved(Address addr) {
		// noop
	}

	@Override
	public void associationAdded(SourceType symbol, Reference ref) {
		// noop
	}

	@Override
	public void associationRemoved(Reference ref) {
		// noop
	}

}
