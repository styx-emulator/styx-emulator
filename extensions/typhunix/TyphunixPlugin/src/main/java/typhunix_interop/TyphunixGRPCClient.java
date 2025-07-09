package typhunix_interop;

import java.net.URL;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import generic.stl.Pair;
import io.grpc.Channel;
import io.grpc.Grpc;
import io.grpc.InsecureChannelCredentials;
import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;
import typhunix_interop.GhidraState.Ack;

public class TyphunixGRPCClient {
	private static final Logger logger = Logger.getLogger(TyphunixGRPCClient.class.getName());
	private static String DEFAULT_HOST = "localhost";
	private static int DEFAULT_PORT = 50051;
	private static int Port = -1;
	private static String Host = null;

	public static Pair<String, Integer> getHostandPort() {
		if (Port == -1 || Host == null) {
			int port = -1;
			String host = null;
			String url_text = System.getenv("TYPHUNIX_URL");
			if (url_text != null) {
				try {
					URL aURL = new URL(url_text);
					host = aURL.getHost();
					port = aURL.getPort();
				} catch (Exception e) {
					host = null;
					port = -1;
					logger.warning(e.toString());
				}
			}
			if (port < 0 || host == null || host.isEmpty() || host.isBlank()) {
				host = DEFAULT_HOST;
				port = DEFAULT_PORT;
			}
			Port = port;
			Host = host;
		}

		return new Pair<String, Integer>(Host, Port);
	}

	private String host = null;
	private int port = -1;
	private TyphunixGrpc.TyphunixBlockingStub blockingStub = null;
	private Channel channel = null;
	private boolean callerOwnsChannel = false;

	public TyphunixGRPCClient(String host, int port) {
		this.host = host;
		this.port = port;
	}

	public static String targetFor(String host, int port) throws Exception {
		if (port == -1) {
			throw new Exception("no port specified");
		}
		if (host == null) {
			throw new Exception("no host specified");
		}
		return String.format("%s:%d", host, port);
	}

	public String getTarget() throws Exception {
		return TyphunixGRPCClient.targetFor(this.host, this.port);
	}

	/*
	 * Constructor that provides a channel
	 */
	public TyphunixGRPCClient(Channel channel) {
		// channel is not a ManagedChannel
		// the caller (consumer) of this class is responsible for shutting
		// it down.
		this.channel = channel;
		callerOwnsChannel = true;
		blockingStub = TyphunixGrpc.newBlockingStub(channel);
	}

	private boolean shouldShutdown() {
		boolean isManagedChannel = channel instanceof ManagedChannel;
		return !callerOwnsChannel && isManagedChannel;
	}

	public void shutdown() throws InterruptedException {
		// ManagedChannels use resources like threads and TCP connections. To prevent
		// leaking these resources the channel should be shut down when it will no
		// longer be used. If
		// it may be used again leave it running.
		if (channel != null && shouldShutdown()) {
			try {
				logger.info("SHUTDOWN channel");
				((ManagedChannel) channel).shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
			} finally {
				this.blockingStub = null;
				this.channel = null;
			}
		}
	}

	public void symbolUpdate(typhunix.symbolic.Symbolic.Symbol symbol) throws Exception {
		if (blockingStub == null) {
			channel = Grpc.newChannelBuilder(getTarget(), InsecureChannelCredentials.create()).build();
			blockingStub = TyphunixGrpc.newBlockingStub(channel);
		}

		try {
			Ack response = blockingStub.symbolUpdate(symbol);
			logger.info("Symbol updated: " + response);
		} catch (StatusRuntimeException e) {
			logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
			throw e;
		}

	}

	private void getBlockingStub() throws Exception {
		if (blockingStub == null) {
			channel = Grpc.newChannelBuilder(getTarget(), InsecureChannelCredentials.create()).build();
			blockingStub = TyphunixGrpc.newBlockingStub(channel);
		}
	}

	public void registerNew(GhidraState.ConnectMessage connectMessage) throws Exception {
		getBlockingStub();

		try {
			Ack response = blockingStub.registerNew(connectMessage);
			logger.info("registerNew " + response);
		} catch (StatusRuntimeException e) {
			logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
			throw e;
		}

	}

	public void programOpened(typhunix.symbolic.Symbolic.Program program) throws Exception {
		if (blockingStub == null) {
			channel = Grpc.newChannelBuilder(getTarget(), InsecureChannelCredentials.create()).build();
			blockingStub = TyphunixGrpc.newBlockingStub(channel);
		}

		try {
			Ack response = blockingStub.programOpened(program);
			logger.info("program opened: " + response);
		} catch (StatusRuntimeException e) {
			logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
			throw e;
		}

	}

	public void programClosed(typhunix.symbolic.Symbolic.Program program) throws Exception {
		if (blockingStub == null) {
			channel = Grpc.newChannelBuilder(getTarget(), InsecureChannelCredentials.create()).build();
			blockingStub = TyphunixGrpc.newBlockingStub(channel);
		}

		try {
			Ack response = blockingStub.programClosed(program);
			logger.info("program closed: " + response);
		} catch (StatusRuntimeException e) {
			logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
			throw e;
		}

	}

	public void dataTypeUpdate(typhunix.symbolic.Symbolic.DataType dataType) throws Exception {
		if (blockingStub == null) {
			channel = Grpc.newChannelBuilder(getTarget(), InsecureChannelCredentials.create()).build();
			blockingStub = TyphunixGrpc.newBlockingStub(channel);
		}
		try {
			Ack response = blockingStub.dataTypeUpdate(dataType);
			logger.info("DataType updated: " + response);
		} catch (StatusRuntimeException e) {
			logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
			throw e;
		}
	}

	public void symbolUpdateExample(String name) throws Exception {
		typhunix.symbolic.Symbolic.ProgramIdentifier pid = typhunix.symbolic.Symbolic.ProgramIdentifier
				.newBuilder()
				.setSourceId("example-program-id")
				.setName("example-prog-name")
				.build();

		typhunix.symbolic.Symbolic.Symbol symbolOut = typhunix.symbolic.Symbolic.Symbol.newBuilder()
				.setId(1)
				.setName(name)
				.setDatatypeName("DATATYPENAME")
				.setAddress(12345)
				.setNamespace("Global")
				.setType(typhunix.symbolic.Symbolic.Symbol.SymbolType.SYMBOL_FUNCTION)
				.setPid(pid)
				.build();
		this.symbolUpdate(symbolOut);
	}

}
