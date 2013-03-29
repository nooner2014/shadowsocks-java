import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.Thread;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

public class Shadowsocks {
	private SocketAddress serverAddr;
	private Secret secret;
	private Thread serverThread;
	private ServerSocket localSock;
	private boolean running = false;
	
	
	public static void main(String[] args){
		if (args.length != 4) {
			System.out.println("java Shadowsocks <localPort> <serverAddr> <serverPort> <key>");
			return;
		}
		int bind = Integer.parseInt(args[0]);
		String addr = args[1];
		int port = Integer.parseInt(args[2]);
		String key = args[3];
		
		Shadowsocks s = new Shadowsocks(addr, port, key);
        System.out.println("Listening " + bind + " ...");
		s.start(bind);
		s.join();
        System.out.println("Stopped.");
	}
	
	
	public boolean start(int port) {
		return start("127.0.0.1", port);
	}
	

	public boolean start(String address, int port) {
		if (running) return true;
		ServerSocketChannel channel;
		ListenSocket server;
		try {
			channel = ServerSocketChannel.open();
			localSock = channel.socket();
			localSock.bind(new InetSocketAddress(address, port));
			server = new ListenSocket();
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		serverThread = new Thread(server);
		running = true;
		serverThread.start();
		return true;
	}
    
    public void join() {
        try {
            serverThread.join();
        } catch (InterruptedException e) { }
    }
	
	public void stop() {
		if (running) return;
		running = false;
		try {
			localSock.close();
		} catch (IOException  e) {
			e.printStackTrace();
		}
	}
	
	public boolean isRunning() {
		return running;
	}
	
	class ListenSocket implements Runnable {
		
		public void run() {
			try {
				ServerSocketChannel serverChannel = localSock.getChannel();
				while (running) {
					SocketChannel localChannel = serverChannel.accept();
					Socket sock = localChannel.socket();
					InputStream localIn = sock.getInputStream();
					OutputStream localOut = sock.getOutputStream();
					
//					Version identifier/method selection message:
//	                   +----+----------+----------+
//	                   |VER | NMETHODS | METHODS  |
//	                   +----+----------+----------+
//	                   | 1  |    1     | 1 to 255 |
//	                   +----+----------+----------+
//					Will be ignored directly.
					
					if (localIn.read() != 5) {
						System.out.println("Unknow protocol version.");
						sock.close();
						continue;
					}
					localIn.read(new byte[localIn.read() | 0]); // ignore methods
					byte[] ver = {5, 0};
					localOut.write(ver); // send version(5)/method(0)
					
//					Request:
//				        +----+-----+-------+------+----------+----------+
//				        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//				        +----+-----+-------+------+----------+----------+
//				        | 1  |  1  | X'00' |  1   | Variable |    2     |
//				        +----+-----+-------+------+----------+----------+
//			          o  CMD
//			             o  CONNECT X'01'
//			          o  ATYP   address type of following address
//			             o  IP V4 address: X'01'
//			             o  DOMAINNAME: X'03'
//								The first octet of the address field contains 
//								the number of octets of name that follow,
//						   		there is no terminating NUL octet.
					
					byte[] req = new byte[4];
					localIn.read(req); // load VER, CMD, RSV
					if (req[1] != 1) { 
						byte[] reply = {5, 7, 0, 1 ,0, 0, 0, 0, 1, 1};
						localOut.write(reply); // Command not supported
						continue;
					}
					byte addrType = req[3];
					byte[] addrToSend;
					if (addrType == 1) { // IP address
						addrToSend = new byte[5];
					} else if(addrType == 3) { // Domain name
						int addrLen = localIn.read();
						addrToSend = new byte[addrLen + 2];
						addrToSend[1] = (byte) addrLen;
						localIn.read(addrToSend, 2, addrLen);
					} else {
						byte[] reply = {5, 8, 0, 1 ,0, 0, 0, 0, 1, 1};
						localOut.write(reply); // Address type not supported
						continue;
					}
					addrToSend[0] = addrType;
					byte[] port = new byte[2];
					localIn.read(port);
					
//					Replies:
//			        +----+-----+-------+------+----------+----------+
//			        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//			        +----+-----+-------+------+----------+----------+
//			        | 1  |  1  | X'00' |  1   | Variable |    2     |
//			        +----+-----+-------+------+----------+----------+
//		          o  REP    Reply field:
//		              o  X'00' succeeded
//		              o  X'01' general SOCKS server failure
//		              o  X'02' connection not allowed by ruleset
//		              o  X'03' Network unreachable
//		              o  X'04' Host unreachable
//		              o  X'05' Connection refused
//		              o  X'06' TTL expired
//		              o  X'07' Command not supported
//		              o  X'08' Address type not supported
//		              o  X'09' to X'FF' unassigned
					
					SocketChannel remoteChannel;
					try {
						remoteChannel = SocketChannel.open(serverAddr);
						Socket rSock = remoteChannel.socket();
						OutputStream remoteOut = rSock.getOutputStream();
						secret.encrypt(addrToSend);
						secret.encrypt(port);
						remoteOut.write(addrToSend);
						remoteOut.write(port);
					} catch (Exception e) {
						byte[] reply = {5, 1, 0, 1 ,0, 0, 0, 0, 1, 1};
						localOut.write(reply); // general SOCKS server failure
						continue;
					}
					
					byte[] reply = {5, 0, 0, 1 ,0, 0, 0, 0, 1, 1};
					localOut.write(reply);
					Router router = new Router(localChannel, remoteChannel);
					Thread routerThread = new Thread(router);
					routerThread.start();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
			running = false;
		}
	}
	
	
	class Router implements Runnable {
		public Selector selector;		
		SocketChannel localCh;
		SocketChannel remoteCh;
		
		public void run() {	
			ByteBuffer buffer = ByteBuffer.allocate(1024);
				try {
					while (running) {
						int nKey = selector.select(12000);
						if (nKey <= 0) return;
						for(SelectionKey key : selector.keys()) {
							SocketChannel recvCh = (SocketChannel) key.channel();
							buffer.clear();
							int read = recvCh.read(buffer);
							if (read == 0) continue;
							else if (read == -1) {
								recvCh.close();
								if (recvCh == localCh) remoteCh.close();
								else localCh.close();
								selector.close();
								return;
							}
							buffer.position(0);
							byte[] data = new byte[read];
							buffer.get(data);
							if (recvCh == localCh) {
								secret.encrypt(data);
								buffer.position(0);
								buffer.put(data);
								buffer.flip();
								remoteCh.write(buffer);
							} else {
								secret.decrypt(data);
								buffer.position(0);
								buffer.put(data);
								buffer.flip();
								localCh.write(buffer);
							}
						}
						selector.selectedKeys().clear();
					}
				} catch (IOException e) {
						try {
							selector.close();
							if (localCh.isConnected()) localCh.close();
							if (remoteCh.isConnected()) remoteCh.close();
						} catch (IOException e1) {
							e1.printStackTrace();
						}
				}
		}
		
		Router(SocketChannel local, SocketChannel remote) throws IOException {
			selector = Selector.open();
			localCh = local;
			remoteCh = remote;
			localCh.configureBlocking(false);
			remoteCh.configureBlocking(false);
			localCh.register(selector, SelectionKey.OP_READ);
			remoteCh.register(selector, SelectionKey.OP_READ);
		}
	}
	

	Shadowsocks(String host, int port, String key) {
		serverAddr = new InetSocketAddress(host, port);
		secret = new Secret(key);
	}
}