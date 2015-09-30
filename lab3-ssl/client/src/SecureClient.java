import javax.net.ssl.*;
import java.io.*;
import java.net.InetAddress;
import java.security.KeyStore;

public class SecureClient {
    final static int DEFAULT_HOST_PORT = 8189;
    final static String LABKEYSTORE = "./assets/ClientKeystore.ks";
    final static String LABTRUSTSTORE = "./assets/ClientTruststore.ks";
    final static String LABSTOREPASSWD = "somekey";
    final static String LABALIASPASSWD = "somekey";
    final static String TERMINATE_CONNECTION = "";
    final static String END_COMMAND = "cmd:end";

    private InetAddress hostAddr;
    private int hostPort;

    private PrintWriter socketOut;
    private BufferedReader socketIn;

    public SecureClient(InetAddress hostAddr) {
        this.hostAddr = hostAddr;
        this.hostPort = DEFAULT_HOST_PORT;
    }

    public SecureClient(InetAddress hostAddr, int hostPort) {
        this.hostAddr = hostAddr;
        this.hostPort = hostPort;
    }

    public void setup() {
        try {
            // load keystores
            KeyStore ks = KeyStore.getInstance("JCEKS");
            ks.load(new FileInputStream(LABKEYSTORE),
                    LABSTOREPASSWD.toCharArray());
            KeyStore ts = KeyStore.getInstance("JCEKS");
            ts.load(new FileInputStream(LABTRUSTSTORE),
                    LABSTOREPASSWD.toCharArray());

            // setup key managers
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, LABALIASPASSWD.toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ts);

            // setup ssl
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(),
                    tmf.getTrustManagers(),
                    null);
            SSLSocketFactory sslFact = sslContext.getSocketFactory();
            SSLSocket client = (SSLSocket) sslFact.createSocket(this.hostAddr, this.hostPort);
            client.setEnabledCipherSuites(client.getSupportedCipherSuites());

            // setup transmissions
            socketIn = new BufferedReader(new InputStreamReader(client.getInputStream()));
            socketOut = new PrintWriter(client.getOutputStream(), true);
        } catch (Exception e) {
            System.out.println(e);
            e.printStackTrace();
        }
    }

    public void add(String numbers) {
        try {
            System.out.println("Adding numbers " + numbers + " together");
            // connect and print result!
            socketOut.println("cmd:add");
            socketOut.println(numbers);
            socketOut.println("cmd:end");
            System.out.println(socketIn.readLine());
        } catch (Exception e) {
            System.out.println(e);
            e.printStackTrace();
        }
    }

    public void upload(String fileName) {
        try {
            socketOut.println("cmd:upload");
            socketOut.println(fileName);

            try (BufferedReader reader = new BufferedReader(
                    new FileReader("files/" + fileName))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    socketOut.println(line);
                }
            } catch (IOException ioe) {
                System.out.println(ioe);
                ioe.printStackTrace();
            }

            socketOut.println(END_COMMAND);
        } catch (Exception e) {
            System.out.println(e);
            e.printStackTrace();
        }
    }

    public void download(String fileName) {
        try {
            socketOut.println("cmd:download");
            socketOut.println(fileName);

            socketOut.println(END_COMMAND);
        } catch (Exception e) {
            System.out.println(e);
            e.printStackTrace();
        }
    }

    public void delete(String fileName) {
        try {
            socketOut.println("cmd:delete");
            socketOut.println(fileName);

            socketOut.println(END_COMMAND);
        } catch (Exception e) {
            System.out.println(e);
            e.printStackTrace();
        }
    }

    public void terminate() {
        try {
            socketOut.println(TERMINATE_CONNECTION);
        } catch (Exception e) {
            System.out.println(e);
            e.printStackTrace();
        }
    }
}
