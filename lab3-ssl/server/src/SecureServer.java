import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.util.StringTokenizer;

/**
 * Created by kalas on 15-09-25.
 */
public class SecureServer {
    private int port;

    static final int DEFAULT_PORT = 8189;
    static final String LABKEYSTORE = "./assets/LABkeystore.ks";
    static final String LABTRUSTSTORE = "./assets/LABtruststore.ks";
    static final String LABSTOREPASSWD = "somekey";
    static final String LABALIASPASSWD = "somekey";
    final static String TERMINATE_CONNECTION = "";

    /**
     * default constructor
     */
    SecureServer () {
        this.port = DEFAULT_PORT;
    }

    /**
     * constructor
     * @param port the port number
     */
    SecureServer (int port) {
        this.port = port;
    }

    public void run() {
        try {
            // load keystores
            KeyStore ks = KeyStore.getInstance("JCEKS");
            ks.load(new FileInputStream(LABKEYSTORE),
                    LABSTOREPASSWD.toCharArray());
            KeyStore ts = KeyStore.getInstance("JCEKS");
            ts.load(new FileInputStream(LABTRUSTSTORE),
                    LABSTOREPASSWD.toCharArray());

            // setup key/trust managers
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, LABALIASPASSWD.toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ts);

            // setup ssl server
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(),
                            tmf.getTrustManagers(),
                            null);
            SSLServerSocketFactory sslServer = sslContext.getServerSocketFactory();

            SSLServerSocket sss = (SSLServerSocket) sslServer.createServerSocket(this.port);
            sss.setEnabledCipherSuites(sss.getSupportedCipherSuites());

            System.out.println("SecureServer running on port " + this.port);

            // prepare incoming connections
            SSLSocket incoming = (SSLSocket) sss.accept();
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(incoming.getInputStream()));
            PrintWriter out = new PrintWriter(incoming.getOutputStream(), true);
            String str;

            // handle incoming transmissions
            while (!(str = in.readLine()).equals(TERMINATE_CONNECTION)) {
                double result = 0;
                StringTokenizer st = new StringTokenizer(str);

                try {
                    while (st.hasMoreTokens()) {
                        Double d = new Double(st.nextToken());
                        result += d.doubleValue();
                    }
                    out.println("The result is " + result);
                } catch (NumberFormatException nfe) {
                    out.println("Weird format");
                }
            }
            // close connection
            incoming.close();
        } catch (Exception e) {
            System.out.println(e);
            e.printStackTrace();
        }
    }
}
