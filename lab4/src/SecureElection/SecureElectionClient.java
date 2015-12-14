package SecureElection;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.security.KeyStore;
import javax.net.ssl.*;
import SecureElection.Common.Settings;

/**
 * Created by Klas Eskilson on 15-11-16.
 */

public class SecureElectionClient {
    // constants
    private static final String CLIENTTRUSTSTORE = Settings.KEYLOCATION + "ClientTruststore.ks";
    private static final String CLIENTKEYSTORE   = Settings.KEYLOCATION + "ClientKeystore.ks";
    private static final String CLIENTPASSWORD   = "somephrase";

    // class variables
    BufferedReader socketIn;
    PrintWriter socketOut;

    SSLSocketFactory sslFact;

    private void setup() throws Exception {
        // load keystores
        KeyStore ks = KeyStore.getInstance("JCEKS");
        ks.load(new FileInputStream(CLIENTKEYSTORE),
                CLIENTPASSWORD.toCharArray());
        KeyStore ts = KeyStore.getInstance("JCEKS");
        ts.load(new FileInputStream(CLIENTTRUSTSTORE),
                CLIENTPASSWORD.toCharArray());

        // setup key managers
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, CLIENTPASSWORD.toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ts);

        // setup ssl
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        sslFact = sslContext.getSocketFactory();
    }

    public void startClient(InetAddress hostAddr, int port) throws Exception{
        SSLSocket client = (SSLSocket) sslFact.createSocket(hostAddr, port);
        client.setEnabledCipherSuites(client.getSupportedCipherSuites());

        // setup transmissions
        socketIn = new BufferedReader(new InputStreamReader(client.getInputStream()));
        socketOut = new PrintWriter(client.getOutputStream(), true);
    }

    public static void main(String[] args) {
        try {
            SecureElectionClient c = new SecureElectionClient();
            c.run();
        } catch (Exception e) {
            System.out.println(e);
            e.printStackTrace();
        }
    }

    public void run() throws Exception {
        // setup connection
        InetAddress localhost = InetAddress.getLocalHost();
        setup();
        // connect to cla
        startClient(localhost, Settings.CLA_PORT);

        // connect to ctf
    }
}
