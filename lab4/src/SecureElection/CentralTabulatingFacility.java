package SecureElection;

import SecureElection.Common.Settings;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.security.KeyStore;

/**
 * Created by Klas Eskilson on 15-11-16.
 */

public class CentralTabulatingFacility {
    // constants
    private static final String CTFTRUSTSTORE = Settings.KEYLOCATION + "CTFTruststore.ks";
    private static final String CTFKEYSTORE   = Settings.KEYLOCATION + "CTFKeystore.ks";
    private static final String CTFPASSWORD   = "somephrase";

    BufferedReader serverInput, clientInput;
    PrintWriter serverOutput, clientOutput;

    SSLSocketFactory sslClientFact;

    private void setup() throws Exception {
        // load keystores
        KeyStore ks = KeyStore.getInstance("JCEKS");
        ks.load(new FileInputStream(CTFKEYSTORE),
                CTFPASSWORD.toCharArray());
        KeyStore ts = KeyStore.getInstance("JCEKS");
        ts.load(new FileInputStream(CTFTRUSTSTORE),
                CTFPASSWORD.toCharArray());

        // setup key/trust managers
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, CTFPASSWORD.toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ts);

        // setup ssl server
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        SSLServerSocketFactory sslServer = serverContext.getServerSocketFactory();

        SSLServerSocket sss = (SSLServerSocket) sslServer.createServerSocket(Settings.CTF_PORT);
        sss.setEnabledCipherSuites(sss.getSupportedCipherSuites());

        // require client auth
        sss.setNeedClientAuth(true);

        // prepare incoming connections
        SSLSocket incoming = (SSLSocket) sss.accept();
        serverInput = new BufferedReader(
                new InputStreamReader(incoming.getInputStream()));
        serverOutput = new PrintWriter(incoming.getOutputStream(), true);

        System.out.println("CTF server running on port " + Settings.CTF_PORT);

        // setup ssl client
        SSLContext clientContext = SSLContext.getInstance("TLS");
        clientContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        sslClientFact = clientContext.getSocketFactory();

        System.out.println("CTF client setup.");
    }

    private void startClient(InetAddress hostAddr, int port) throws Exception {
        SSLSocket client = (SSLSocket) sslClientFact.createSocket(hostAddr, port);
        client.setEnabledCipherSuites(client.getSupportedCipherSuites());

        clientInput = new BufferedReader(new InputStreamReader(client.getInputStream()));
        clientOutput = new PrintWriter(client.getOutputStream(), true);
    }

    public static void main(String[] args) {
        try {
            CentralTabulatingFacility ctf = new CentralTabulatingFacility();
            ctf.run();
        } catch (Exception e) {
            System.out.println(e);
            e.printStackTrace();
        }
    }

    public void run() throws Exception {
        setup();
    }
}
