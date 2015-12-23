package SecureElection;

import SecureElection.Common.Settings;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.KeyStore;
import java.util.Set;
import java.util.Vector;

/**
 * Created by Klas Eskilson on 15-11-16.
 */

public class CentralTabulatingFacility {
    // constants
    private static final String CTFTRUSTSTORE = Settings.KEYLOCATION + "CTFTruststore.ks";
    private static final String CTFKEYSTORE   = Settings.KEYLOCATION + "CTFKeystore.ks";
    private static final String CTFPASSWORD   = "somephrase";

    // string versions of CLA's validation numbers
    Vector<String> authorizedVoters = new Vector<>();

    // server/client socket and IO vars
    BufferedReader serverInput, clientInput;
    PrintWriter serverOutput, clientOutput;
    SSLSocketFactory sslClientFact;
    SSLServerSocket sss;

    private void setup() throws Exception {
        // load keystores
        System.out.print("loading keystores... ");
        KeyStore ks = KeyStore.getInstance("JCEKS");
        ks.load(new FileInputStream(CTFKEYSTORE),
                CTFPASSWORD.toCharArray());
        KeyStore ts = KeyStore.getInstance("JCEKS");
        ts.load(new FileInputStream(CTFTRUSTSTORE),
                CTFPASSWORD.toCharArray());
        System.out.print("done.\n");

        // setup key/trust managers
        System.out.print("Preparing trust managers... ");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, CTFPASSWORD.toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ts);
        System.out.print("done.\n");

        // setup ssl server
        System.out.print("Starting server... ");
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        SSLServerSocketFactory sslServer = serverContext.getServerSocketFactory();
        System.out.print("done.\n");

        sss = (SSLServerSocket) sslServer.createServerSocket(Settings.CTF_PORT);
        sss.setEnabledCipherSuites(sss.getSupportedCipherSuites());

        // setup ssl client
        System.out.print("Setting up SSL Client... ");
        SSLContext clientContext = SSLContext.getInstance("TLS");
        clientContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        sslClientFact = clientContext.getSocketFactory();
        System.out.print("done.\n");

        // require client auth
//        sss.setNeedClientAuth(true);
        System.out.println("CTF server running on port " + Settings.CTF_PORT);
    }

    private void receiveConnections() throws Exception {
        System.out.println("Starting server socket IO, accepting connections.");
        SSLSocket incoming = (SSLSocket) sss.accept();
        // prepare incoming connections
        serverInput = new BufferedReader(
                new InputStreamReader(incoming.getInputStream()));
        serverOutput = new PrintWriter(incoming.getOutputStream(), true);
        String str = serverInput.readLine();
        while (!str.equals(Settings.Commands.TERMINATE)) {
            switch (str) {
                default:
                    System.out.println("Unknown command: " + str);
                    break;
            }

            if ((str = serverInput.readLine()) == null) {
                str = "";
                Thread.sleep(1000);
            }
        }
        incoming.close();
    }

    private void startClient(InetAddress hostAddr, int port) throws Exception {
        System.out.println("Connecting client to " + hostAddr.toString() + ":" + port);
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
        startClient(InetAddress.getLocalHost(), Settings.CLA_PORT);
//        clientOutput.println(Settings.Commands.TERMINATE);
        receiveConnections();
    }
}
