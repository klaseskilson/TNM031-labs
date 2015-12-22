package SecureElection;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Vector;
import javax.net.ssl.*;
import SecureElection.Common.Settings;
import SecureElection.Common.Voter;

/**
 * Created by Klas Eskilson on 15-11-16.
 */

public class CentralLegitimizationAgency {
    // constants
    private static final String CLATRUSTSTORE = Settings.KEYLOCATION + "CLATruststore.ks";
    private static final String CLAKEYSTORE   = Settings.KEYLOCATION + "CLAKeystore.ks";
    private static final String CLAPASSWORD   = "somephrase";

    private Vector<Voter> authorizedVoters = new Vector<>();

    BufferedReader serverInput, clientInput;
    PrintWriter serverOutput, clientOutput;
    SSLSocketFactory sslClientFact;
    SSLSocket incoming;

    private void setup() throws Exception {
        System.out.print("loading keystores... ");
        // load keystores
        KeyStore ks = KeyStore.getInstance("JCEKS");
        ks.load(new FileInputStream(CLAKEYSTORE),
                CLAPASSWORD.toCharArray());
        KeyStore ts = KeyStore.getInstance("JCEKS");
        ts.load(new FileInputStream(CLATRUSTSTORE),
                CLAPASSWORD.toCharArray());
        System.out.print("done.\n");

        System.out.print("Preparing trust managers... ");
        // setup key/trust managers
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, CLAPASSWORD.toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ts);
        System.out.print("done.\n");

        // setup ssl server
        System.out.print("Starting server... ");
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        SSLServerSocketFactory sslServer = serverContext.getServerSocketFactory();

        SSLServerSocket sss = (SSLServerSocket) sslServer.createServerSocket(Settings.CLA_PORT);
        sss.setEnabledCipherSuites(sss.getSupportedCipherSuites());
        System.out.print("done.\n");

        // setup ssl client
        System.out.print("Setting up SSL Client... ");
        SSLContext clientContext = SSLContext.getInstance("TLS");
        clientContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        sslClientFact = clientContext.getSocketFactory();
        System.out.print("done.\n");

        // require client auth
//        sss.setNeedClientAuth(true);
        System.out.println("CLA server running on port " + Settings.CLA_PORT);

        // prepare incoming connections
        System.out.println("Starting server socket IO, accepting connections. ");
        incoming = (SSLSocket) sss.accept();
        serverInput = new BufferedReader(
                new InputStreamReader(incoming.getInputStream()));
        serverOutput = new PrintWriter(incoming.getOutputStream(), true);
    }

    private void receiveConnections() throws Exception {
        String str = serverInput.readLine();
        while (!str.equals(Settings.Commands.TERMINATE)) {
            switch (str) {
                case Settings.Commands.CLIENT_CTF:
                    authorizeVoters();
                    break;
                case "": break;
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

    private void authorizeVoters() throws Exception {
        String str;
        while (!(str = serverInput.readLine())
                .equals(Settings.Commands.END)) {
            System.out.println("s: " + str);
            // remove 'id=' from string and parse as int
            int id = Integer.parseInt(str.substring(3));
            Voter v = new Voter(-1, id);
            if (!authorizedVoters.contains(v) && v.getId() > Settings.MIN_AGE) {
                v.setValidationNumber(BigInteger.probablePrime(
                        Settings.VALIDATION_BITLENGTH, new SecureRandom()));
                authorizedVoters.add(v);
                serverOutput.println(v.CTFToClient() + '\n' + Settings.Commands.END);
            }

        }
    }

    private void startClient(InetAddress hostAddr, int port) throws Exception {
        SSLSocket client = (SSLSocket) sslClientFact.createSocket(hostAddr, port);
        client.setEnabledCipherSuites(client.getSupportedCipherSuites());

        clientInput = new BufferedReader(new InputStreamReader(client.getInputStream()));
        clientOutput = new PrintWriter(client.getOutputStream(), true);
    }


    public static void main(String[] args) {
        try {
            CentralLegitimizationAgency cla = new CentralLegitimizationAgency();
            cla.run();
        } catch (Exception e) {
            System.out.println(e);
            e.printStackTrace();
        }
    }

    public void run() throws Exception {
        System.out.println("Setting up CLA...");
        setup();
        receiveConnections();
    }
}
