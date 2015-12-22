package SecureElection;

import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.KeyStore;
import java.util.Vector;
import javax.net.ssl.*;
import SecureElection.Common.Settings;
import SecureElection.Common.Voter;

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
    Vector<Voter> voters;

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

    private void startClient(InetAddress hostAddr, int port) throws Exception {
        System.out.println("Connecting client to " + hostAddr.toString() + ":" + port);
        SSLSocket client = (SSLSocket) sslFact.createSocket(hostAddr, port);
        client.setEnabledCipherSuites(client.getSupportedCipherSuites());

        // setup transmissions
        socketIn = new BufferedReader(new InputStreamReader(client.getInputStream()));
        socketOut = new PrintWriter(client.getOutputStream(), true);
    }

    private void validateVoters(Vector<Voter> theVoters) throws Exception {
        // send voters to ctf
        socketOut.println(Settings.Commands.CLIENT_CTF);
        for (Voter v : theVoters) {
            socketOut.println(v.clientToCTF());
            // receive response (validation number) from server
            String resp;
            while (!(resp = socketIn.readLine()).equals(Settings.Commands.END)) {
                // System.out.println(resp);
                // use the server response to create our validation number
                BigInteger validationNumber = new BigInteger(resp);
                if (validationNumber.toString().equals("0")) {
                    v.setValidationNumber(new BigInteger(resp));
                }
            }
        }
        socketOut.println(Settings.Commands.END);
    }

    /**
     * simple testing function for the secure voting machine
     * @throws Exception
     */
    public void run() throws Exception {
        // setup connection
        InetAddress localhost = InetAddress.getLocalHost();
        setup();
        // connect to cla
        startClient(localhost, Settings.CLA_PORT);

        // create and validate voters with the CLA
        voters = new Vector<>();
        for (int i = 0; i < 10; ++i) {
            voters.add(new Voter(i % 3));
        }
        validateVoters(voters);

        // receive votes
        // connect to ctf
        // send votes
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
}
