package SecureElection;

import SecureElection.Common.Settings;
import SecureElection.Common.Voter;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.KeyStore;
import java.util.*;

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
    Vector<Voter> voters = new Vector<>();
    Map<Integer, Integer> votes = new HashMap<Integer, Integer>();

    // server/client socket and IO vars
    BufferedReader serverInput;
    PrintWriter serverOutput;
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

        // require client auth
        sss.setNeedClientAuth(true);
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
                case Settings.Commands.REGISTER_VALID:
                    registerValidationNumber();
                    break;
                case Settings.Commands.REGISTER_VOTE:
                    registerVote();
                    break;
                case Settings.Commands.REQUEST_RESULT:
                    sendResult();
                    break;
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

    private void registerValidationNumber() throws Exception {
        String str = serverInput.readLine();
        System.out.println("s: " + str);
        if (!authorizedVoters.contains(str)) {
            authorizedVoters.add(str);
        }
    }

    private void registerVote() throws Exception {
        String str = serverInput.readLine();
        System.out.println("s: " + str);
        String[] s = str.split("-");
        if (authorizedVoters.contains(s[1])) {
            int id = Integer.parseInt(s[0]),
                choice = Integer.parseInt(s[2]);
            BigInteger validationNumber = new BigInteger(s[1]);
            Voter v = new Voter(validationNumber, choice, id);
            if (!voters.contains(v)) {
                System.out.println(v);
                voters.add(v);
                // save vote
                votes.put(choice, votes.getOrDefault(choice, 0) + 1);
            }
        }
    }

    private void sendResult() throws Exception {
        int total = voters.size();
        serverOutput.println("Total votes: " + total);
        // get all votes and calculate their percentage
        for (Map.Entry<Integer, Integer> v : votes.entrySet()) {
            float res = 100 * v.getValue() / total;
            serverOutput.println("Alternative " + v.getKey() + ": "
                    + v.getValue() + " (" +  res + "%)");
        }
        serverOutput.println(Settings.Commands.END);
    }

    public void run() throws Exception {
        setup();
        receiveConnections();
        receiveConnections();
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
}
