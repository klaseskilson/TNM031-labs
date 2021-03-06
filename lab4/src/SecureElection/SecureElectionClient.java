package SecureElection;

import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.util.Vector;
import javax.net.ssl.*;

import SecureElection.Common.Client;
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
    Vector<Voter> voters;

    private void startClient(InetAddress host, int port) throws Exception {
        Client client = new Client(CLIENTKEYSTORE, CLIENTTRUSTSTORE, CLIENTPASSWORD, host, port);
        SSLSocket c = client.getSocket();
        // setup transmissions
        socketIn = new BufferedReader(new InputStreamReader(c.getInputStream()));
        socketOut = new PrintWriter(c.getOutputStream(), true);
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
                if (!validationNumber.toString().equals("0")) {
                    v.setValidationNumber(new BigInteger(resp));
                }
            }
        }
        socketOut.println(Settings.Commands.END);
    }

    private void sendVote(Voter v) {
        socketOut.println(Settings.Commands.REGISTER_VOTE);
        socketOut.println(v.toVote());
        socketOut.println(Settings.Commands.END);
    }

    private void getResult() throws Exception {
        socketOut.println(Settings.Commands.REQUEST_RESULT);
        String resp;
        while (!(resp = socketIn.readLine()).equals(Settings.Commands.END)) {
            System.out.println(resp);
        }
    }

    /**
     * simple testing function for the secure voting machine
     * @throws Exception
     */
    public void run() throws Exception {
        // connect to cla
        startClient(InetAddress.getLocalHost(), Settings.CLA_PORT);

        // create and validate voters with the CLA
        voters = new Vector<>();
        for (int i = 0; i < 10; ++i) {
            voters.add(new Voter(i % 3));
        }
        validateVoters(voters);

        // connect to ctf
        startClient(InetAddress.getLocalHost(), Settings.CTF_PORT);

        // send votes
        for (Voter v : voters) {
            sendVote(v);
        }

        // ask for result
        getResult();
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
