package SecureElection;

import SecureElection.Common.Server;
import SecureElection.Common.Settings;
import SecureElection.Common.Voter;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.*;

public class CentralTabulatingFacility implements Runnable {
    // constants
    private static final String CTFTRUSTSTORE = Settings.KEYLOCATION + "CTFTruststore.ks";
    private static final String CTFKEYSTORE   = Settings.KEYLOCATION + "CTFKeystore.ks";
    private static final String CTFPASSWORD   = "somephrase";

    // string versions of CLA's validation numbers
    private Vector<String> authorizedVoters = new Vector<>();
    private Vector<Voter> voters = new Vector<>();
    private Map<Integer, Integer> votes = new HashMap<Integer, Integer>();

    // server/client socket and IO vars
    SSLSocket incoming;
    BufferedReader serverInput;
    PrintWriter serverOutput;

    public CentralTabulatingFacility(SSLSocket incoming) {
        this.incoming = incoming;
    }

    public void setAuthorizedVoters(Vector<String> authorizedVoters) {
        this.authorizedVoters = authorizedVoters;
    }

    public void setVoters(Vector<Voter> voters) {
        this.voters = voters;
    }

    public void setVotes(Map<Integer, Integer> votes) {
        this.votes = votes;
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

    public void run() {
        try {
            // prepare incoming connections
            serverInput = new BufferedReader(
                    new InputStreamReader(incoming.getInputStream()));
            serverOutput = new PrintWriter(incoming.getOutputStream(), true);
            String str = serverInput.readLine();
            while (str != null) {
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

                str = serverInput.readLine();
            }
            incoming.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            Server s = new Server(CTFKEYSTORE, CTFTRUSTSTORE, CTFPASSWORD, Settings.CTF_PORT);
            // shared resources for all threads
            Vector<String> authorizedVoters = new Vector<>();
            Vector<Voter> voters = new Vector<>();
            Map<Integer, Integer> votes = new HashMap<Integer, Integer>();

            while (true) {
                SSLSocket socket = (SSLSocket) s.getServerSocket().accept();
                System.out.println("New client connected");
                CentralTabulatingFacility c = new CentralTabulatingFacility(socket);
                c.setAuthorizedVoters(authorizedVoters);
                c.setVoters(voters);
                c.setVotes(votes);
                Thread t = new Thread(c);
                t.start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
