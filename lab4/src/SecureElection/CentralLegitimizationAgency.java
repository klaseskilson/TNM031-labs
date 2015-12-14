package SecureElection;

import java.util.Vector;

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

    public static void main(String[] args) {

    }
}
