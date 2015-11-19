package SecureElection.Common;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by Klas Eskilson on 15-11-16.
 */

public class Voter {
    public static int BITLENGTH = 128;

    private BigInteger validationNumber, identificationNumber;
    private int choice;

    public Voter() {
        this.identificationNumber = BigInteger.probablePrime(BITLENGTH, new SecureRandom());
    }

    public BigInteger getIdentificationNumber() {
        return identificationNumber;
    }

    public void setChoice(int choice) {
        this.choice = choice;
    }
}
