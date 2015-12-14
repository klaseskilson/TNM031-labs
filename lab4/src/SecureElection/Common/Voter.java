package SecureElection.Common;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Created by Klas Eskilson on 15-11-16.
 */

public class Voter {
    private BigInteger validationNumber;
    private int choice, id;

    public Voter() {
        Random r = new Random();
        this.id = r.nextInt(1000000000);
    }

    public int getId() {
        return id;
    }

    public void setValidationNumber(BigInteger validationNumber) {
        this.validationNumber = validationNumber;
    }

    public void setChoice(int choice) {
        this.choice = choice;
    }
}
