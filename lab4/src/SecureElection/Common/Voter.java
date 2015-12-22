package SecureElection.Common;

import java.math.BigInteger;
import java.util.Random;

/**
 * Created by Klas Eskilson on 15-11-16.
 */

public class Voter {
    private BigInteger validationNumber = BigInteger.ZERO;
    private int choice, id;

    public Voter() {
        Random r = new Random();
        this.id = r.nextInt(1000000000);
        this.choice = -1;
    }

    public Voter(int choice, int id) {
        this.choice = choice;
        this.id = id;
    }

    public Voter(int choice) {
        Random r = new Random();
        this.id = r.nextInt(1000000000);
        this.choice = choice;
    }

    public int getId() {
        return id;
    }

    public void setValidationNumber(BigInteger validationNumber) {
        this.validationNumber = validationNumber;
    }

    public BigInteger getValidationNumber() {
        return validationNumber;
    }

    public void setChoice(int choice) {
        this.choice = choice;
    }

    public String clientToCTF() {
        return "id=" + id;
    }

    public String CTFToClient() {
        return validationNumber.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Voter voter = (Voter) o;

        return id == voter.id;

    }

    @Override
    public String toString() {
        return "Voter{" +
                "validationNumber=" + validationNumber +
                ", choice=" + choice +
                ", id=" + id +
                '}';
    }
}
