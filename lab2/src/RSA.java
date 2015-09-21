import com.sun.javafx.event.CompositeEventTarget;

import java.math.BigInteger;
import java.util.Random;

/**
 * Created by kalas on 2015-09-12.
 */

public class RSA {
    final static int KEYSIZE = 1024;
    final static int BIT_LENGTH = 1024;
    final static int EXPONENT_BIT_LENGTH = 1024;

    private BigInteger n, e, d;

    /**
     * constructor, create our RSA session
     */
    public RSA() {
        // create our numbers
        BigInteger p = BigInteger.probablePrime(BIT_LENGTH, new Random());
        BigInteger q = BigInteger.probablePrime(BIT_LENGTH, new Random());
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        e = BigInteger.probablePrime(EXPONENT_BIT_LENGTH, new Random());
        n = p.multiply(q);

        // get d such that (ed % pq = 1)
        d = e.modInverse(phi);

//        System.out.println("n: " + n);
//        System.out.println("e: " + e);
//        System.out.println("gcd: " + e.gcd(pq) + "\n");
    }

    /**
     * getter for the E variable, one of the public keys
     * @return e
     */
    public BigInteger getE() {
        return e;
    }

    /**
     * getter for the N variable, one of the public keys
     * @return n
     */
    public BigInteger getN() {
        return n;
    }

    public BigInteger getD() {
        return d;
    }

    /**
     * Static, encrypt a message given two public keys
     * @param message the message to encrypt
     * @param exp     the e variable
     * @param product the n variable
     * @return the encrypted message
     */
    static public BigInteger encrypt(String message, BigInteger exp, BigInteger product) {
        BigInteger c = new BigInteger(message.getBytes());
        // return biginteger such that encrypted = c^exp % product
        return c.modPow(exp, product);
    }

    /**
     * decrypt message encrypted with this session's public keys
     * @param c the encrypted message
     * @return the decrypted message
     */
    public String decrypt(BigInteger c) {
        BigInteger m = c.modPow(this.e, this.n);
        return new String(m.toByteArray());
    }

}
