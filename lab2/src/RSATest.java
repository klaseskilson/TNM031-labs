import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;

/**
 * Created by kalas on 2015-09-12.
 */

public class RSATest {

    public static void main (String[] args) {
        // start new rsa session
        RSA session = new RSA();

        while (true) {
            System.out.println("\nEnter message to encrypt (empty to quit):");
            String input = "";
            try {
                input = (new BufferedReader(new InputStreamReader(System.in))).readLine();
            } catch(IOException e) {
                System.out.println("Something went wrong: " + e.toString());
                break;
            }

            if (input.equals(""))
                break;

            // get public keys and encrypt
            BigInteger encrypted = RSA.encrypt(input, session.getE(), session.getN());

            // present encrypted and decrypted message
            System.out.println("Encrypted message:\n" + encrypted);
            System.out.println("Decrypted message:\n" + session.decrypt(encrypted));
        }
    }
}
