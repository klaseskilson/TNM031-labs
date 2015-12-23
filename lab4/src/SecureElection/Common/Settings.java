package SecureElection.Common;

/**
 * Created by kalas on 2015-11-20.
 */
public class Settings {
    public static final int CLA_PORT = 8988;
    public static final int CTF_PORT = 8989;
    public static final int MIN_AGE = 10000;
    public static final int VALIDATION_BITLENGTH = 64;
    public static final String KEYLOCATION = "./assets/";

    public static final class Commands {
        public static final String END = "cmd:end";
        public static final String TERMINATE = "cmd:die";
        public static final String CLIENT_CTF = "cmd:client_ctf";
        public static final String REGISTER_VALID = "cmd:reg_valid";
        public static final String REGISTER_VOTE = "cmd:reg_vote";
        public static final String REQUEST_RESULT = "cmd:req_res";
    }
}
