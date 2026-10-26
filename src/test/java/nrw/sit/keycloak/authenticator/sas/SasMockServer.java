package nrw.sit.keycloak.authenticator.sas;

import com.safenet.keycloak.agent.tokenvalidatoradapter.tvadapter.crypto.AgentKeyFile;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Test double for SAS PCE with REAL crypto: generates an agent key file in the exact format
 * the vendor {@code AgentKeyFile} class parses (mirror of {@code openRawFile}), and runs a
 * SOAP mock that decrypts requests / encrypts responses with the vendor class itself.
 *
 * <p>Usable as JUnit fixture (see {@link SasEndToEndTest}) and as a standalone process for
 * manual Keycloak tests:
 * <pre>
 *   java -cp ... nrw.sit.keycloak.authenticator.sas.SasMockServer 9999 /tmp/test.bsidkey
 *   # accepts OTP "123456" for every user, rejects everything else
 * </pre>
 */
public final class SasMockServer {

    /** Hard-coded password from the vendor class (pszValue). */
    static final byte[] VENDOR_PASSWORD = "2wsder@WSDER67tyghbn^&TYGHBN!@#$%^&*().|".getBytes(StandardCharsets.US_ASCII);

    private final HttpServer server;
    private final AgentKeyFile keyFile;
    private final Map<String, String> validOtps = new ConcurrentHashMap<>();
    private volatile String lastDecryptedRequest;
    private volatile String forcedReturnValue;
    private volatile boolean verbose;

    public SasMockServer(int port, String keyFileBase64) throws IOException {
        this.keyFile = new AgentKeyFile(Base64.getDecoder().decode(keyFileBase64), null);
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/TokenValidator/TokenValidator.asmx", ex -> {
            String soap = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String enc = between(soap, "<blac:CRYPTOCardData>", "</blac:CRYPTOCardData>");
            String xml = keyFile.decrypt(enc);
            lastDecryptedRequest = xml;
            String user = between(xml, "<username>", "</username>");
            String pass = between(xml, "<passcode>", "</passcode>");
            String expected = validOtps.getOrDefault(user, validOtps.get("*"));
            String rv = forcedReturnValue != null ? forcedReturnValue
                    : (pass != null && pass.equals(expected) ? "1" : "0");
            if (verbose) {
                System.out.println("user=" + user + " passcode=" + pass + " -> return_value=" + rv);
            }
            String plain = "<xml><CRYPTOCard><return_value>" + rv + "</return_value><message>mock</message></CRYPTOCard></xml>";
            String reply = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\">"
                    + "<soap:Body><AuthenticateTokenResponse xmlns=\"http://www.cryptocard.com/blackshield/\"><AuthenticateTokenResult>"
                    + keyFile.encrypt(plain)
                    + "</AuthenticateTokenResult></AuthenticateTokenResponse></soap:Body></soap:Envelope>";
            byte[] out = reply.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/soap+xml; charset=utf-8");
            ex.sendResponseHeaders(200, out.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(out);
            }
        });
    }

    public void start() {
        server.start();
    }

    public void stop() {
        server.stop(0);
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public String url() {
        return "http://127.0.0.1:" + port() + "/TokenValidator/TokenValidator.asmx?orgCode=MOCK";
    }

    public void allow(String user, String otp) {
        validOtps.put(user, otp);
    }

    public void forceReturnValue(String rv) {
        forcedReturnValue = rv;
    }

    public String lastDecryptedRequest() {
        return lastDecryptedRequest;
    }

    private static String between(String s, String a, String b) {
        int i = s.indexOf(a);
        int j = i < 0 ? -1 : s.indexOf(b, i + a.length());
        return i < 0 || j < 0 ? null : s.substring(i + a.length(), j);
    }

    // ---------------------------------------------------------------- key file generation

    /** Returns the Base64 text of a new agent key file (what SAS would let you download). */
    public static String generateKeyFile() throws Exception {
        byte[] aesKey = new byte[32];
        new SecureRandom().nextBytes(aesKey);
        return generateKeyFile(aesKey);
    }

    static String generateKeyFile(byte[] aesKey) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        byte[] password = VENDOR_PASSWORD;
        byte[] salt = new byte[8];
        new SecureRandom().nextBytes(salt);

        String xml = "<SafeNet>" + Base64.getEncoder().encodeToString(aesKey) + "</SafeNet>";
        byte[] xmlBytes = xml.getBytes(StandardCharsets.UTF_8);

        byte[] keyVerify = Arrays.copyOf(sha.digest(concat(password, salt)), 8);

        // MAC = SHA1(key2 || SHA1(key1 || xml)), key1/key2 = Mash(password,16,1) padded to 64, XOR 0x36 / 0x5C
        byte[] macMash = mash(password, 16, 1);
        byte[] key1 = new byte[64];
        byte[] key2 = new byte[64];
        System.arraycopy(macMash, 0, key1, 0, 16);
        for (int i = 0; i < 64; i++) {
            key2[i] = (byte) (key1[i] ^ 0x5C);
            key1[i] = (byte) (key1[i] ^ 0x36);
        }
        byte[] stage1 = sha.digest(concat(key1, xmlBytes));
        byte[] mac = sha.digest(concat(key2, stage1));

        byte[] plain = concat(concat(keyVerify, xmlBytes), mac);

        byte[] mashed = mash(concat(password, salt), 24, 200);
        byte[] tdesKey = new byte[24];
        System.arraycopy(mashed, 0, tdesKey, 0, 16);
        System.arraycopy(mashed, 0, tdesKey, 16, 8);
        byte[] iv = Arrays.copyOfRange(mashed, 16, 24);
        Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(tdesKey, "DESede"), new IvParameterSpec(iv));
        byte[] cipher = c.doFinal(plain);

        return Base64.getEncoder().encodeToString(concat(salt, cipher));
    }

    /** Mirror of the vendor's proprietary SHA-1 stretching (AgentKeyFile.Mash). */
    static byte[] mash(byte[] in, int outLen, int iterations) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        int digest = sha.getDigestLength();
        int bufSize = ((outLen + digest - 1) / digest) * digest;
        byte[] buf = new byte[bufSize];
        byte[] out = new byte[bufSize];
        byte[] mangler = new byte[in.length + 2];
        for (int i = 0; i < outLen; i += digest) {
            mangler[0] = (byte) (i >> 8);
            mangler[1] = (byte) i;
            System.arraycopy(in, 0, mangler, 2, in.length);
            System.arraycopy(sha.digest(mangler), 0, out, i, digest);
        }
        byte[] big = new byte[bufSize + 2];
        while (iterations-- > 1) {
            System.arraycopy(out, 0, buf, 0, bufSize);
            for (int i = 0; i < bufSize; i += digest) {
                big[0] = (byte) (i >> 8);
                big[1] = (byte) i;
                System.arraycopy(buf, 0, big, 2, bufSize);
                System.arraycopy(sha.digest(big), 0, out, i, digest);
            }
        }
        return Arrays.copyOf(out, outLen);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    /** Standalone: {@code SasMockServer <port> <keyFilePathToWrite>} – accepts OTP 123456 for everyone. */
    public static void main(String[] args) throws Exception {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 9999;
        Path keyPath = Path.of(args.length > 1 ? args[1] : "test.bsidkey");
        String key = generateKeyFile();
        Files.writeString(keyPath, key);
        SasMockServer mock = new SasMockServer(port, key);
        mock.allow("*", "123456");
        mock.verbose = true;
        mock.start();
        System.out.println("SAS mock listening on " + mock.url() + " – key file written to " + keyPath.toAbsolutePath());
        Thread.currentThread().join();
    }
}
