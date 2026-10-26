package nrw.sit.keycloak.authenticator.sas;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Full path with the PRODUCTION wrapper and the vendor crypto on both ends: agent key file
 * parsing, AES-GCM encryption of the request, SOAP transport, decryption + unmarshalling of
 * the reply. Only the SAS server itself is a mock.
 */
class SasEndToEndTest {

    private SasMockServer sas;
    private String keyFileBase64;
    private Path keyFilePath;

    @BeforeEach
    void start() throws Exception {
        // Keycloak registers BouncyCastle at startup; the vendor AES-GCM code needs it (AEADParameterSpec)
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        keyFileBase64 = SasMockServer.generateKeyFile();
        keyFilePath = Files.createTempFile("agent", ".bsidkey");
        Files.writeString(keyFilePath, keyFileBase64);
        sas = new SasMockServer(0, keyFileBase64);
        sas.allow("alice", "123456");
        sas.start();
    }

    @AfterEach
    void stop() throws Exception {
        sas.stop();
        Files.deleteIfExists(keyFilePath);
    }

    @Test
    void acceptsCorrectOtpWithKeyFilePath() {
        SasTokenValidatorClient client = new SasTokenValidatorClient(sas.url(), keyFilePath.toString());
        assertEquals(SasTokenValidatorClient.Result.ACCEPTED, client.validate("alice", "123456", "10.1.2.3", "client-a"));
        String req = sas.lastDecryptedRequest();
        assertTrue(req.contains("<username>alice</username>"));
        assertTrue(req.contains("<passcode>123456</passcode>"));
        assertTrue(req.contains("<user_ipaddress>10.1.2.3</user_ipaddress>"));
        assertTrue(req.contains("<ResourceName>client-a</ResourceName>"));
    }

    @Test
    void acceptsCorrectOtpWithKeyFileContent() {
        SasTokenValidatorClient client = new SasTokenValidatorClient(sas.url(), keyFileBase64);
        assertEquals(SasTokenValidatorClient.Result.ACCEPTED, client.validate("alice", "123456", null, null));
    }

    @Test
    void rejectsWrongOtp() {
        SasTokenValidatorClient client = new SasTokenValidatorClient(sas.url(), keyFilePath.toString());
        assertEquals(SasTokenValidatorClient.Result.REJECTED, client.validate("alice", "999999", null, null));
        assertEquals(SasTokenValidatorClient.Result.REJECTED, client.validate("bob", "123456", null, null));
    }

    @Test
    void unsupportedServerActions() {
        SasTokenValidatorClient client = new SasTokenValidatorClient(sas.url(), keyFilePath.toString());
        sas.forceReturnValue("10"); // push dispatched
        assertEquals(SasTokenValidatorClient.Result.UNSUPPORTED, client.validate("alice", "123456", null, null));
        sas.forceReturnValue("4"); // user pin change
        assertEquals(SasTokenValidatorClient.Result.UNSUPPORTED, client.validate("alice", "123456", null, null));
    }

    @Test
    void wrongKeyFileIsError() throws Exception {
        // a key file for a different AES key: our request decrypts on the mock side to garbage -> mock can't answer
        String otherKey = SasMockServer.generateKeyFile();
        SasTokenValidatorClient client = new SasTokenValidatorClient(sas.url(), otherKey);
        assertEquals(SasTokenValidatorClient.Result.ERROR, client.validate("alice", "123456", null, null));
    }

    @Test
    void corruptKeyFileIsError() {
        SasTokenValidatorClient client = new SasTokenValidatorClient(sas.url(), "bm90IGEga2V5ZmlsZQ==");
        assertEquals(SasTokenValidatorClient.Result.ERROR, client.validate("alice", "123456", null, null));
    }
}
