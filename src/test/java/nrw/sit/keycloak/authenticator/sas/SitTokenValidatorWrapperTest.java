package nrw.sit.keycloak.authenticator.sas;

import com.safenet.keycloak.agent.tokenvalidatoradapter.dto.tv.SasTokenAuthReq;
import com.safenet.keycloak.agent.tokenvalidatoradapter.dto.tv.TVRequestCredentialType;
import com.safenet.keycloak.agent.tokenvalidatoradapter.dto.tv.TVRequestType;
import com.safenet.keycloak.agent.tokenvalidatoradapter.dto.tv.TokenValidatorRequestDTO;
import com.safenet.keycloak.agent.tokenvalidatoradapter.dto.tv.TokenValidatorResponseDTO;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Transport tests against an in-JVM SOAP mock. The vendor crypto needs a real agent key file,
 * so a test subclass makes encrypt/decrypt the identity function; request-XML building and
 * response unmarshalling (vendor JAXB) run for real.
 */
class SitTokenValidatorWrapperTest {

    /** Crypto disabled, everything else vendor + our transport. */
    static class PlainTextWrapper extends SitTokenValidatorWrapper {
        PlainTextWrapper(String url) {
            super(url, "unused");
        }

        @Override
        protected com.safenet.keycloak.agent.tokenvalidatoradapter.tvadapter.crypto.AgentKeyFile getAgentKeyfile() {
            return null; // vendor authenticate() loads the key file eagerly; no real key in unit tests
        }

        @Override
        protected String encryptContent(String xml, int version) {
            return xml;
        }

        @Override
        protected TokenValidatorResponseDTO doDecryptionAfterAutheticate(String plain) {
            SasTokenAuthReq r = getUnmarshalledReq(plain);
            TokenValidatorResponseDTO dto = new TokenValidatorResponseDTO();
            dto.setReturnValue(r.getCryptoCardElement().getReturnValue());
            dto.setChallengedata(r.getCryptoCardElement().getChallengedata());
            dto.setMessage(r.getCryptoCardElement().getMessage());
            return dto;
        }
    }

    record Captured(Map<String, List<String>> headers, String body) {
    }

    private HttpServer server;
    private final List<Captured> captured = new CopyOnWriteArrayList<>();
    private volatile int replyStatus = 200;
    private volatile String replyBody = "";

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/TokenValidator/TokenValidator.asmx", ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, List<String>> h = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            h.putAll(ex.getRequestHeaders());
            captured.add(new Captured(h, body));
            byte[] out = replyBody.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/soap+xml; charset=utf-8");
            ex.sendResponseHeaders(replyStatus, out.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(out);
            }
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/TokenValidator/TokenValidator.asmx?orgCode=TESTORG";
    }

    private static String soapReply(String returnValue, String challengeData) {
        return "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\">"
                + "<soap:Body><AuthenticateTokenResponse xmlns=\"http://www.cryptocard.com/blackshield/\">"
                + "<AuthenticateTokenResult>"
                + "<xml><CRYPTOCard><return_value>" + returnValue + "</return_value>"
                + (challengeData == null ? "" : "<challengedata>" + challengeData + "</challengedata>")
                + "<message>mock</message></CRYPTOCard></xml>"
                + "</AuthenticateTokenResult></AuthenticateTokenResponse></soap:Body></soap:Envelope>";
    }

    private static TokenValidatorRequestDTO request(String user, String otp) {
        return new TokenValidatorRequestDTO.TokenValidatorRequestBuilder()
                .username(user).password(otp).userIpAddress("10.0.0.1").resourceName("test-client")
                .isAgentOtgEnabled(true)
                .tvRequestType(TVRequestType.verifycredentials)
                .tvRequestCredentialType(TVRequestCredentialType.TokenValidation)
                .build();
    }

    @Test
    void sendsVendorCompatibleSoapRequest() {
        replyBody = soapReply("1", null);
        new PlainTextWrapper(url()).authenticate(request("alice", "123456"));

        assertEquals(1, captured.size());
        Captured c = captured.get(0);
        assertEquals("http://www.cryptocard.com/blackshield/AuthenticateToken", c.headers().get("SOAPAction").get(0));
        assertEquals("1.0.0:30", c.headers().get("AgentInfo").get(0));
        assertTrue(c.headers().get("Content-Type").get(0).startsWith("application/soap+xml"));
        assertEquals("text/xml", c.headers().get("Accept").get(0));
        assertTrue(c.body().startsWith(SitTokenValidatorWrapper.SOAP_ENVELOPE_PREFIX));
        assertTrue(c.body().endsWith(SitTokenValidatorWrapper.SOAP_ENVELOPE_SUFFIX));
        // vendor-built request XML travels inside CRYPTOCardData (plain text in this test)
        assertTrue(c.body().contains("<username>alice</username>"));
        assertTrue(c.body().contains("<passcode>123456</passcode>"));
        assertTrue(c.body().contains("<requesttype>verifycredentials</requesttype>"));
        assertTrue(c.body().contains("<agentid>30</agentid>"));
    }

    @Test
    void mapsReturnValueFromResponse() {
        replyBody = soapReply("1", null);
        TokenValidatorResponseDTO dto = new PlainTextWrapper(url()).authenticate(request("alice", "123456"));
        assertNotNull(dto);
        assertEquals("1", dto.getReturnValue());

        replyBody = soapReply("0", null);
        assertEquals("0", new PlainTextWrapper(url()).authenticate(request("alice", "000000")).getReturnValue());

        replyBody = soapReply("2", "SMS");
        dto = new PlainTextWrapper(url()).authenticate(request("alice", ""));
        assertEquals("2", dto.getReturnValue());
        assertEquals("SMS", dto.getChallengedata());
    }

    @Test
    void httpErrorYieldsNull() {
        replyStatus = 500;
        replyBody = "boom";
        assertNull(new PlainTextWrapper(url()).authenticate(request("alice", "123456")));
    }

    @Test
    void missingResultElementYieldsNull() {
        replyBody = "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"><soap:Body/></soap:Envelope>";
        assertNull(new PlainTextWrapper(url()).authenticate(request("alice", "123456")));
    }

    @Test
    void unreachableHostYieldsNull() {
        assertNull(new PlainTextWrapper("http://127.0.0.1:1/TokenValidator/TokenValidator.asmx")
                .authenticate(request("alice", "123456")));
    }

    @Test
    void clientMapsResultCodes() {
        replyBody = soapReply("1", null);
        assertEquals(SasTokenValidatorClient.Result.ACCEPTED, clientWith(url()).validate("alice", "1", null, null));
        replyBody = soapReply("0", null);
        assertEquals(SasTokenValidatorClient.Result.REJECTED, clientWith(url()).validate("alice", "1", null, null));
        replyBody = soapReply("12", null);
        assertEquals(SasTokenValidatorClient.Result.REJECTED, clientWith(url()).validate("alice", "1", null, null));
        replyBody = soapReply("10", null);
        assertEquals(SasTokenValidatorClient.Result.UNSUPPORTED, clientWith(url()).validate("alice", "1", null, null));
        replyBody = soapReply("2", "GrIDsure");
        assertEquals(SasTokenValidatorClient.Result.UNSUPPORTED, clientWith(url()).validate("alice", "1", null, null));
        replyStatus = 503;
        assertEquals(SasTokenValidatorClient.Result.ERROR, clientWith(url()).validate("alice", "1", null, null));
    }

    private static SasTokenValidatorClient clientWith(String url) {
        return new SasTokenValidatorClient(new PlainTextWrapper(url));
    }
}
