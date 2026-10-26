package nrw.sit.keycloak.authenticator.sas;

import com.safenet.keycloak.agent.tokenvalidatoradapter.dto.tv.TokenValidatorResponseDTO;
import com.safenet.keycloak.agent.tokenvalidatoradapter.tvadapter.TVUrl;
import com.safenet.keycloak.agent.tokenvalidatoradapter.tvadapter.TokenValidatorWrapperImpl;
import com.safenet.keycloak.agent.tokenvalidatoradapter.tvadapter.exception.TokenValidatorWrapperException;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.time.Duration;

/**
 * Thales {@code TokenValidatorWrapperImpl} with the HTTP transport replaced.
 *
 * <p>Kept from the vendor (unchanged, protected methods of the superclass):
 * request-XML building, {@code createFullUrl}, agent key file handling, AES-GCM
 * encryption/decryption, response unmarshalling. Replaced: only the piece between
 * "encrypted payload" and "encrypted reply" – the SOAP POST – which now uses the JDK
 * {@link HttpClient}. This removes the dependency on the vendor {@code SoapClient}
 * (Apache HttpClient 4 from Keycloak), the primary/secondary failover and the HTTP-307
 * push handling, none of which this authenticator uses.
 *
 * <p>The SOAP envelope, SOAPAction and the {@code AgentInfo} header are byte-for-byte what the
 * vendor client sends (see decompiled {@code SoapClient.invoke} /
 * {@code TokenValidatorWrapperImpl.processAuthentication}).
 *
 * <p>TLS: the JDK default {@code SSLContext} is used, i.e. Keycloak's {@code --truststore-paths}
 * applies. Proxy: {@code HTTPS_PROXY}/{@code HTTP_PROXY}/{@code NO_PROXY} from the environment
 * (see {@link EnvProxySelector}), same as Keycloak's own HttpClientProvider. Without those
 * variables the connection is direct (like the vendor client).
 */
public class SitTokenValidatorWrapper extends TokenValidatorWrapperImpl {

    private static final Logger LOG = Logger.getLogger(SitTokenValidatorWrapper.class);

    static final String SOAP_ACTION_AUTHENTICATE = "http://www.cryptocard.com/blackshield/AuthenticateToken";
    static final String SOAP_ENVELOPE_PREFIX =
            "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" "
            + "xmlns:blac=\"http://www.cryptocard.com/blackshield/\"><soap:Header/><soap:Body>"
            + "<blac:AuthenticateToken><blac:CRYPTOCardData>";
    static final String SOAP_ENVELOPE_SUFFIX =
            "</blac:CRYPTOCardData></blac:AuthenticateToken></soap:Body></soap:Envelope>";
    static final String RESULT_START = "<AuthenticateTokenResult>";
    static final String RESULT_END = "</AuthenticateTokenResult>";
    /** Vendor sends "<APPLICATION_VERSION>:<agentid>"; agentid 30 = Keycloak agent. */
    static final String AGENT_INFO = "1.0.0:30";

    static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(15);

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1) // no h2c upgrade header; behave like the vendor client
            .proxy(EnvProxySelector.fromEnvironment())
            .connectTimeout(CONNECT_TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    private final String primaryUrl;

    public SitTokenValidatorWrapper(String tokenValidatorUrl, String agentKeyFilePathOrContent) {
        // secondary URL "" – never used, but the superclass calls .length() on it
        super(tokenValidatorUrl, "", resolveKeyFile(agentKeyFilePathOrContent));
        this.primaryUrl = tokenValidatorUrl;
    }

    /**
     * The vendor's path detection ({@code DataValidationUtils.isValidPath}) only matches Windows
     * paths ({@code C:\...\x.bsidkey}); a Linux path is silently treated as Base64 content and
     * fails with "Invalid file". So resolve the path here and always hand the content to the
     * vendor class.
     */
    static String resolveKeyFile(String pathOrContent) {
        if (pathOrContent == null) {
            return null;
        }
        String v = pathOrContent.trim();
        try {
            Path p = Path.of(v);
            if (Files.isRegularFile(p)) {
                return Files.readString(p, StandardCharsets.UTF_8).trim();
            }
        } catch (InvalidPathException e) {
            // not a path -> content
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read agent key file " + v, e);
        }
        return v;
    }

    /** No failover: always the configured URL. Also avoids instantiating the vendor SoapClient. */
    @Override
    protected String getSASServerURL() {
        return primaryUrl;
    }

    @Override
    protected TokenValidatorResponseDTO processAuthentication(String authReqXml, TVUrl authUrl) {
        String encryptedPayload = encryptContent(authReqXml, 0); // vendor crypto, throws if key missing
        String soap = SOAP_ENVELOPE_PREFIX + encryptedPayload + SOAP_ENVELOPE_SUFFIX;

        HttpResponse<String> response;
        try {
            response = HTTP.send(buildRequest(authUrl.getFullUrl(), soap), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException e) {
            LOG.errorf(e, "SAS TokenValidator %s not reachable", authUrl.getBaseUrl());
            throw new TokenValidatorWrapperException("Could not connect to Token Validator " + authUrl.getBaseUrl());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TokenValidatorWrapperException("Interrupted while calling Token Validator");
        } catch (IllegalArgumentException e) {
            throw new TokenValidatorWrapperException("Invalid Token Validator URL: " + authUrl.getFullUrl());
        }

        int status = response.statusCode();
        if (status != 200) {
            LOG.errorf("SAS TokenValidator %s answered HTTP %d", authUrl.getBaseUrl(), status);
            throw new TokenValidatorWrapperException("Token Validator returned HTTP " + status);
        }

        String encryptedResult = extractResult(response.body());
        return doDecryptionAfterAutheticate(encryptedResult); // vendor crypto + unmarshalling
    }

    static HttpRequest buildRequest(String url, String soapBody) {
        return HttpRequest.newBuilder(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .header("Content-Type", "application/soap+xml; charset=UTF-8")
                .header("Accept", "text/xml")
                .header("SOAPAction", SOAP_ACTION_AUTHENTICATE)
                .header("AgentInfo", AGENT_INFO)
                .POST(HttpRequest.BodyPublishers.ofString(soapBody, StandardCharsets.UTF_8))
                .build();
    }

    /** Same contract as the vendor's private validateRespAndExtractEncryptedContent. */
    static String extractResult(String body) {
        if (body == null) {
            throw new TokenValidatorWrapperException("Authentication Service returned NO DATA");
        }
        int start = body.indexOf(RESULT_START);
        int end = start < 0 ? -1 : body.indexOf(RESULT_END, start + RESULT_START.length());
        if (start < 0 || end < 0) {
            throw new TokenValidatorWrapperException("Authentication Service returned NO DATA");
        }
        String content = body.substring(start + RESULT_START.length(), end);
        if (content.isEmpty()) {
            throw new TokenValidatorWrapperException("Authentication Service returned NO DATA");
        }
        return content;
    }
}
