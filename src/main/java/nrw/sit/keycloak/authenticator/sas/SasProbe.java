package nrw.sit.keycloak.authenticator.sas;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Round-trip check against a real SAS PCE, without Keycloak in the loop: same wrapper, same
 * crypto, same proxy selection as the authenticator. Meant as a dry run on the production
 * system before (or after) switching the browser flow.
 *
 * <pre>
 * # inside the Keycloak container (image variant -safenet ships the wrapper script):
 * /opt/keycloak/bin/sas-probe.sh &lt;tokenValidatorUrl&gt; &lt;agentKeyFile&gt; &lt;sasUserId&gt; &lt;otp&gt; [clientIp]
 * </pre>
 *
 * Exit code 0 = ACCEPTED, 1 = REJECTED, 2 = UNSUPPORTED, 3 = ERROR, 64 = usage.
 *
 * <p>Keycloak puts the certificates from {@code --truststore-paths} into the JVM default
 * trust store; a separate JVM does not get that. So the probe reads {@code KC_TRUSTSTORE_PATHS}
 * (PEM files or directories of PEM files, as in the container environment) and trusts those
 * certificates in addition to the JDK's own CAs. Proxy: {@code HTTPS_PROXY}/{@code NO_PROXY}
 * from the environment, like the authenticator.
 */
public final class SasProbe {

    private SasProbe() {
    }

    /** Keycloak registers BouncyCastle itself; standalone we have to (vendor AES-GCM uses BC's AEADParameterSpec). */
    private static void registerBouncyCastle() {
        try {
            Class<?> bc = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            java.security.Security.addProvider((java.security.Provider) bc.getDeclaredConstructor().newInstance());
        } catch (ReflectiveOperationException e) {
            System.err.println("BouncyCastle not on classpath – add /opt/keycloak/lib/lib/main/*");
            System.exit(3);
        }
    }

    /**
     * Trust the JDK CAs plus every certificate from {@code paths} (comma-separated files or
     * directories, PEM/DER). Must run before {@link SitTokenValidatorWrapper} is loaded, its
     * HTTP client picks up the default SSLContext once.
     */
    static int installTruststore(String paths) throws IOException, GeneralSecurityException {
        if (paths == null || paths.isBlank()) {
            return 0;
        }
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);

        TrustManagerFactory jdk = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        jdk.init((KeyStore) null);
        int n = 0;
        for (var tm : jdk.getTrustManagers()) {
            if (tm instanceof javax.net.ssl.X509TrustManager x) {
                for (var ca : x.getAcceptedIssuers()) {
                    ks.setCertificateEntry("jdk-" + n++, ca);
                }
            }
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        int added = 0;
        for (String entry : paths.split(",")) {
            Path p = Path.of(entry.trim());
            List<Path> files = new ArrayList<>();
            if (Files.isDirectory(p)) {
                try (Stream<Path> s = Files.list(p)) {
                    s.filter(Files::isRegularFile).forEach(files::add);
                }
            } else if (Files.isRegularFile(p)) {
                files.add(p);
            } else {
                System.err.println("truststore: " + p + " not found, skipped");
            }
            for (Path f : files) {
                try (InputStream in = Files.newInputStream(f)) {
                    for (Certificate c : cf.generateCertificates(in)) {
                        ks.setCertificateEntry("kc-" + added++, c);
                    }
                } catch (java.security.cert.CertificateException e) {
                    System.err.println("truststore: " + f + " is not a PEM/DER certificate file, skipped");
                }
            }
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        SSLContext.setDefault(ctx);
        return added;
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.err.println("usage: SasProbe <tokenValidatorUrl> <agentKeyFilePathOrContent> <sasUserId> <otp> [clientIp]");
            System.exit(64);
        }
        registerBouncyCastle();
        String tsPaths = System.getenv("KC_TRUSTSTORE_PATHS");
        int certs = installTruststore(tsPaths);
        if (certs > 0) {
            System.out.printf("truststore: JDK CAs + %d certificate(s) from KC_TRUSTSTORE_PATHS%n", certs);
        }
        EnvProxySelector proxy = EnvProxySelector.fromEnvironment();
        System.out.println("proxy: " + proxy + " -> " + proxy.select(java.net.URI.create(args[0])));

        String clientIp = args.length > 4 ? args[4] : null;
        SasTokenValidatorClient client = new SasTokenValidatorClient(args[0], args[1]);
        long t0 = System.nanoTime();
        SasTokenValidatorClient.Result result = client.validate(args[2], args[3], clientIp, "SasProbe");
        long ms = (System.nanoTime() - t0) / 1_000_000;
        System.out.printf("%s (%d ms)%n", result, ms);
        System.exit(result.ordinal());
    }
}
