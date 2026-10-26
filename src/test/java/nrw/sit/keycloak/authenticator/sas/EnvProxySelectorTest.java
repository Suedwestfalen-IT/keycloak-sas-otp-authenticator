package nrw.sit.keycloak.authenticator.sas;

import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EnvProxySelectorTest {

    private static final URI SAS = URI.create("https://otp.example.org/TokenValidator/TokenValidator.asmx?orgCode=X");

    @Test
    void noEnvMeansDirect() {
        EnvProxySelector s = new EnvProxySelector(Map.of());
        assertEquals(Proxy.NO_PROXY, s.select(SAS).get(0));
    }

    @Test
    void httpsProxyIsUsedForHttpsTargets() {
        EnvProxySelector s = new EnvProxySelector(Map.of("HTTPS_PROXY", "http://proxy.intra:3128"));
        Proxy p = s.select(SAS).get(0);
        assertEquals(Proxy.Type.HTTP, p.type());
        assertEquals(InetSocketAddress.createUnresolved("proxy.intra", 3128), p.address());
    }

    @Test
    void lowerCaseAndBareHostPortAreAccepted() {
        EnvProxySelector s = new EnvProxySelector(Map.of("https_proxy", "proxy.intra:8080"));
        assertEquals(InetSocketAddress.createUnresolved("proxy.intra", 8080), s.select(SAS).get(0).address());
    }

    @Test
    void httpProxyIsFallbackForHttps() {
        EnvProxySelector s = new EnvProxySelector(Map.of("HTTP_PROXY", "http://proxy.intra:3128"));
        assertEquals(InetSocketAddress.createUnresolved("proxy.intra", 3128), s.select(SAS).get(0).address());
    }

    @Test
    void noProxyMatchesExactSuffixAndWildcard() {
        Map<String, String> env = Map.of("HTTPS_PROXY", "proxy.intra:3128",
                "NO_PROXY", "localhost,127.0.0.1,.intra.kommunale.it,otp.example.org:443,*.mk.de");
        EnvProxySelector s = new EnvProxySelector(env);
        assertEquals(Proxy.NO_PROXY, s.select(SAS).get(0)); // exact (port stripped)
        assertEquals(Proxy.NO_PROXY, s.select(URI.create("https://kc.intra.kommunale.it/")).get(0)); // suffix
        assertEquals(Proxy.NO_PROXY, s.select(URI.create("https://otp.mk.de/")).get(0)); // *.suffix
        assertEquals(Proxy.NO_PROXY, s.select(URI.create("http://127.0.0.1:9999/")).get(0));
        assertTrue(s.select(URI.create("https://other.example.com/")).get(0) != Proxy.NO_PROXY);

        EnvProxySelector all = new EnvProxySelector(Map.of("HTTPS_PROXY", "proxy.intra:3128", "NO_PROXY", "*"));
        assertEquals(Proxy.NO_PROXY, all.select(SAS).get(0));
    }

    @Test
    void invalidProxyValueIsIgnored() {
        EnvProxySelector s = new EnvProxySelector(Map.of("HTTPS_PROXY", "::not a proxy::"));
        assertEquals(Proxy.NO_PROXY, s.select(SAS).get(0));
    }
}
