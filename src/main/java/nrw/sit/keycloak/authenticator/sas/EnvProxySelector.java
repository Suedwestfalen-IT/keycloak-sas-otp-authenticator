package nrw.sit.keycloak.authenticator.sas;

import org.jboss.logging.Logger;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * {@link ProxySelector} that honours the environment variables {@code HTTPS_PROXY},
 * {@code HTTP_PROXY} and {@code NO_PROXY} (upper- or lower-case), like Keycloak's own
 * HttpClientProvider does. The JDK default selector only reads JVM system properties, so
 * without this the SAS call would ignore the proxy configured for the container.
 *
 * <p>Proxy values may be {@code host:port} or {@code http://host:port}. Credentials in the URL
 * are not supported (the JDK disables Basic auth for CONNECT tunnels by default anyway).
 * {@code NO_PROXY} is a comma-separated list of hosts; an entry matches the target host exactly,
 * as a domain suffix ({@code .example.org} or {@code example.org} matches {@code a.example.org}),
 * or everything with {@code *}.
 */
final class EnvProxySelector extends ProxySelector {

    private static final Logger LOG = Logger.getLogger(EnvProxySelector.class);
    private static final List<Proxy> DIRECT = List.of(Proxy.NO_PROXY);

    private final Proxy httpsProxy;
    private final Proxy httpProxy;
    private final List<String> noProxy;

    static EnvProxySelector fromEnvironment() {
        return new EnvProxySelector(System.getenv());
    }

    EnvProxySelector(Map<String, String> env) {
        this.httpsProxy = parseProxy(get(env, "HTTPS_PROXY"));
        this.httpProxy = parseProxy(get(env, "HTTP_PROXY"));
        this.noProxy = parseNoProxy(get(env, "NO_PROXY"));
        if (httpsProxy != null || httpProxy != null) {
            LOG.infof("SAS TokenValidator proxy from environment: https=%s http=%s no_proxy=%s",
                    describe(httpsProxy), describe(httpProxy), noProxy);
        }
    }

    boolean hasProxy() {
        return httpsProxy != null || httpProxy != null;
    }

    @Override
    public List<Proxy> select(URI uri) {
        if (uri == null || uri.getHost() == null) {
            return DIRECT;
        }
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        if (isNoProxy(host)) {
            return DIRECT;
        }
        Proxy p = "https".equalsIgnoreCase(uri.getScheme()) ? httpsProxy : httpProxy;
        if (p == null) {
            p = httpsProxy != null ? httpsProxy : httpProxy; // fall back to whichever is set
        }
        return p == null ? DIRECT : List.of(p);
    }

    @Override
    public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
        LOG.warnf("Proxy %s failed for %s: %s", sa, uri, ioe.getMessage());
    }

    boolean isNoProxy(String host) {
        for (String entry : noProxy) {
            if (entry.equals("*") || entry.equals(host) || host.endsWith("." + entry)) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------ parsing

    private static String get(Map<String, String> env, String key) {
        String v = env.get(key);
        if (v == null || v.isBlank()) {
            v = env.get(key.toLowerCase(Locale.ROOT));
        }
        return v == null || v.isBlank() ? null : v.trim();
    }

    static Proxy parseProxy(String value) {
        if (value == null) {
            return null;
        }
        try {
            String v = value.contains("://") ? value : "http://" + value;
            URI u = URI.create(v);
            if (u.getHost() == null) {
                throw new IllegalArgumentException("no host");
            }
            int port = u.getPort() > 0 ? u.getPort() : ("https".equalsIgnoreCase(u.getScheme()) ? 443 : 80);
            return new Proxy(Proxy.Type.HTTP, InetSocketAddress.createUnresolved(u.getHost(), port));
        } catch (IllegalArgumentException e) {
            LOG.warnf("Ignoring invalid proxy setting '%s': %s", value, e.getMessage());
            return null;
        }
    }

    static List<String> parseNoProxy(String value) {
        if (value == null) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (String raw : value.split("[,\\s]+")) {
            String e = raw.trim().toLowerCase(Locale.ROOT);
            if (e.isEmpty()) {
                continue;
            }
            if (e.startsWith("*.")) {
                e = e.substring(2);
            } else if (e.startsWith(".")) {
                e = e.substring(1);
            }
            int colon = e.indexOf(':');
            if (colon > 0) {
                e = e.substring(0, colon); // strip port
            }
            out.add(e);
        }
        return List.copyOf(out);
    }

    private static String describe(Proxy p) {
        return p == null ? "-" : String.valueOf(p.address());
    }

    @Override
    public String toString() {
        return "EnvProxySelector{https=" + describe(httpsProxy) + ", http=" + describe(httpProxy)
                + ", noProxy=" + Arrays.toString(noProxy.toArray()) + '}';
    }
}
