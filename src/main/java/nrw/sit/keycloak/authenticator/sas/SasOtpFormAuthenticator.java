package nrw.sit.keycloak.authenticator.sas;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;

import java.util.Map;

/**
 * OTP form whose passcode is validated by Thales SafeNet Authentication Service (SAS PCE)
 * instead of a Keycloak OTP credential.
 *
 * <ul>
 *   <li>Renders Keycloak's standard {@code login-otp.ftl} (field name {@code otp}), so any
 *       theme based on {@code keycloak.v2} works unchanged – no Thales theme required.</li>
 *   <li>Never offers self-enrolment: the user has no Keycloak credential to set up, tokens are
 *       managed in SAS.</li>
 *   <li>Only plain passcode validation is implemented. Challenge/PIN-change/push flows that
 *       SAS may request are rejected with a clear error (see
 *       {@link SasTokenValidatorClient.Result#UNSUPPORTED}).</li>
 * </ul>
 */
public class SasOtpFormAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(SasOtpFormAuthenticator.class);

    public static final SasOtpFormAuthenticator SINGLETON = new SasOtpFormAuthenticator();

    /** Name of the OTP input in login-otp.ftl. */
    static final String FORM_PARAM_OTP = "otp";
    /** Field id used by login-otp.ftl for error highlighting. */
    static final String FIELD_TOTP = "totp";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (!isConfigured(context.getAuthenticatorConfig())) {
            LOG.errorf("Execution %s is not configured (TokenValidator URL / agent key file missing)",
                    context.getExecution().getId());
            context.failure(AuthenticationFlowError.INTERNAL_ERROR,
                    context.form().setError("sasOtpNotConfigured").createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
            return;
        }
        context.challenge(challenge(context, null, null));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        String otp = form.getFirst(FORM_PARAM_OTP);
        UserModel user = context.getUser();

        if (user == null) {
            context.failure(AuthenticationFlowError.UNKNOWN_USER);
            return;
        }
        if (!user.isEnabled()) {
            context.getEvent().user(user).error(Errors.USER_DISABLED);
            context.failure(AuthenticationFlowError.USER_DISABLED);
            return;
        }
        if (otp == null || otp.isBlank()) {
            context.challenge(challenge(context, Messages.MISSING_TOTP, FIELD_TOTP));
            return;
        }

        Map<String, String> cfg = context.getAuthenticatorConfig().getConfig();
        String sasUserId = resolveSasUserId(user, cfg.get(SasOtpFormAuthenticatorFactory.CFG_USER_ATTRIBUTE));
        if (sasUserId == null || sasUserId.isBlank()) {
            LOG.warnf("User %s has no value for SAS user id attribute '%s'",
                    user.getUsername(), cfg.get(SasOtpFormAuthenticatorFactory.CFG_USER_ATTRIBUTE));
            context.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    challenge(context, Messages.INVALID_TOTP, FIELD_TOTP));
            return;
        }

        String clientIp = context.getConnection() != null ? context.getConnection().getRemoteAddr() : null;
        String resourceName = context.getAuthenticationSession().getClient() != null
                ? context.getAuthenticationSession().getClient().getClientId() : null;

        SasTokenValidatorClient.Result result;
        try {
            SasTokenValidatorClient client = new SasTokenValidatorClient(
                    cfg.get(SasOtpFormAuthenticatorFactory.CFG_TV_URL).trim(),
                    cfg.get(SasOtpFormAuthenticatorFactory.CFG_KEY_FILE).trim());
            result = client.validate(sasUserId, otp.trim(), clientIp, resourceName);
        } catch (NoClassDefFoundError e) {
            // Thales JARs not deployed in this image
            LOG.error("SafeNet TokenValidator library not available in providers/ – cannot validate OTP", e);
            result = SasTokenValidatorClient.Result.ERROR;
        }

        switch (result) {
            case ACCEPTED:
                context.success("otp");
                return;
            case REJECTED:
                context.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                        challenge(context, Messages.INVALID_TOTP, FIELD_TOTP));
                return;
            case UNSUPPORTED:
                context.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                        challenge(context, "sasOtpUnsupportedResponse", FIELD_TOTP));
                return;
            case ERROR:
            default:
                context.getEvent().user(user).error(Errors.INVALID_REQUEST);
                context.failure(AuthenticationFlowError.INTERNAL_ERROR,
                        context.form().setError("sasOtpUnavailable").createErrorPage(Response.Status.SERVICE_UNAVAILABLE));
        }
    }

    private static Response challenge(AuthenticationFlowContext context, String error, String field) {
        LoginFormsProvider form = context.form()
                .setExecution(context.getExecution().getId());
        if (error != null) {
            if (field != null) {
                form.addError(new FormMessage(field, error));
            } else {
                form.setError(error);
            }
        }
        return form.createLoginTotp();
    }

    private static String resolveSasUserId(UserModel user, String attribute) {
        if (attribute == null || attribute.isBlank()) {
            return user.getUsername();
        }
        return user.getFirstAttribute(attribute.trim());
    }

    static boolean isConfigured(AuthenticatorConfigModel config) {
        if (config == null || config.getConfig() == null) {
            return false;
        }
        String url = config.getConfig().get(SasOtpFormAuthenticatorFactory.CFG_TV_URL);
        String key = config.getConfig().get(SasOtpFormAuthenticatorFactory.CFG_KEY_FILE);
        return url != null && !url.isBlank() && key != null && !key.isBlank();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // Whether the user owns a token is only known to SAS. Treat every user as configured and
        // let SAS decide; combine with a role/attribute condition in the flow if only part of the
        // users should go through SAS.
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No self-enrolment: tokens are provisioned in SAS.
    }

    @Override
    public void close() {
        // Nothing to close.
    }
}
