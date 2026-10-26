package nrw.sit.keycloak.authenticator.sas;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

/**
 * Factory for {@link SasOtpFormAuthenticator}.
 *
 * <p>Configuration is per execution; keys and labels are identical to the original SafeNet
 * Authentication Form ({@code agent.bsidkey}, {@code tokenvalidator.url}, {@code user.id.mapper}),
 * so an existing execution config can be copied over. {@code otp.autotrigger.enabled} is not
 * offered: it only pre-triggers push/SMS/GrIDsure, which this authenticator does not support.
 */
public class SasOtpFormAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "sit-auth-otp-form-sas";

    public static final String CFG_TV_URL = "tokenvalidator.url";
    public static final String CFG_KEY_FILE = "agent.bsidkey";
    public static final String CFG_USER_ATTRIBUTE = "user.id.mapper";

    private static final Requirement[] REQUIREMENT_CHOICES = {
            Requirement.REQUIRED,
            Requirement.ALTERNATIVE,
            Requirement.DISABLED,
    };

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
            .property()
                .name(CFG_KEY_FILE)
                .label("Agent BSID Key")
                .helpText("Path or content of SAS encryption file required for remote authentication agents. "
                        + "Path inside the container (e.g. /opt/keycloak/conf/agent.bsidkey, mounted as secret) "
                        + "or the Base64 content of the file.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .required(true)
                .add()
            .property()
                .name(CFG_TV_URL)
                .label("Token Validator URL")
                .helpText("Token Validator URL, e.g. https://sas.example.org/TokenValidator/TokenValidator.asmx")
                .type(ProviderConfigProperty.STRING_TYPE)
                .required(true)
                .add()
            .property()
                .name(CFG_USER_ATTRIBUTE)
                .label("User Id Mapper")
                .helpText("User attribute whose first value is sent to SAS as user id. "
                        + "Leave empty to send the Keycloak username.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
            .build();

    @Override
    public Authenticator create(KeycloakSession session) {
        return SasOtpFormAuthenticator.SINGLETON;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        // Same category as the OTP form, so it counts as "otp" for ACR/LoA and step-up
        // handling. Note: "Condition - user configured" / "Condition - credential" look at
        // Keycloak credentials, which SAS users do not have – do not combine with those.
        return OTPCredentialModel.TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "SIT: OTP Form (SAS PCE / Thales)";
    }

    @Override
    public String getHelpText() {
        return "Standard OTP form (login-otp.ftl) whose passcode is validated by Thales SafeNet "
                + "Authentication Service (SAS PCE) via the TokenValidator library. "
                + "Requires the SafeNet Agent JARs in providers/. No self-setup.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public void init(Config.Scope config) {
        // No global configuration.
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Nothing to do.
    }

    @Override
    public void close() {
        // Nothing to close.
    }
}
