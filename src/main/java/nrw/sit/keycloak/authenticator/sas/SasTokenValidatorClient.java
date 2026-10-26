package nrw.sit.keycloak.authenticator.sas;

import com.safenet.keycloak.agent.tokenvalidatoradapter.dto.tv.TVRequestCredentialType;
import com.safenet.keycloak.agent.tokenvalidatoradapter.dto.tv.TVRequestType;
import com.safenet.keycloak.agent.tokenvalidatoradapter.dto.tv.TokenValidatorRequestDTO;
import com.safenet.keycloak.agent.tokenvalidatoradapter.dto.tv.TokenValidatorResponseDTO;
import com.safenet.keycloak.agent.tokenvalidatoradapter.dto.tv.TokenValidatorReturn;
import com.safenet.keycloak.agent.tokenvalidatoradapter.tvadapter.TokenValidatorWrapper;
import org.jboss.logging.Logger;

/**
 * Thin wrapper around the Thales TokenValidator library
 * ({@code token-validator-adapter-jar-with-dependencies.jar} + {@code commons.jar} from the
 * SafeNet Agent for Keycloak 1.5.0).
 *
 * <p>This class and {@link SitTokenValidatorWrapper} are the ONLY classes in this module that
 * reference Thales types. The authenticator
 * and factory never mention them, so the JVM links this class lazily on the first OTP
 * validation. If the Thales JARs are missing, that surfaces as a {@link NoClassDefFoundError}
 * at that point (handled in {@link SasOtpFormAuthenticator}) instead of breaking server start.
 *
 * <p>Request construction mirrors {@code SASIDPServiceFacadeImpl.validateToken} of the
 * original agent (request type {@code verifycredentials}, credential type
 * {@code TokenValidation}), reduced to what a plain OTP validation needs. The organization
 * identifier the original agent sets on the DTO is never copied into the request XML by
 * {@code TokenValidatorWrapperImpl}; the SAS virtual server is determined by the agent key file.
 */
final class SasTokenValidatorClient {

    private static final Logger LOG = Logger.getLogger(SasTokenValidatorClient.class);

    /** Outcome of a TokenValidator call, decoupled from Thales types. */
    enum Result {
        /** OTP accepted by SAS. */
        ACCEPTED,
        /** OTP rejected by SAS (wrong / reused / user has no token / user unknown). */
        REJECTED,
        /** SAS answered with a challenge or an action this authenticator does not implement
         *  (GrIDsure, server-provided PIN, PIN change, push dispatch, outer window resync ...). */
        UNSUPPORTED,
        /** No usable answer from SAS (network, agent key file, malformed response). */
        ERROR
    }

    private final TokenValidatorWrapper wrapper;

    /**
     * @param tokenValidatorUrl full TokenValidator endpoint,
     *                          e.g. {@code https://sas.example/TokenValidator/TokenValidator.asmx}
     * @param agentKeyFilePath  path of the {@code .bsidkey} agent key file inside the container,
     *                          or its Base64 content (the library accepts both: if the value is not
     *                          a valid path it is parsed as Base64)
     */
    SasTokenValidatorClient(String tokenValidatorUrl, String agentKeyFilePath) {
        this(new SitTokenValidatorWrapper(tokenValidatorUrl, agentKeyFilePath));
    }

    /** For tests. */
    SasTokenValidatorClient(TokenValidatorWrapper wrapper) {
        this.wrapper = wrapper;
    }

    /**
     * Validates {@code otp} for {@code sasUserId}.
     *
     * @param sasUserId    user id as known in SAS (username or mapped attribute)
     * @param otp          passcode entered by the user
     * @param clientIp     end-user IP for SAS auditing / IP policies; may be {@code null}
     * @param resourceName client name for SAS auditing; may be {@code null}
     */
    Result validate(String sasUserId, String otp, String clientIp, String resourceName) {
        TokenValidatorRequestDTO request = new TokenValidatorRequestDTO.TokenValidatorRequestBuilder()
                .username(sasUserId)
                .password(otp)
                .userIpAddress(clientIp)
                .resourceName(resourceName)
                .isAgentOtgEnabled(true)
                .tvRequestType(TVRequestType.verifycredentials)
                .tvRequestCredentialType(TVRequestCredentialType.TokenValidation)
                .build();

        TokenValidatorResponseDTO response;
        try {
            // The library logs and swallows TokenValidatorWrapperException and returns null;
            // key-file problems propagate as RuntimeException.
            response = wrapper.authenticate(request);
        } catch (RuntimeException e) {
            LOG.errorf(e, "SAS TokenValidator call failed for user '%s'", sasUserId);
            return Result.ERROR;
        }
        if (response == null || response.getReturnValue() == null) {
            LOG.errorf("SAS TokenValidator returned no usable response for user '%s'", sasUserId);
            return Result.ERROR;
        }

        TokenValidatorReturn code = TokenValidatorReturn.getEnum(response.getReturnValue());
        LOG.debugf("SAS TokenValidator: user='%s' return=%s challengeData='%s' message='%s'",
                sasUserId, code, response.getChallengedata(), response.getMessage());

        if (code == null) {
            return Result.ERROR;
        }
        switch (code) {
            case AUTH_SUCCESS:
                return Result.ACCEPTED;
            case AUTH_FAILURE:
            case IPADDRESS_OUTSIDE_RANGE_DENIED:
            case PUSH_OTP_REJECTED:
                return Result.REJECTED;
            default:
                // CHALLENGE, SERVER_PIN_PROVIDED, USER_PIN_CHANGE, OUTER_WINDOW_AUTH,
                // CHANGE_STATIC_PASSWORD, *_CHANGE_FAILED, PUSH_OTP_DISPATCH
                LOG.warnf("SAS TokenValidator requested unsupported action %s (challengeData='%s') for user '%s'",
                        code, response.getChallengedata(), sasUserId);
                return Result.UNSUPPORTED;
        }
    }
}
