package com.vunet.keycloak.auth.otp;

import static org.keycloak.services.validation.Validation.FIELD_OTP_CODE;
import static org.keycloak.services.validation.Validation.FIELD_USERNAME;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.ResourceBundle;

import org.jboss.logging.Logger;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.json.JSONObject;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.credential.OTPCredentialProviderFactory;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;

@JBossLog
public class OtpAuthenticatorForm  extends AbstractUsernameFormAuthenticator implements Authenticator, CredentialValidator<OTPCredentialProvider> {
	
    private static final Logger logger = Logger.getLogger(OtpAuthenticatorForm.class);

    protected static final String USER_SET_BEFORE_USERNAME_PASSWORD_AUTH = "USER_SET_BEFORE_USERNAME_PASSWORD_AUTH";

    public static final String SELECTED_OTP_CREDENTIAL_ID = "selectedOtpCredentialId";


    static final String ID = "otp-form";

    public static final String OTP = "totp";
    public static final String STATUS = "Status";
    public static final String USER_REGISTERED = "UserRegistered";
    public static final String RESPONSE_CODE = "ResponseCode";
    public static final String TOKEN_PROP ="otp.auth.token";
    public static final String URL_PROP ="otp.auth.url";
    public static final String PROP_FILE_PATH="/opt/bitnami/keycloak/npci.properties";
    public static final String UNAME="uname";
    public static final String UOTP="uotp";
    public static final String TOKEN="token";

    private final KeycloakSession session;

    public OtpAuthenticatorForm(KeycloakSession session) {
        this.session = session;
    }
    
    @Override
    public void authenticate(AuthenticationFlowContext context) {
    	logger.info("Otp Authenticator Form page");
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        String loginHint = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);

        String rememberMeUsername = AuthenticationManager.getRememberMeUsername(context.getRealm(), context.getHttpRequest().getHttpHeaders());

        if (context.getUser() != null) {
            LoginFormsProvider form = context.form();
            form.setAttribute(LoginFormsProvider.USERNAME_HIDDEN, true);
            form.setAttribute(LoginFormsProvider.REGISTRATION_DISABLED, true);
            context.getAuthenticationSession().setAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH, "true");
        } else {
            context.getAuthenticationSession().removeAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH);
            if (loginHint != null || rememberMeUsername != null) {
                if (loginHint != null) {
                    formData.add(AuthenticationManager.FORM_USERNAME, loginHint);
                } else {
                    formData.add(AuthenticationManager.FORM_USERNAME, rememberMeUsername);
                    formData.add("rememberMe", "on");
                }
            }
        }
        Response challengeResponse = lchallenge(context, formData);
        context.challenge(challengeResponse);
    }

    protected Response lchallenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();

        if (formData.size() > 0) forms.setFormData(formData);

        return forms.createLoginUsernamePassword();
    }


    @Override
    public void action(AuthenticationFlowContext context) {
    	logger.info("User action made");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
        	logger.info("canceling login");
            context.cancelLogin();
            return;
        }
        if (!validateForm(context, formData)) {
            return;
        }
        context.success();
    }
    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
    	logger.info("validating credentials "+formData.toString());
    	boolean result = validateUserAndPassword(context, formData);
        if(result) {
        	result= validateOTP(context,formData);
        }
        return result;

    }
        
    public boolean validateOTP(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {

    	logger.info("validating otp");
        String otp = inputData.getFirst(OTP);

        UserModel userModel = context.getUser();
        if (!enabledUser(context, userModel)) {
            return false;
        }

        if (otp.isBlank()) {
        	logger.info("otp is empty");
        	 Response challengeResponse = challenge(context, Messages.MISSING_TOTP);
             context.forceChallenge(challengeResponse);
            return false;
        }
        boolean valid = mockvalidateWithNPCI(context, inputData);
        if(!valid) {
        	context.resetFlow();
        }
        
		return valid;
    }
    
    private boolean mockvalidateWithNPCI(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
	    try {
	    	logger.info("mock");

	        String username = inputData.getFirst(AuthenticationManager.FORM_USERNAME);
	        String otp = inputData.getFirst(OTP);
	        if(otp.equals("11")){
	        	return true;
	        } else if(otp.equals("22")) {
	        	context.getEvent().error(Errors.INVALID_CODE);
	            Response challengeResponse = challenge(context, Messages.INVALID_TOTP);
	            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
	            return false;
	        } else if(otp.equals("33")) {
	        	context.getEvent().error(Errors.USER_NOT_FOUND);
	            Response challengeResponse = challenge(context, "User not registered");
	            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
	            return false;
	        } else if(otp.equals("44")) {
	        	context.getEvent().error(Errors.INVALID_TOKEN);
	            Response challengeResponse = challenge(context,Messages.INTERNAL_SERVER_ERROR);
	            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challengeResponse);
	            return false;
	        }
			
		} catch (Exception e) {
			logger.error("Exception in validating OTP ",e);
		}
	    Response challengeResponse = challenge(context,Messages.INTERNAL_SERVER_ERROR);
        context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challengeResponse);
		return false;
	}


    private boolean validateWithNPCI(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
	    try {
	    	FileInputStream fis = new FileInputStream(PROP_FILE_PATH);

            Properties prop = new Properties();
            prop.load(fis);
            logger.info(prop.getProperty("Url from property file "+ URL_PROP));

	        String username = inputData.getFirst(AuthenticationManager.FORM_USERNAME);
	        String otp = inputData.getFirst(OTP);
	
	        OkHttpClient httpClient = new OkHttpClient();
	
	    	RequestBody formBody = new FormBody.Builder()
	    		      .add(UNAME, username)
	    		      .add(UOTP, otp)
	    		      .add(TOKEN, prop.getProperty(TOKEN_PROP))
	    		      .build();
	
		    Request request = new Request.Builder()
		      .url(prop.getProperty(URL_PROP))
		      .addHeader("Content-Type", "application/json")
		      .addHeader("Cache-Control", "no-cache")
		      .post(formBody)
		      .build();


			okhttp3.Response response = httpClient.newCall(request).execute();
			JSONObject jsonObject = new JSONObject(response.toString());
			int responseCode = jsonObject.getInt(RESPONSE_CODE);
			
			if(responseCode==200) {
				boolean status = jsonObject.getBoolean(STATUS);
				boolean userRegistered = jsonObject.getBoolean(USER_REGISTERED);
				if(status&&userRegistered) {
					return true;
				}else if(!status&&userRegistered) {
					context.getEvent().error(Errors.INVALID_CODE);
		            Response challengeResponse = challenge(context, Messages.INVALID_TOTP);
		            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
		            return false;
				}else if(!status&&!userRegistered) {
					context.getEvent().error(Errors.USER_NOT_FOUND);
		            Response challengeResponse = challenge(context, "User not registered");
		            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
		            return false;
				}
			} else if(responseCode==401){
				String status = jsonObject.getString(STATUS);
				String userRegistered = jsonObject.getString(USER_REGISTERED);
				if(status.equalsIgnoreCase("InvalidToken")) {
					context.getEvent().error(Errors.INVALID_TOKEN);
		            Response challengeResponse = challenge(context,Messages.INTERNAL_SERVER_ERROR);
		            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challengeResponse);
		            return false;
				}
			}
			
		} catch (IOException e) {
			logger.error("Exception in validating OTP ",e);
		}
	    Response challengeResponse = challenge(context,Messages.INTERNAL_SERVER_ERROR);
        context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challengeResponse);
		return false;
	}
    
    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // NOOP
    }

    @Override
    public void close() {
        // NOOP
    }
    
    @Override
    public OTPCredentialProvider getCredentialProvider(KeycloakSession session) {
        return (OTPCredentialProvider)session.getProvider(CredentialProvider.class, OTPCredentialProviderFactory.PROVIDER_ID);
    }
}
