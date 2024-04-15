package com.vunet.keycloak.auth.otp;

import static org.keycloak.services.validation.Validation.FIELD_OTP_CODE;
import static org.keycloak.services.validation.Validation.FIELD_USERNAME;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.UndeclaredThrowableException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Date;
import java.util.Locale;
import java.util.Properties;
import java.util.Random;
import java.util.ResourceBundle;
import java.util.Timer;
import java.util.TimerTask;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.jboss.logging.Logger;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.json.JSONArray;
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
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.quartz.CronTrigger;
import org.quartz.JobDetail;
import org.quartz.impl.StdSchedulerFactory;

import com.google.common.util.concurrent.AbstractScheduledService.Scheduler;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import okhttp3.FormBody;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;

@JBossLog
public class OtpAuthenticatorForm extends AbstractUsernameFormAuthenticator
		implements Authenticator, CredentialValidator<OTPCredentialProvider> {

	private static final Logger logger = Logger.getLogger(OtpAuthenticatorForm.class);

	protected static final String USER_SET_BEFORE_USERNAME_PASSWORD_AUTH = "USER_SET_BEFORE_USERNAME_PASSWORD_AUTH";

	public static final String SELECTED_OTP_CREDENTIAL_ID = "selectedOtpCredentialId";

	static final String ID = "otp-form";

	public static final String OTP = "totp";
	public static final String STATUS = "Status";
	public static final String USER_REGISTERED = "UserRegistered";
	public static final String RESPONSE_CODE = "ResponseCode";
	public static final String TOKEN_PROP = "otp.auth.token";
	public static final String SEND_OTP_URL_PROP = "otp.send.url";
	public static final String VALIDATE_OTP_URL_PROP = "otp.validate.url";
	public static final String PROP_FILE_PATH = "/opt/bitnami/keycloak/icici.properties";
	public static final String UNAME = "uname";
	public static final String UOTP = "uotp";
	public static final String TOKEN = "token";
	public static final String APPLICATION_ID = "application.id";
	public static final String APPLICATION_SECRET = "application.secrect";
	private String hasedApplicationSecret;

	private final KeycloakSession session;
    
	public OtpAuthenticatorForm(KeycloakSession session) {
		this.session = session;
	}

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		logger.info("Otp Authenticator Form page");
		MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
		String loginHint = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);

		String rememberMeUsername = AuthenticationManager.getRememberMeUsername(context.getRealm(),
				context.getHttpRequest().getHttpHeaders());

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

		if (formData.size() > 0)
			forms.setFormData(formData);

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

		if (formData.containsKey("generateOTP")) {
			logger.info("request for generating otp");
			boolean valid = generateOTPWithICICI(context, formData);
		}

		if (!validateForm(context, formData)) {
			return;
		}

		context.success();
	}

	protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
		logger.info("validating credentials " + formData.toString());
		boolean result = validateUserAndPassword(context, formData);
		if (result) {
			result = validateOTP(context, formData);
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
		boolean valid = validateWithICICI(context, inputData);
		if (!valid) {
			context.resetFlow();
		}

		return valid;
	}

	private boolean generateOTPWithICICI(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
		try {
			FileInputStream fis = new FileInputStream(PROP_FILE_PATH);

			Properties prop = new Properties();
			prop.load(fis);
			logger.info(prop.getProperty("Url from property file " + SEND_OTP_URL_PROP));

			String username = inputData.getFirst(AuthenticationManager.FORM_USERNAME);

			OkHttpClient httpClient = new OkHttpClient();
			final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
			
			final String notificationMessageBody = "Dear Customer, <OTP> is the OTP to LOGIN to ICICI Bank icici. OTPs are SECRET. DO NOT disclose it to anyone. Bank NEVER asks for OTP.";
			
			JSONObject jsonBody = new JSONObject();
			
			JSONArray searchAttributeArray = new JSONArray();
			JSONObject searchAttributeItem = new JSONObject();
			searchAttributeItem.put("attributeName", username);
			searchAttributeItem.put("attributeValue", username);
			searchAttributeArray.put(searchAttributeItem);
			
			jsonBody.put("searchAttributes", searchAttributeArray);
			
			JSONArray notificationArray = new JSONArray();
			JSONObject notificationEmailItem = new JSONObject();
			notificationEmailItem.put("notificationType", "EMAIL");
			notificationEmailItem.put("messageBody", notificationMessageBody);
			notificationEmailItem.put("templateId", "TMPT1001");
			notificationArray.put(notificationEmailItem);
			
			JSONObject notificationSMSItem = new JSONObject();
			notificationSMSItem.put("notificationType", "SMS");
			notificationSMSItem.put("messageBody", notificationMessageBody);
			notificationSMSItem.put("templateId", "TMPT1001");
			notificationArray.put(notificationSMSItem);
			
			jsonBody.put("notification", notificationArray);
			
			jsonBody.put("password", encryptPassword(context, inputData));
			
			String jsonString = jsonBody.toString();

			RequestBody body = RequestBody.create(jsonString, JSON);
			

			Request request = new Request.Builder().url(prop.getProperty(SEND_OTP_URL_PROP))
					.addHeader("Application-Id", prop.getProperty(APPLICATION_ID))
					.addHeader("Application-Secret", hasedApplicationSecret).addHeader("Services", "APPROVAL")
					.addHeader("Content-Type", "application/json").post(body).build();

			okhttp3.Response response = httpClient.newCall(request).execute();
			JSONObject jsonObject = new JSONObject(response.toString());
			int responseCode = jsonObject.getInt(RESPONSE_CODE);

			if (responseCode == 200) {
				boolean status = jsonObject.getBoolean(STATUS);
				if (status) {
					return true;
				} else if (!status ) {
					context.getEvent().error(Errors.INVALID_CODE);
					Response challengeResponse = challenge(context, Messages.INVALID_TOTP);
					context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
					return false;
				}
			} else if (responseCode == 401) {
				String status = jsonObject.getString(STATUS);
				if (status.equalsIgnoreCase("InvalidToken")) {
					context.getEvent().error(Errors.INVALID_TOKEN);
					Response challengeResponse = challenge(context, Messages.INTERNAL_SERVER_ERROR);
					context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challengeResponse);
					return false;
				}
			}

		} catch (IOException e) {
			logger.error("Exception in generating OTP ", e);
		}catch (Exception e) {
			logger.error("Exception in generating OTP ", e);
		}
		
		Response challengeResponse = challenge(context, Messages.INTERNAL_SERVER_ERROR);
		context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challengeResponse);
		return false;
	}

	private boolean validateWithICICI(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
		try {
			FileInputStream fis = new FileInputStream(PROP_FILE_PATH);

			Properties prop = new Properties();
			prop.load(fis);
			logger.info(prop.getProperty("Url from property file " + VALIDATE_OTP_URL_PROP));

			String username = inputData.getFirst(AuthenticationManager.FORM_USERNAME);

			OkHttpClient httpClient = new OkHttpClient();
			
			
            final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
			
			JSONObject jsonBody = new JSONObject();
			
			JSONArray searchAttributeArray = new JSONArray();
			JSONObject searchAttributeItem = new JSONObject();
			searchAttributeItem.put("attributeName", username);
			searchAttributeItem.put("attributeValue", username);
			searchAttributeArray.put(searchAttributeItem);
			
			jsonBody.put("searchAttributes", searchAttributeArray);
			
			jsonBody.put("authenticationToken", inputData.getFirst(OTP));
			
			String jsonString = jsonBody.toString();

			RequestBody body = RequestBody.create(jsonString, JSON);

			Request request = new Request.Builder().url(prop.getProperty(VALIDATE_OTP_URL_PROP))
					.addHeader("Application-Id", prop.getProperty(APPLICATION_ID))
					.addHeader("Application-Secret", hasedApplicationSecret)
					.addHeader("Content-Type", "application/json").post(body)
					.build();

			okhttp3.Response response = httpClient.newCall(request).execute();
			JSONObject jsonObject = new JSONObject(response.toString());
			int responseCode = jsonObject.getInt(RESPONSE_CODE);

			if (responseCode == 200) {
				boolean status = jsonObject.getBoolean(STATUS);
				JSONArray notificationArray = jsonObject.getJSONArray("notification");
				JSONObject emailNotification = (JSONObject) notificationArray.get(0);
				JSONObject smsNotification = (JSONObject) notificationArray.get(0);
				
				if ( emailNotification.get("status").equals("SUCCESS") && smsNotification.get("status").equals("SUCCESS")){
					logger.info("OTP validated");
					return true;
				} else if (emailNotification.get("status").equals("SUCCESS") && smsNotification.get("status").equals("FAILED")) {
					logger.error("sms notification failed:"+ smsNotification.get("errorMessage"));
					context.getEvent().error(Errors.INVALID_CODE);
					Response challengeResponse = challenge(context, Messages.INVALID_TOTP);
					context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
					return false;
				} else if (emailNotification.get("status").equals("FAILED") && smsNotification.get("status").equals("SUCCESS")) {
					logger.error("email notification failed:"+ emailNotification.get("errorMessage"));
					context.getEvent().error(Errors.INVALID_CODE);
					Response challengeResponse = challenge(context, Messages.INVALID_TOTP);
					context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
					return false;
				}
			} else if (responseCode == 401) {
					context.getEvent().error(Errors.INVALID_TOKEN);
					Response challengeResponse = challenge(context, Messages.INTERNAL_SERVER_ERROR);
					context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challengeResponse);
					return false;
			}

		} catch (IOException e) {
			logger.error("Exception in validating OTP ", e);
		}
		Response challengeResponse = challenge(context, Messages.INTERNAL_SERVER_ERROR);
		context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challengeResponse);
		return false;
	}
	
	

	private void applicationSecretHashing() {
		// generate a 20 characters random string as salt
		Random random = new Random();
		char[] buf = new char[20];
		String upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		String lower = upper.toLowerCase(Locale.ROOT);
		String digits = "0123456789";

		// creating an alphanumeric string with all range of characters
		String alphanum = upper + lower + digits;

		// converting the alphanumeric string to individual characters
		char[] symbols = alphanum.toCharArray();

		// creating a 20 char buffer with randomly selected alphanumeric characters
		for (int idx = 0; idx < buf.length; ++idx)
			buf[idx] = symbols[random.nextInt(symbols.length)];

		// converting the character buffer into the random salt string
		String randomSalt = new String(buf);

		// combine the plain-text application secret with the random salt
		String applicationSecretePlainText = "f726502b312f06c7f79e466ead6e68206b359447aa5b3c1023a52b4a32e82688";
		applicationSecretePlainText = applicationSecretePlainText + randomSalt;

		// creating an instance of the SHA-256 hashing algorithm
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new UndeclaredThrowableException(e);
		}

		// using the SHA-256 algorithm to encrypt the salt + plain-text app secret
		// encoding the generated hash value
		String generatedHash = Base64.getEncoder()
				.encodeToString(messageDigest.digest(applicationSecretePlainText.getBytes()));

		// adding the salt to the generated encoded hash
		String applicationSecret = randomSalt + generatedHash;
		hasedApplicationSecret = applicationSecret;
	}

	private String encryptPassword(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) throws FileNotFoundException, CertificateException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, GeneralSecurityException, BadPaddingException {
		String password = inputData.getFirst(CredentialRepresentation.PASSWORD);
		
		// need to mention public key file path
		String filePath = "/opt/bitnami/keycloak/iamadpuat.cer";
		FileInputStream fis = new FileInputStream(filePath);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		Certificate cert =  (Certificate) cf.generateCertificate(fis);
		PublicKey publicKey = cert.getPublicKey();

		// using RSA algorithm encrypt the password
		Cipher encryptCipher = Cipher.getInstance("RSA");
		encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] secretMessageBytes = password.getBytes(StandardCharsets.UTF_8);
		byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);
		
		// encode the encrypted password using Base64
		String encryptedPassword = Base64.getEncoder().encodeToString(encryptedMessageBytes);
		
		return encryptedPassword;
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
		return (OTPCredentialProvider) session.getProvider(CredentialProvider.class,
				OTPCredentialProviderFactory.PROVIDER_ID);
	}
}