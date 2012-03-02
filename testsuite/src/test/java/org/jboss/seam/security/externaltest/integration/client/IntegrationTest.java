package org.jboss.seam.security.externaltest.integration.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import junit.framework.Assert;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.client.utils.URIUtils;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.solder.logging.Logger;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(Arquillian.class)
@RunAsClient
public class IntegrationTest {
    private static final Logger log = Logger.getLogger(IntegrationTest.class);

    private HttpClient httpClient;

    private HttpUriRequest request;

    private ResponseType responseType;

    private String responseBody;

    private HttpResponse response;

    enum ResponseType {
        SAML_MESSAGE_REDIRECT_BOUND, SAML_MESSAGE_POST_BOUND, APPLICATION_MESSAGE, ERROR
    }

    @Deployment(order = 1, name = "sp")
    public static Archive<?> createSpArchive()
    {
     return ArchiveBuilder.getArchive("sp");
    }
    
    @Deployment(order = 2, name = "idp")
    public static Archive<?> createIdpArchive()
    {
     return ArchiveBuilder.getArchive("idp");
    }
    
    @Deployment(order = 3, name = "rp")
    public static Archive<?> createRpArchive()
    {
     return ArchiveBuilder.getArchive("rp");
    }
    
    @Deployment(order = 4, name = "op")
    public static Archive<?> createOpArchive()
    {
     return ArchiveBuilder.getArchive("op");
    }    

    // Seems broken in ARQ Alpha5
    //@Before
    public void init() {
        httpClient = new DefaultHttpClient();
        httpClient.getParams().setParameter(ClientPNames.HANDLE_REDIRECTS, false);
    }

    @Test @OperateOnDeployment("sp")
    public void samlTest() {
        init();
        Map<String, String> params = new HashMap<String, String>();
        params.put("command", "loadMetaData");
        sendMessageToApplication("www.sp1.com", "sp", params);
        sendMessageToApplication("www.sp2.com", "sp", params);
        sendMessageToApplication("www.idp.com", "idp", params);

        // Login one user at each service provider application
        samlSignOn("www.sp1.com", "https://www.idp.com", "John Doe");
        samlSignOn("www.sp2.com", "https://www.idp.com", "Jane Doe");

        // Check that the IDP has two sessions (one for each user) and that each
        // SP has one
        checkNrOfSessions("www.idp.com", "idp", 2);
        checkNrOfSessions("www.sp1.com", "sp", 1);
        checkNrOfSessions("www.sp2.com", "sp", 1);

        // Do an IDP-initiated single logout of the user at SP1.
        params.clear();
        params.put("command", "singleLogout");
        sendMessageToApplication("www.idp.com", "idp", params);

        checkApplicationMessage("Single logout succeeded");

        checkNrOfSessions("www.idp.com", "idp", 1);
        checkNrOfSessions("www.sp1.com", "sp", 0);
        checkNrOfSessions("www.sp2.com", "sp", 1);

        // Do an SP-initiated single logout of the user at SP2.
        params.clear();
        params.put("command", "singleLogout");
        sendMessageToApplication("www.sp2.com", "sp", params);

        checkApplicationMessage("Single logout succeeded");

        // All sessions should be terminated by now.
        checkNrOfSessions("www.idp.com", "idp", 0);
        checkNrOfSessions("www.sp1.com", "sp", 0);
        checkNrOfSessions("www.sp2.com", "sp", 0);

        // All dialogues should be terminated by now.
        checkDialogueTermination("www.idp.com", "idp");
        checkDialogueTermination("www.sp1.com", "sp");
        checkDialogueTermination("www.sp2.com", "sp");
    }

    @Test @OperateOnDeployment("sp")
    public void openIdLoginWithOpIdentifierTest() {
        init();
        String opIdentifier = "http://localhost:8080/op/openid/OP/XrdsService";
        String userName = "john_doe";

        Map<String, String> params = new HashMap<String, String>();
        params.put("command", "login");
        params.put("identifier", opIdentifier);
        params.put("fetchEmail", "false");
        sendMessageToApplication("localhost", "rp", params);

        checkApplicationMessage("Please login.");

        params = new HashMap<String, String>();
        params.put("command", "authenticate");
        params.put("userName", userName);
        sendMessageToApplication("localhost", "op", params);

        checkApplicationMessage("Login succeeded (http://localhost:8080/op/users/" + userName + ")");

        // All dialogues should be terminated by now.
        checkDialogueTermination("www.op.com", "op");
        checkDialogueTermination("www.rp.com", "rp");
    }

    @Test @OperateOnDeployment("sp")
    public void openIdLoginWithClaimedIdentifierAndAttributeExchangeTest() {
        init();
        String userName = "jane_doe";
        String claimedId = "http://localhost:8080/op/users/" + userName;

        Map<String, String> params = new HashMap<String, String>();
        params.put("command", "login");
        params.put("identifier", claimedId);
        params.put("fetchEmail", "true");
        sendMessageToApplication("localhost", "rp", params);

        checkApplicationMessage("Please provide the password for " + userName + ".");

        params = new HashMap<String, String>();
        params.put("command", "authenticate");
        params.put("userName", userName);
        sendMessageToApplication("localhost", "op", params);

        checkApplicationMessage("Please provide your email.");

        params = new HashMap<String, String>();
        params.put("command", "setAttribute");
        String email = "jane_doe@op.com";
        params.put("email", email);
        sendMessageToApplication("localhost", "op", params);

        checkApplicationMessage("Login succeeded (" + claimedId + ", email " + email + ")");

        // All dialogues should be terminated by now.
        checkDialogueTermination("www.op.com", "op");
        checkDialogueTermination("www.rp.com", "rp");
    }

    private void checkNrOfSessions(String serverName, String spOrIdp, int expectedNumber) {
        Map<String, String> params = new HashMap<String, String>();
        params.put("command", "getNrOfSessions");
        sendMessageToApplication(serverName, spOrIdp, params);
        checkApplicationMessage(Integer.toString(expectedNumber));
    }

    private void samlSignOn(String spHostName, String idpEntityId, String userName) {
        Map<String, String> params = new HashMap<String, String>();
        params.put("command", "login");
        params.put("idpEntityId", idpEntityId);
        sendMessageToApplication(spHostName, "sp", params);

        checkApplicationMessage("Please login");

        params = new HashMap<String, String>();
        params.put("command", "authenticate");
        params.put("userName", userName);
        sendMessageToApplication("www.idp.com", "idp", params);

        checkApplicationMessage("Login succeeded (" + userName + ")");
    }

    private void sendMessageToApplication(String hostName, String contextRoot, Map<String, String> params) {
        List<NameValuePair> qParams = new ArrayList<NameValuePair>();
        for (Map.Entry<String, String> mapEntry : params.entrySet()) {
            qParams.add(new BasicNameValuePair(mapEntry.getKey(), mapEntry.getValue()));
        }
        URI uri;
        try {
            uri = URIUtils.createURI("http", "localhost", 8080, "/" + contextRoot + "/testservlet", URLEncodedUtils.format(qParams, "UTF-8"), null);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        request = new HttpGet(uri);
        if (!hostName.equals("localhost")) {
            request.getParams().setParameter(ClientPNames.VIRTUAL_HOST, new HttpHost(hostName, 8080));
        }

        executeHttpRequestAndRelay();
    }

    private void checkDialogueTermination(String serverName, String spOrIdp) {
        Map<String, String> params = new HashMap<String, String>();
        params.put("command", "getNrOfDialogues");
        sendMessageToApplication(serverName, spOrIdp, params);
        checkApplicationMessage("0");
    }

    /**
     * Relays the SAML message from the SP to the IDP or vice versa. Results in
     * an HTTP request that is ready to be executed.
     */
    private void relaySamlMessage() {
        if (responseType == ResponseType.SAML_MESSAGE_POST_BOUND) {
            Matcher matcher = Pattern.compile("ACTION=\"(.*?)\"").matcher(responseBody);
            matcher.find();
            String uri = matcher.group(1);

            matcher = Pattern.compile("NAME=\"(.*?)\"").matcher(responseBody);
            matcher.find();
            String name = matcher.group(1);

            matcher = Pattern.compile("VALUE=\"(.*?)\"").matcher(responseBody);
            matcher.find();
            String value = matcher.group(1);

            String serverName = extractServerNameFromUri(uri);
            uri = uri.replace(serverName, "localhost");
            HttpPost httpPost = new HttpPost(uri);
            if (!serverName.equals("localhost")) {
                httpPost.getParams().setParameter(ClientPNames.VIRTUAL_HOST, new HttpHost(serverName, 8080));
            }
            List<NameValuePair> formparams = new ArrayList<NameValuePair>();
            formparams.add(new BasicNameValuePair(name, value));
            UrlEncodedFormEntity entity;
            try {
                entity = new UrlEncodedFormEntity(formparams, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
            httpPost.setEntity(entity);
            request = httpPost;
        } else if (responseType == ResponseType.SAML_MESSAGE_REDIRECT_BOUND) {
            String location = response.getFirstHeader("Location").getValue();
            log.info("Received redirect to " + location);
            String serverName = extractServerNameFromUri(location);
            HttpGet httpGet = new HttpGet(location.replace(serverName, "localhost"));
            httpGet.getParams().setParameter(ClientPNames.VIRTUAL_HOST, new HttpHost(serverName, 8080));
            request = httpGet;
        } else if (responseType == ResponseType.ERROR) {
            Assert.fail("Error response received by test client (status code " + response.getStatusLine().getStatusCode() + "): " + responseBody);
        } else {
            throw new RuntimeException("Cannot relay the non-SAML response type " + responseType + " (message: " + responseBody + ")");
        }
    }

    private ResponseType determineResponseType() {
        if (response.getStatusLine().getStatusCode() == HttpStatus.SC_MOVED_TEMPORARILY) {
            return ResponseType.SAML_MESSAGE_REDIRECT_BOUND;
        } else if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
            return ResponseType.ERROR;
        } else if (responseBody.contains("HTTP Post SamlBinding")) {
            return ResponseType.SAML_MESSAGE_POST_BOUND;
        } else {
            return ResponseType.APPLICATION_MESSAGE;
        }
    }

    private String extractServerNameFromUri(String string) {
        Matcher matcher = Pattern.compile("http://(.*?):").matcher(string);
        matcher.find();
        return matcher.group(1);
    }

    private void checkApplicationMessage(String expectedMessageBody) {
        if (responseType == ResponseType.ERROR) {
            Assert.fail("Error response received by test client (status code " + response.getStatusLine().getStatusCode() + "): " + responseBody);
        }
        Assert.assertEquals(ResponseType.APPLICATION_MESSAGE, responseType);
        Assert.assertEquals(expectedMessageBody, responseBody);
    }

    /**
     * Executes the current HTTP request and evaluates the response. If the
     * response is a SAML message that needs to be relayed, by the user agent
     * (which is mimicked by the current class), from the SP to the IDP or vice
     * versa, the relay is performed. This is repeated until a non-relay response
     * has been received.
     */
    private void executeHttpRequestAndRelay() {
        executeHttpRequest();
        while (responseType == ResponseType.SAML_MESSAGE_POST_BOUND || responseType == ResponseType.SAML_MESSAGE_REDIRECT_BOUND) {
            relaySamlMessage();
            executeHttpRequest();
        }
    }

    private void executeHttpRequest() {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            response = httpClient.execute(request);
            HttpEntity entity = response.getEntity();
            if (entity != null) {
                entity.writeTo(outputStream);
            }
            responseBody = outputStream.toString("UTF-8");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        responseType = determineResponseType();
    }
}
