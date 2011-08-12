package org.jboss.seam.security.external.openid;

import java.io.IOException;
import java.io.Writer;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.security.external.InvalidRequestException;
import org.jboss.seam.security.external.OpenIdRequestedAttributeImpl;
import org.jboss.seam.security.external.ResponseHandler;
import org.jboss.seam.security.external.dialogues.DialogueBean;
import org.jboss.seam.security.external.dialogues.api.DialogueManager;
import org.jboss.seam.security.external.openid.api.OpenIdRequestedAttribute;
import org.jboss.seam.security.external.spi.OpenIdProviderSpi;
import org.openid4java.association.AssociationException;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.DirectError;
import org.openid4java.message.Message;
import org.openid4java.message.MessageException;
import org.openid4java.message.MessageExtension;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.server.ServerException;
import org.openid4java.server.ServerManager;

/**
 * @author Marcel Kolsteren
 */
public class OpenIdProviderAuthenticationService {
    @Inject
    private Instance<OpenIdProviderRequest> openIdProviderRequest;

    @Inject
    private Instance<ServerManager> openIdServerManager;

    @Inject
    private Instance<OpenIdProviderSpi> openIdProviderSpi;

    @Inject
    private ResponseHandler responseHandler;

    @Inject
    private DialogueManager dialogueManager;

    @Inject
    private Instance<DialogueBean> dialogue;

    @Inject
    private Instance<OpenIdProviderBeanApi> opBean;

    public void handleIncomingMessage(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws InvalidRequestException {
        ParameterList parameterList = new ParameterList(httpRequest.getParameterMap());

        String mode = parameterList.getParameterValue("openid.mode");

        Message associationResponse;

        if ("associate".equals(mode)) {
            associationResponse = openIdServerManager.get().associationResponse(parameterList);
            writeMessageToResponse(associationResponse, httpResponse);
        } else if ("checkid_setup".equals(mode) || "checkid_immediate".equals(mode)) {
            dialogueManager.beginDialogue();
            String claimedIdentifier = parameterList.getParameterValue("openid.claimed_id");
            String opLocalIdentifier = parameterList.getParameterValue("openid.identity");

            openIdProviderRequest.get().setParameterList(parameterList);
            openIdProviderRequest.get().setClaimedIdentifier(claimedIdentifier);

            MessageExtension ext = null;
            try {
                AuthRequest authReq = AuthRequest.createAuthRequest(parameterList, openIdServerManager.get().getRealmVerifier());
                if (authReq.hasExtension(AxMessage.OPENID_NS_AX)) {
                    ext = authReq.getExtension(AxMessage.OPENID_NS_AX);
                }
            } catch (MessageException e) {
                throw new RuntimeException(e);
            }

            if (ext instanceof FetchRequest) {
                FetchRequest fetchRequest = (FetchRequest) ext;

                List<OpenIdRequestedAttribute> requestedAttributes = new LinkedList<OpenIdRequestedAttribute>();
                handleAttributeRequests(fetchRequest, requestedAttributes, false);
                handleAttributeRequests(fetchRequest, requestedAttributes, true);
                openIdProviderRequest.get().setRequestedAttributes(requestedAttributes);
                openIdProviderRequest.get().setFetchRequest(fetchRequest);
            }

            if (claimedIdentifier != null && opLocalIdentifier != null) {
                boolean immediate = "checkid_immediate".equals(mode);
                String realm = parameterList.getParameterValue("openid.realm");
                if (realm == null) {
                    realm = parameterList.getParameterValue("openid.return_to");
                }

                if (opLocalIdentifier.equals(AuthRequest.SELECT_ID)) {
                    openIdProviderSpi.get().authenticate(realm, null, immediate, responseHandler.createResponseHolder(httpResponse));
                } else {
                    String userName = opBean.get().getUserNameFromOpLocalIdentifier(opLocalIdentifier);
                    openIdProviderSpi.get().authenticate(realm, userName, immediate, responseHandler.createResponseHolder(httpResponse));
                }
            } else {
                associationResponse = DirectError.createDirectError("Invalid request; claimed_id or identity attribute is missing");
                writeMessageToResponse(associationResponse, httpResponse);
            }
            dialogueManager.detachDialogue();
        } else if ("check_authentication".equals(mode)) {
            associationResponse = openIdServerManager.get().verify(parameterList);
            writeMessageToResponse(associationResponse, httpResponse);
        } else {
            associationResponse = DirectError.createDirectError("Unknown request");
            writeMessageToResponse(associationResponse, httpResponse);
        }
    }

    private void handleAttributeRequests(FetchRequest fetchRequest, List<OpenIdRequestedAttribute> requestedAttributes, boolean required) {
        @SuppressWarnings("unchecked")
        Map<String, String> attributes = fetchRequest.getAttributes(required);

        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            OpenIdRequestedAttributeImpl requestedAttribute = new OpenIdRequestedAttributeImpl();
            requestedAttribute.setAlias(entry.getKey());
            requestedAttribute.setTypeUri(entry.getValue());
            requestedAttribute.setRequired(required);
            requestedAttribute.setCount(fetchRequest.getCount(entry.getKey()));
            requestedAttributes.add(requestedAttribute);
        }
    }

    public void sendAuthenticationResponse(boolean authenticationSuccesful, Map<String, List<String>> attributeValues, HttpServletResponse response) {
        ParameterList parameterList = openIdProviderRequest.get().getParameterList();
        String userName = openIdProviderRequest.get().getUserName();
        String opLocalIdentifier = opBean.get().getOpLocalIdentifierForUserName(userName);
        String claimedIdentifier = openIdProviderRequest.get().getClaimedIdentifier();
        if (claimedIdentifier.equals(AuthRequest.SELECT_ID)) {
            claimedIdentifier = opLocalIdentifier;
        }

        Message authResponse;

        if (response instanceof DirectError) {
            authResponse = openIdServerManager.get().authResponse(parameterList, opLocalIdentifier, claimedIdentifier, authenticationSuccesful, true);                     
            writeMessageToResponse(authResponse, response);
        } else {
            // We cannot sign the message before we add the extension
            authResponse = openIdServerManager.get().authResponse(parameterList, opLocalIdentifier, claimedIdentifier, authenticationSuccesful, false);
            
            if (openIdProviderRequest.get().getRequestedAttributes() != null) {
                try {
                    FetchResponse fetchResponse = FetchResponse.createFetchResponse(openIdProviderRequest.get().getFetchRequest(), attributeValues);
                    authResponse.addExtension(fetchResponse);
                } catch (MessageException e) {
                    throw new RuntimeException(e);
                }
            }
            
            try {
                openIdServerManager.get().sign((AuthSuccess)authResponse);
            } catch (ServerException e) {
                throw new RuntimeException(e);
            } catch (AssociationException e) {
                throw new RuntimeException(e);
            }

            // caller will need to decide which of the following to use:

            // option1: GET HTTP-redirect to the return_to URL
            String destinationUrl = authResponse.getDestinationUrl(true);
            responseHandler.sendHttpRedirectToUserAgent(destinationUrl, response);

            // option2: HTML FORM Redirection
            // RequestDispatcher dispatcher =
            // getServletContext().getRequestDispatcher("formredirection.jsp");
            // httpReq.setAttribute("prameterMap", response.getParameterMap());
            // httpReq.setAttribute("destinationUrl",
            // response.getDestinationUrl(false));
            // dispatcher.forward(request, response);
            // return null;
        }

        dialogue.get().setFinished(true);
    }

    private void writeMessageToResponse(Message message, HttpServletResponse response) {
        Writer writer = responseHandler.getWriter("text/plain", response);
        try {
            writer.append(message.keyValueFormEncoding());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
