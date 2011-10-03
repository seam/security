package org.jboss.seam.security.external.saml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.Binder;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.jboss.solder.logging.Logger;
import org.jboss.seam.security.external.Base64;
import org.jboss.seam.security.external.JaxbContext;
import org.jboss.seam.security.external.ResponseHandler;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.AuthnRequestType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.LogoutRequestType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.ObjectFactory;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.RequestAbstractType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.ResponseType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.StatusResponseType;
import org.jboss.seam.security.external.saml.api.SamlBinding;
import org.jboss.seam.security.external.saml.sp.SamlExternalIdentityProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

/**
 * @author Marcel Kolsteren
 */
@ApplicationScoped
public class SamlMessageSender {
    @Inject
    private Logger log;

    @Inject
    private Instance<SamlEntityBean> samlEntityBean;

    @Inject
    private SamlSignatureUtilForPostBinding signatureUtilForPostBinding;

    @Inject
    private SamlSignatureUtilForRedirectBinding samlSignatureUtilForRedirectBinding;

    @Inject
    private ResponseHandler responseHandler;

    @Inject
    @JaxbContext({RequestAbstractType.class, StatusResponseType.class})
    private JAXBContext jaxbContext;

    @Inject
    private Instance<SamlDialogue> samlDialogue;

    public void sendRequest(SamlExternalEntity samlProvider, SamlProfile profile, RequestAbstractType samlRequest, HttpServletResponse response) {
        Document message = null;

        SamlService service = samlProvider.getService(profile);
        SamlEndpoint endpoint = getEndpoint(service);

        try {
            samlRequest.setDestination(endpoint.getLocation());

            JAXBElement<?> requestElement;
            if (samlRequest instanceof AuthnRequestType) {
                AuthnRequestType authnRequest = (AuthnRequestType) samlRequest;
                requestElement = new ObjectFactory().createAuthnRequest(authnRequest);
            } else if (samlRequest instanceof LogoutRequestType) {
                LogoutRequestType logoutRequest = (LogoutRequestType) samlRequest;
                requestElement = new ObjectFactory().createLogoutRequest(logoutRequest);
            } else {
                throw new RuntimeException("Currently only authentication and logout requests can be sent");
            }

            Binder<Node> binder = jaxbContext.createBinder();

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setXIncludeAware(true);
            DocumentBuilder builder;
            builder = factory.newDocumentBuilder();
            message = builder.newDocument();

            binder.marshal(requestElement, message);
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        }

        sendMessage(samlProvider, message, SamlRequestOrResponse.REQUEST, endpoint, response);
    }

    public void sendResponse(SamlExternalEntity samlProvider, StatusResponseType samlResponse, SamlProfile profile, HttpServletResponse response) {
        Document message = null;

        SamlService service = samlProvider.getService(profile);
        SamlEndpoint endpoint = getEndpoint(service);

        try {
            samlResponse.setDestination(endpoint.getResponseLocation());

            JAXBElement<? extends StatusResponseType> responseElement;
            if (endpoint.getService().getProfile().equals(SamlProfile.SINGLE_LOGOUT)) {
                responseElement = new ObjectFactory().createLogoutResponse(samlResponse);
            } else {
                responseElement = new ObjectFactory().createResponse((ResponseType) samlResponse);
            }

            Binder<Node> binder = jaxbContext.createBinder();

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setXIncludeAware(true);
            DocumentBuilder builder;
            builder = factory.newDocumentBuilder();
            message = builder.newDocument();

            binder.marshal(responseElement, message);
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        }

        sendMessage(samlDialogue.get().getExternalProvider(), message, SamlRequestOrResponse.RESPONSE, endpoint, response);
    }

    public SamlEndpoint getEndpoint(SamlService service) {
        SamlEndpoint endpoint = service.getEndpointForBinding(samlEntityBean.get().getPreferredBinding());
        if (endpoint == null) {
            // Preferred binding not available. Use the other binding.
            endpoint = service.getEndpointForBinding(samlEntityBean.get().getPreferredBinding() == SamlBinding.HTTP_Post ? SamlBinding.HTTP_Redirect : SamlBinding.HTTP_Post);
        }
        if (endpoint == null) {
            throw new RuntimeException("No endpoint found for profile " + service.getProfile());
        }
        return endpoint;
    }

    private void sendMessage(SamlExternalEntity samlProvider, Document message, SamlRequestOrResponse samlRequestOrResponse, SamlEndpoint endpoint, HttpServletResponse response) {
        log.debug("Sending " + samlRequestOrResponse + ": " + SamlUtils.getDocumentAsString(message));

        try {
            boolean signMessage;

            if (endpoint.getService().getProfile() == SamlProfile.SINGLE_SIGN_ON) {
                if (samlEntityBean.get().getIdpOrSp() == SamlIdpOrSp.SP) {
                    signMessage = ((SamlExternalIdentityProvider) samlProvider).isWantAuthnRequestsSigned();
                } else {
                    signMessage = true;
                }
            } else {
                signMessage = samlEntityBean.get().isSingleLogoutMessagesSigned();
            }

            if (endpoint.getBinding() == SamlBinding.HTTP_Redirect) {
                byte[] responseBytes = SamlUtils.getDocumentAsString(message).getBytes("UTF-8");

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                Deflater deflater = new Deflater(Deflater.DEFLATED, true);
                DeflaterOutputStream deflaterStream = new DeflaterOutputStream(baos, deflater);
                deflaterStream.write(responseBytes);
                deflaterStream.finish();

                byte[] deflatedMsg = baos.toByteArray();
                String base64EncodedResponse = Base64.encodeBytes(deflatedMsg, Base64.DONT_BREAK_LINES);

                PrivateKey privateKey = null;
                if (signMessage) {
                    privateKey = samlEntityBean.get().getSigningKey().getPrivateKey();
                }
                sendSamlRedirect(base64EncodedResponse, signMessage, samlRequestOrResponse, privateKey, endpoint, response);
            } else {
                if (signMessage) {
                    PublicKey publicKey = samlEntityBean.get().getSigningKey().getCertificate().getPublicKey();
                    PrivateKey privateKey = samlEntityBean.get().getSigningKey().getPrivateKey();
                    signatureUtilForPostBinding.sign(message, new KeyPair(publicKey, privateKey));
                }
                byte[] messageBytes = SamlUtils.getDocumentAsString(message).getBytes("UTF-8");

                String base64EncodedMessage = Base64.encodeBytes(messageBytes, Base64.DONT_BREAK_LINES);

                SamlPostMessage samlPostMessage = new SamlPostMessage();
                samlPostMessage.setRequestOrResponse(samlRequestOrResponse);
                samlPostMessage.setSamlMessage(base64EncodedMessage);
                samlPostMessage.setRelayState(samlDialogue.get().getExternalProviderRelayState());
                responseHandler.sendFormToUserAgent(endpoint.getLocation(), samlPostMessage, response);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void sendSamlRedirect(String base64EncodedSamlMessage, boolean sign, SamlRequestOrResponse samlRequestOrResponse, PrivateKey signingKey, SamlEndpoint endpoint, HttpServletResponse response) {
        SamlRedirectMessage redirectMessage = new SamlRedirectMessage();

        if (sign) {
            try {
                redirectMessage.setRequestOrResponse(samlRequestOrResponse);
                redirectMessage.setSamlMessage(base64EncodedSamlMessage);
                redirectMessage.setRelayState(samlDialogue.get().getExternalProviderRelayState());

                samlSignatureUtilForRedirectBinding.sign(redirectMessage, signingKey);
            } catch (IOException e) {
                throw new RuntimeException(e);
            } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
            }
        } else {
            redirectMessage.setRequestOrResponse(samlRequestOrResponse);
            redirectMessage.setSamlMessage(base64EncodedSamlMessage);
        }

        responseHandler.sendHttpRedirectToUserAgent(endpoint.getLocation(), redirectMessage, response);
    }

}
