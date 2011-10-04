package org.jboss.seam.security.external.saml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.jboss.solder.logging.Logger;
import org.jboss.seam.security.external.Base64;
import org.jboss.seam.security.external.InvalidRequestException;
import org.jboss.seam.security.external.JaxbContext;
import org.jboss.seam.security.external.dialogues.api.DialogueManager;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.RequestAbstractType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.ResponseType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.StatusResponseType;
import org.jboss.seam.security.external.saml.idp.SamlIdpBeanApi;
import org.jboss.seam.security.external.saml.idp.SamlIdpSingleLogoutService;
import org.jboss.seam.security.external.saml.idp.SamlIdpSingleSignOnService;
import org.jboss.seam.security.external.saml.sp.SamlSpBeanApi;
import org.jboss.seam.security.external.saml.sp.SamlSpSingleLogoutService;
import org.jboss.seam.security.external.saml.sp.SamlSpSingleSignOnService;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

/**
 * @author Marcel Kolsteren
 */
@ApplicationScoped
public class SamlMessageReceiver {
    @Inject
    private Logger log;

    @Inject
    private DialogueManager dialogueManager;

    @Inject
    private Instance<SamlDialogue> samlDialogue;

    @Inject
    private SamlSpSingleLogoutService samlSpSingleLogoutService;

    @Inject
    private SamlIdpSingleLogoutService samlIdpSingleLogoutService;

    @Inject
    private SamlSpSingleSignOnService samlSpSingleSignOnService;

    @Inject
    private SamlIdpSingleSignOnService samlIdpSingleSignOnService;

    @Inject
    private Instance<SamlEntityBean> samlEntityBean;

    @Inject
    private Instance<SamlSpBeanApi> samlSpBean;

    @Inject
    private Instance<SamlIdpBeanApi> samlIdpBean;

    @Inject
    private SamlSignatureUtilForPostBinding signatureUtilForPostBinding;

    @Inject
    private SamlSignatureUtilForRedirectBinding signatureUtilForRedirectBinding;

    @Inject
    @JaxbContext({RequestAbstractType.class, StatusResponseType.class})
    private JAXBContext jaxbContext;

    public void handleIncomingSamlMessage(SamlServiceType service, HttpServletRequest httpRequest, HttpServletResponse httpResponse, SamlIdpOrSp idpOrSp) throws InvalidRequestException {
        String samlRequestParam = httpRequest.getParameter(SamlRedirectMessage.QSP_SAML_REQUEST);
        String samlResponseParam = httpRequest.getParameter(SamlRedirectMessage.QSP_SAML_RESPONSE);

        SamlRequestOrResponse samlRequestOrResponse;
        String samlMessage;

        if (samlRequestParam != null && samlResponseParam == null) {
            samlMessage = samlRequestParam;
            samlRequestOrResponse = SamlRequestOrResponse.REQUEST;
        } else if (samlRequestParam == null && samlResponseParam != null) {
            samlMessage = samlResponseParam;
            samlRequestOrResponse = SamlRequestOrResponse.RESPONSE;
        } else {
            throw new InvalidRequestException("SAML message should either have a SAMLRequest parameter or a SAMLResponse parameter");
        }

        InputStream is;
        if (httpRequest.getMethod().equals("POST")) {
            byte[] decodedMessage = Base64.decode(samlMessage);
            is = new ByteArrayInputStream(decodedMessage);
        } else {
            byte[] base64Decoded = Base64.decode(samlMessage);
            ByteArrayInputStream bais = new ByteArrayInputStream(base64Decoded);
            is = new InflaterInputStream(bais, new Inflater(true));
        }

        Document document = getDocument(is);
        String issuerEntityId;
        RequestAbstractType samlRequestMessage = null;
        StatusResponseType samlResponseMessage = null;
        if (samlRequestOrResponse.isRequest()) {
            samlRequestMessage = getSamlRequest(document);
            issuerEntityId = samlRequestMessage.getIssuer().getValue();
        } else {
            samlResponseMessage = getSamlResponse(document);
            issuerEntityId = samlResponseMessage.getIssuer().getValue();
        }
        log.debug("Received: " + SamlUtils.getDocumentAsString(document));

        try {
            if (samlRequestOrResponse.isRequest() || samlResponseMessage.getInResponseTo() == null) {
                // Request or unsolicited response

                String destination = samlRequestOrResponse.isRequest() ? samlRequestMessage.getDestination() : samlResponseMessage.getDestination();
                if (!samlEntityBean.get().getServiceURL(service).equals(destination)) {
                    throw new InvalidRequestException("Destination (" + destination + ") is not valid.");
                }

                dialogueManager.beginDialogue();
                samlDialogue.get().setExternalProviderMessageId(samlRequestOrResponse.isRequest() ? samlRequestMessage.getID() : samlResponseMessage.getID());
                SamlExternalEntity externalProvider = samlEntityBean.get().getExternalSamlEntityByEntityId(issuerEntityId);
                if (externalProvider == null) {
                    throw new InvalidRequestException("Received message from unknown entity id " + issuerEntityId);
                }
                samlDialogue.get().setExternalProvider(externalProvider);
            } else {
                String dialogueId = samlResponseMessage.getInResponseTo();
                if (!dialogueManager.isExistingDialogue(dialogueId)) {
                    throw new InvalidRequestException("No request that corresponds with the received response");
                }

                dialogueManager.attachDialogue(dialogueId);
                if (!(samlDialogue.get().getExternalProvider().getEntityId().equals(issuerEntityId))) {
                    throw new InvalidRequestException("Identity samlEntityBean of request and response do not match");
                }
            }

            SamlExternalEntity externalProvider = samlEntityBean.get().getExternalSamlEntityByEntityId(issuerEntityId);

            boolean validate;
            if (samlRequestOrResponse.isRequest()) {
                if (service.getProfile() == SamlProfile.SINGLE_SIGN_ON) {
                    if (idpOrSp == SamlIdpOrSp.IDP) {
                        validate = samlIdpBean.get().isWantAuthnRequestsSigned();
                    } else {
                        validate = samlSpBean.get().isWantAssertionsSigned();
                    }
                } else {
                    if (idpOrSp == SamlIdpOrSp.IDP) {
                        validate = samlIdpBean.get().isWantSingleLogoutMessagesSigned();
                    } else {
                        validate = samlSpBean.get().isWantSingleLogoutMessagesSigned();
                    }
                }
            } else {
                validate = samlResponseMessage instanceof ResponseType;
            }

            if (validate) {
                if (httpRequest.getMethod().equals("POST")) {
                    signatureUtilForPostBinding.validateSignature(externalProvider.getPublicKey(), document);
                } else {
                    SamlRedirectMessage redirectMessage = new SamlRedirectMessage(samlRequestOrResponse, httpRequest);
                    signatureUtilForRedirectBinding.validateSignature(redirectMessage, externalProvider.getPublicKey());
                }
            }

            if (service.getProfile() == SamlProfile.SINGLE_SIGN_ON) {
                if (samlRequestOrResponse.isRequest()) {
                    samlIdpSingleSignOnService.processSPRequest(httpRequest, httpResponse, samlRequestMessage);
                } else {
                    samlSpSingleSignOnService.processIDPResponse(httpRequest, httpResponse, samlResponseMessage);
                }
            } else {
                if (samlRequestOrResponse.isRequest()) {
                    if (idpOrSp == SamlIdpOrSp.IDP) {
                        samlIdpSingleLogoutService.processSPRequest(httpRequest, httpResponse, samlRequestMessage);
                    } else {
                        samlSpSingleLogoutService.processIDPRequest(httpRequest, httpResponse, samlRequestMessage);
                    }
                } else {
                    if (idpOrSp == SamlIdpOrSp.IDP) {
                        samlIdpSingleLogoutService.processSPResponse(httpRequest, httpResponse, samlResponseMessage);
                    } else {
                        samlSpSingleLogoutService.processIDPResponse(httpRequest, httpResponse, samlResponseMessage);
                    }
                }
            }
        } catch (Exception e) {
            if (dialogueManager.isAttached()) {
                dialogueManager.endDialogue();
            }
            throw new RuntimeException(e);
        }

        dialogueManager.detachDialogue();
    }

    private RequestAbstractType getSamlRequest(Document document) throws InvalidRequestException {
        try {
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            @SuppressWarnings("unchecked")
            JAXBElement<RequestAbstractType> jaxbRequest = (JAXBElement<RequestAbstractType>) unmarshaller.unmarshal(document);
            RequestAbstractType request = jaxbRequest.getValue();
            return request;
        } catch (JAXBException e) {
            throw new InvalidRequestException("SAML message could not be parsed", e);
        }
    }

    private StatusResponseType getSamlResponse(Document document) throws InvalidRequestException {
        try {
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            @SuppressWarnings("unchecked")
            JAXBElement<StatusResponseType> jaxbResponseType = (JAXBElement<StatusResponseType>) unmarshaller.unmarshal(document);
            StatusResponseType statusResponse = jaxbResponseType.getValue();
            return statusResponse;
        } catch (JAXBException e) {
            throw new InvalidRequestException("SAML message could not be parsed", e);
        }
    }

    private Document getDocument(InputStream is) throws InvalidRequestException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setXIncludeAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            return builder.parse(is);
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        } catch (SAXException e) {
            throw new InvalidRequestException("SAML request could not be parsed", e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
