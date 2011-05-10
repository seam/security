package org.jboss.seam.security.external.saml;

import java.util.GregorianCalendar;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;

import org.jboss.seam.security.external.dialogues.api.Dialogue;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.AssertionType;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.AudienceRestrictionType;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.AuthnContextType;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.AuthnStatementType;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.ConditionsType;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.NameIDType;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.SubjectConfirmationDataType;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.SubjectConfirmationType;
import org.jboss.seam.security.external.jaxb.samlv2.assertion.SubjectType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.AuthnRequestType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.LogoutRequestType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.ObjectFactory;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.RequestAbstractType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.ResponseType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.StatusCodeType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.StatusResponseType;
import org.jboss.seam.security.external.jaxb.samlv2.protocol.StatusType;
import org.jboss.seam.security.external.saml.api.SamlIdpSession;
import org.jboss.seam.security.external.saml.api.SamlNameId;
import org.jboss.seam.security.external.saml.idp.SamlIdpSessionImpl;

/**
 * @author Marcel Kolsteren
 */
@ApplicationScoped
public class SamlMessageFactory {
    private static final int ASSERTION_VALIDITY_IN_MINUTES = 5;

    @Inject
    private Instance<SamlEntityBean> samlEntityBean;

    @Inject
    private Dialogue dialogue;

    @Inject
    private Instance<SamlDialogue> samlDialogue;

    private ObjectFactory objectFactory = new ObjectFactory();

    private org.jboss.seam.security.external.jaxb.samlv2.assertion.ObjectFactory assertionObjectFactory = new org.jboss.seam.security.external.jaxb.samlv2.assertion.ObjectFactory();

    public StatusResponseType createStatusResponse(String statusCode, String statusMessage) {
        StatusResponseType response = objectFactory.createStatusResponseType();

        fillStatusResponseFields(response, statusCode, statusMessage);

        return response;
    }

    public AuthnRequestType createAuthnRequest() {
        AuthnRequestType authnRequest = objectFactory.createAuthnRequestType();

        fillRequestAbstractTypeFields(authnRequest);

        // Fill in the optional fields that indicate where and how the response
        // should be delivered.
        authnRequest.setAssertionConsumerServiceURL(samlEntityBean.get().getServiceURL(SamlServiceType.SAML_ASSERTION_CONSUMER_SERVICE));
        authnRequest.setProtocolBinding(SamlConstants.HTTP_POST_BINDING);

        return authnRequest;
    }

    public ResponseType createResponse(SamlIdpSession session, SamlEndpoint externalSamlEndpoint) {
        ResponseType response = objectFactory.createResponseType();

        fillStatusResponseFields(response, SamlConstants.STATUS_SUCCESS, null);

        AssertionType assertion = assertionObjectFactory.createAssertionType();
        response.getAssertionOrEncryptedAssertion().add(assertion);

        SubjectType subject = assertionObjectFactory.createSubjectType();
        assertion.setSubject(subject);

        NameIDType nameID = assertionObjectFactory.createNameIDType();
        subject.getContent().add(assertionObjectFactory.createNameID(nameID));
        nameID.setValue(session.getPrincipal().getNameId().getValue());
        nameID.setFormat(session.getPrincipal().getNameId().getFormat());
        nameID.setNameQualifier(session.getPrincipal().getNameId().getQualifier());

        SubjectConfirmationType subjectConfirmation = assertionObjectFactory.createSubjectConfirmationType();
        subject.getContent().add(assertionObjectFactory.createSubjectConfirmation(subjectConfirmation));
        subjectConfirmation.setMethod(SamlConstants.CONFIRMATION_METHOD_BEARER);
        subjectConfirmation.setNameID(nameID);

        SubjectConfirmationDataType subjectConfirmationData = assertionObjectFactory.createSubjectConfirmationDataType();
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

        subjectConfirmationData.setRecipient(externalSamlEndpoint.getLocation());
        subjectConfirmationData.setNotOnOrAfter(SamlUtils.getXMLGregorianCalendarNowPlusDuration(GregorianCalendar.MINUTE, ASSERTION_VALIDITY_IN_MINUTES));
        subjectConfirmationData.setInResponseTo(samlDialogue.get().getExternalProviderMessageId());

        ConditionsType conditions = assertionObjectFactory.createConditionsType();
        assertion.setConditions(conditions);
        AudienceRestrictionType audienceRestriction = assertionObjectFactory.createAudienceRestrictionType();
        conditions.getConditionOrAudienceRestrictionOrOneTimeUse().add(audienceRestriction);
        audienceRestriction.getAudience().add(samlDialogue.get().getExternalProvider().getEntityId());

        AuthnStatementType authnStatement = assertionObjectFactory.createAuthnStatementType();
        assertion.getStatementOrAuthnStatementOrAuthzDecisionStatement().add(authnStatement);
        authnStatement.setAuthnInstant(SamlUtils.getXMLGregorianCalendarNow());
        authnStatement.setSessionIndex(((SamlIdpSessionImpl) session).getSessionIndex());

        AuthnContextType authnContext = assertionObjectFactory.createAuthnContextType();
        authnStatement.setAuthnContext(authnContext);
        authnContext.getContent().add(assertionObjectFactory.createAuthnContextDeclRef(SamlConstants.AC_PASSWORD_PROTECTED_TRANSPORT));

        return response;
    }

    public LogoutRequestType createLogoutRequest(SamlNameId samlNameId, String sessionIndex) {
        LogoutRequestType logoutRequest = objectFactory.createLogoutRequestType();

        fillRequestAbstractTypeFields(logoutRequest);

        NameIDType nameID = assertionObjectFactory.createNameIDType();
        nameID.setValue(samlNameId.getValue());
        nameID.setFormat(samlNameId.getFormat());
        nameID.setNameQualifier(samlNameId.getQualifier());
        logoutRequest.setNameID(nameID);

        logoutRequest.getSessionIndex().add(sessionIndex);

        return logoutRequest;
    }

    private void fillRequestAbstractTypeFields(RequestAbstractType request) {
        request.setID(dialogue.getId());
        request.setIssueInstant(SamlUtils.getXMLGregorianCalendarNow());

        NameIDType issuer = assertionObjectFactory.createNameIDType();
        issuer.setValue(samlEntityBean.get().getEntityId());
        request.setIssuer(issuer);

        request.setVersion(SamlConstants.VERSION_2_0);
    }

    private void fillStatusResponseFields(StatusResponseType response, String statusCode, String statusMessage) {
        response.setID(dialogue.getId());
        response.setIssueInstant(SamlUtils.getXMLGregorianCalendarNow());

        NameIDType issuer = assertionObjectFactory.createNameIDType();
        issuer.setValue(samlEntityBean.get().getEntityId());
        response.setIssuer(issuer);

        response.setVersion(SamlConstants.VERSION_2_0);
        response.setInResponseTo(samlDialogue.get().getExternalProviderMessageId());

        StatusCodeType statusCodeJaxb = objectFactory.createStatusCodeType();
        statusCodeJaxb.setValue(statusCode);

        StatusType statusType = objectFactory.createStatusType();
        statusType.setStatusCode(statusCodeJaxb);
        if (statusMessage != null) {
            statusType.setStatusMessage(statusMessage);
        }

        response.setStatus(statusType);
    }
}
