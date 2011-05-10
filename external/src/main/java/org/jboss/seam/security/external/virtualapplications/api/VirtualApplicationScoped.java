package org.jboss.seam.security.external.virtualapplications.api;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import javax.enterprise.context.NormalScope;

/**
 * <p>
 * The virtual application scope corresponds to a part of the application that
 * serves a certain host name. It can be used for situations where a single
 * application is used by different companies, each accessing the application
 * using a host name that is part of the company's internet domain name.
 * </p>
 * <p/>
 * <p>
 * The virtual application scope is intented to be used in a multi-tenant
 * software architecture. Wikipedia describes this architecture as follows:
 * "Multi-tenancy refers to a principle in software architecture where a single
 * instance of the software runs on a server, serving multiple client
 * organizations (tenants). Multi-tenancy is contrasted with a multi-instance
 * architecture where separate software instances (or hardware systems) are set
 * up for different client organizations. With a multi-tenant architecture, a
 * software application is designed to virtually partition its data and
 * configuration thus each client organization works with a customized virtual
 * application instance."
 * </p>
 * <p/>
 * <p>
 * In the application context, one stores the configuration or data that is
 * specific for one company using the application. In the context of Seam
 * security, the virtual application context can be used to store the
 * configuration of an OpenID or SAML entity that is specific for one
 * hostName/company.
 * </p>
 * <p/>
 * <p>
 * Virtual applications need to be configured by adding the following observer
 * to your application:
 * <p/>
 * <pre>
 * public void virtualApplicationManagerCreated(@Observes final AfterVirtualApplicationManagerCreation event)
 * {
 *    event.addVirtualApplication(&quot;www.company1.com&quot;);
 *    event.addVirtualApplication(&quot;www.company2.com&quot;);
 * }
 * </pre>
 * <p/>
 * </p>
 * <p/>
 * <p>
 * If you need to configure an application scoped bean, for example a SAML
 * service provider bean that is scoped to the virtual application context, you
 * should do that by reacting on the {@link VirtualApplicationCreated} event,
 * which is fired for each configured virtual application at application startup
 * time. For example:
 * <p/>
 * <pre>
 * public void customize(@Observes AfterVirtualApplicationCreation event, SamlServiceProviderConfigurationApi sp, VirtualApplication virtualApplication)
 * {
 *    if (virtualApplication.getHostName().equals(&quot;www.sp2.com&quot;))
 *    {
 *       sp.setPreferredBinding(SamlBinding.HTTP_Redirect);
 *    }
 *    sp.setSingleLogoutMessagesSigned(false);
 *    sp.setProtocol(&quot;http&quot;);
 *    sp.setPort(8080);
 * }
 * </pre>
 * <p/>
 * </p>
 *
 * @author Marcel Kolsteren
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD})
@NormalScope(passivating = false)
public @interface VirtualApplicationScoped {

}
