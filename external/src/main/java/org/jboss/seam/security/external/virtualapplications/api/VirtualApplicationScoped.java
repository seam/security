/*
 * JBoss, Home of Professional Open Source
 * Copyright 2010, Red Hat, Inc., and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
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
 * using a host name that is part of the company's internet domain name. It is
 * comparable to virtual hosting mechanisms that can be used to share one
 * webserver with one IP-address by multiple companies.
 * </p>
 * 
 * <p>
 * In the application context, one stores the configuration or data that is
 * specific for one company using the application. In the context of Seam
 * security, the virtual application context can be used to store the
 * configuration of an OpenID or SAML entity that is specific for one
 * hostName/company.
 * </p>
 * 
 * <p>
 * Virtual applications need to be configured by adding the following observer
 * to your application:
 * 
 * <pre>
 * public void virtualApplicationManagerCreated(@Observes final AfterVirtualApplicationManagerCreation event)
 * {
 *    event.addVirtualApplication(&quot;www.company1.com&quot;);
 *    event.addVirtualApplication(&quot;www.company2.com&quot;);
 * }
 * </pre>
 * 
 * </p>
 * 
 * <p>
 * If you need to configure an application scoped bean, for example a SAML
 * service provider bean that is scoped to the virtual application context, you
 * should do that by reacting on the {@link VirtualApplicationCreated} event,
 * which is fired for each configured virtual application at application startup
 * time. For example:
 * 
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
 * 
 * </p>
 * 
 * @author Marcel Kolsteren
 * 
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target( { ElementType.TYPE, ElementType.METHOD, ElementType.FIELD })
@NormalScope(passivating = false)
public @interface VirtualApplicationScoped
{

}
