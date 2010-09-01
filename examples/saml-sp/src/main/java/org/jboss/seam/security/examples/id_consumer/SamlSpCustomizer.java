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
package org.jboss.seam.security.examples.id_consumer;

import javax.enterprise.event.Observes;

import org.jboss.seam.security.external.api.SamlServiceProviderConfigurationApi;
import org.jboss.seam.security.external.virtualapplications.api.AfterVirtualApplicationCreation;
import org.jboss.seam.security.external.virtualapplications.api.VirtualApplication;

public class SamlSpCustomizer
{
   public void customize(@Observes AfterVirtualApplicationCreation event, SamlServiceProviderConfigurationApi sp, VirtualApplication virtualApplication)
   {
      sp.setEntityId("http://" + virtualApplication.getHostName());
      sp.setProtocol("http");
      sp.setPort(8080);
      sp.setSigningKey("classpath:/test_keystore.jks", "store456", "servercert", "pass456");
   }

}
