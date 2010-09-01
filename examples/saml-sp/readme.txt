SAML-SP EXAMPLE


What is it?
===========

This demo web application shows how to delegate user authentication and session
management to trusted SAMLv2 identity providers (IDPs). It makes use of the
SAMLv2 submodule of Seam Security.


How to deploy it?
=================

The application is packaged as a war file and should run in any JEE6
environment. It has been tested on JBoss AS 6. Before deploying the application,
you need to map these two host names to the localhost:

www.saml-sp1.com
www.saml-sp2.com

On Unix based systems, you do this by putting the following lines in
'/etc/hosts':

127.0.0.1	www.saml-sp1.com
127.0.0.1	www.saml-sp2.com


Some background info
====================

The application contains two "virtual applications":

http://www.saml-sp1.com:8080/saml-sp
http://www.saml-sp2.com:8080/saml-sp

Think of it as two web shops hosted by the same SaaS provider, sharing the same
war file, but each having their own SAML Service Provider (SP) configuration,
their own database objects and their own users and user sessions.

The Service Providers are preconfigured to run at port 8080, to use a test key
store which is included in the war file, and to use the http protocol for
communicating with IDPs. These settings are ok for a test setup, but please be
aware that in production, you'd use http on port 443, and you'd use your own
well-secured keystore, probably somewhere on the file system. In the test
application these settings are done programmatically (by the SpCustomizer). 


How to use the application
==========================

Start the application and surf to:

http://www.saml-sp1.com:8080/saml-sp

First you need to configure the identity provider(s) to trust. You have
different options:
- install and use your own third-party identity provider (e.g. OpenSSO,
Shibboleth, SimpleSAMLphp, CAS or A-Select)
- use an existing SAMLv2 identity provider where you have an account (you could
create an account for the www.ssocircle.com identity provider, which is open to
everyone)
- use the seam-idp example application

You need to create a trust relationship between the chosen identity provider(s)
and the sample application. You do that by exchanging meta data. The menu option
"Configuration" will help you. Note that in a production system you'd definitely
restrict such a configuration page to system administrators! On the
configuration page, you see a link that points out where the meta data of the
current service provider resides. You use that link for uploading the meta data
to your identity provider. The other way around, you find out where your
identity provider's meta data is (read your IDP manual), and you upload it on
the Configuration page. You do that for all identity providers (probably only
one).

Do the configuration not only for the saml-sp1 virtual application, but also for
saml-sp2. Remember that you need to see it as two separate service providers.

Now you are ready to login. Go to the login page by using the menu. You need to
choose which identity provider you want to use, and click the login link next to
it. By the way, an application that only trusts one identity provider won't have
such a page, and an application that trusts multiple identity providers might
save the user's choice in a cookie so that this page will only be shown once.
You'll be redirected to your identity provider's login page and input your
credentials to log in. After that, you'll be redirected back to the service
provider, and you'll see the info of the logged in user, including any
attributes that have been provided by the identity provider. Normally you'd do
the things where you needed to login for, but this is a kind of hollow sample
application, and we'll move on.

Now go to the other virtual application and login there. You'll see that you'll
be immediately logged in into that other application without entering your
credentials again. Single sign on in other words.

The identity provider now manages one user session, with two service providers
participating in the session. You can stop the whole session by choosing "Global
Logout" from the menu in one of the virtual apps. Check that you are logged out
at the other virtual app as well, and also at the identity providers side. That
was a single logout in other words. You can also logout locally. In that case
you just stop using the IDP-managed session at the service provider side,
without informing the identity provider about that.