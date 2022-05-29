package com.sspl;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

public class GetIssuerCertificateLDAP {

	public GetIssuerCertificateLDAP() {
		// TODO Auto-generated constructor stub
		
	}

	public byte [] getCertificateByteArray(URI ldapURI) {
		byte [] certByteArray = null;
		
		// let's see what URI lets us do with the ldap URI we get from the cert:
			
		System.out.println("URI in: " + ldapURI.toString());
		System.out.println("Path: " + ldapURI.getPath());
		System.out.println("host: " + ldapURI.getHost());
		System.out.println("authority: " + ldapURI.getAuthority());
		
		System.out.println("fragment: " + ldapURI.getFragment());
		System.out.println("query: " + ldapURI.getQuery());
		System.out.println("scheme: " + ldapURI.getSchemeSpecificPart());
		System.out.println("proto:" + ldapURI.getScheme());
		
		// appears we want a string of the URL:
		StringBuilder ldapStr = new StringBuilder();
		ldapStr.append(ldapURI.getScheme() + "://");
		ldapStr.append(ldapURI.getHost());
		// path holds the base DN to query
		//ldapStr.append(ldapURI.getPath());
		
		// query holds the attributes to return!
		String [] attrs = ldapURI.getQuery().toString().split(",");
		
		System.out.println("URL string: " + ldapStr.toString());
		System.out.println("Attrs to get: " + String.join(",", attrs));
		/*
		URL ldapURL = null;
		try {
			ldapURL = ldapURI.toURL();
			System.out.println("LDAPURL: " + ldapURL.toString());
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
		*/
		
		
		// setup ldap
		
		Hashtable env = new Hashtable<String, Object>();;
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, ldapStr.toString());
		env.put(Context.SECURITY_AUTHENTICATION, "none");
		
		SearchControls sControls = new SearchControls();
		sControls.setSearchScope(SearchControls.OBJECT_SCOPE);
		sControls.setReturningAttributes(attrs);
		
		
		LdapContext ctx;
		try {
			ctx = new InitialLdapContext(env, null);
			ctx.setRequestControls(null);
			
			NamingEnumeration<?> namingEnum = ctx.search(ldapURI.getPath().replace("/", ""), "(objectclass=*)", sControls);
		    while (namingEnum.hasMore ()) {
		        SearchResult result = (SearchResult) namingEnum.next ();    
		        Attributes attrsReturned = result.getAttributes ();
		        System.out.println(attrsReturned.get("cACertificate;binary"));
		        Attribute a = attrsReturned.get("cACertificate;binary");
		        // assuming single valued otherwise use .size();
		        certByteArray  = (byte []) a.get();

		    } 
		    System.out.println("after the while");
		    namingEnum.close();
			System.out.println("have directory context");
			
			ctx.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			System.out.println("THERE WAS A DIRECTORY ISSUE: " + e.getMessage());
			e.printStackTrace();
		}
		
		return certByteArray;
	}
	
}
