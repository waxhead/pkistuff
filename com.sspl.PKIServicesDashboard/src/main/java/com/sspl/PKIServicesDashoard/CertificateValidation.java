package com.sspl.PKIServicesDashoard;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.sspl.CRLInfo;
import com.sspl.CertInfo;
import com.sspl.GetCRLHTTP;
import com.sspl.GetIssuerCertificateHTTP;
import com.sspl.GetIssuerCertificateLDAP;

// use the OCSP class?

@WebServlet(description = "Main Servlet to handle certificate validation.", urlPatterns = { "/CertificateValidation",
		"/PKIServicesDashboard/CertificateValidation" })
//limit the upload size to a sane size for a certificate
@MultipartConfig(maxFileSize = 8192)
public class CertificateValidation extends HttpServlet {
	private static final long serialVersionUID = 1L;

	// final static Logger logger =
	// LogManager.getLogger(CertificateValidation.class);

	//
	private CertInfo ci;
	private CertInfo ciIssuer;
	private CertInfo ciIssuerLDAP;
	
	private CRLInfo ciIssuerCRLHTTP;
	private CRLInfo ciIssuerCRLLDAP;
	

	// check this with subjectname = issuer
	private CertInfo ciRootHTTP;
	private CertInfo ciRootLDAP;

	// not sure about this approach. Seems too locked in. for now this will do
	// somewhat.
	private boolean issuerCertHTTP = false;
	private boolean issuerCertLDAP = false;

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public CertificateValidation() {
		super();
		// TODO Auto-generated constructor stub
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		response.getWriter().append("Served at: ").append(request.getContextPath());
		// logger.info("doGet() caled " + getServletInfo());
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		// logger.info( "doPost " + getServletInfo());
		StringBuilder error = new StringBuilder();

		/*
		 * response.setContentType("text/html");
		 * 
		 * response.getWriter().
		 * append("We need to get the cert, check its valid and do stuff<br>");
		 * response.getWriter().append("Lets see what we got back:<br>");
		 */
		Enumeration<String> parNames = request.getParameterNames();
		while (parNames.hasMoreElements()) {
			String pName = (String) parNames.nextElement();
			// response.getWriter().append("Parameter name: " + pName + "<br>");
			String[] parValues = request.getParameterValues(pName);
			for (int i = 0; i < parValues.length; i++) {
				// response.getWriter().append("Values are: " + parValues[i] +"<br>");

			}
		}
		/*
		 * response.getWriter().
		 * append("That should be the list of the response paramters<br>");
		 */
		String whatSvcToUse = request.getParameter("certCheckType");
		if (whatSvcToUse == null || whatSvcToUse.isEmpty()) {
			// handle empty string
			// response.getWriter().append("No radio button checked.<br>");

		} else {
			// response.getWriter().append("The check to use for this cert is: " +
			// whatSvcToUse + "<br>");
		}

		// Get the CertInfo
		error.append(getCertToWorkWith(request, response));
		// doCertStuff(request, response);

		// we have a certificate already so will use the ci.get to work the required
		// URIs
		error.append(getIssuerCert(ci));
		
		// lets get the CRL here for this cert:
		// check if we have http URI
		for(URI uri : ci.getCDPLocations() ) {
			if(uri.toString().startsWith("http")) {
				System.out.println("have http for crl to get: " + uri.toString());
				getIssuerCRLHTTP(uri);
			}
			else if( uri.toString().startsWith("ldap")) {
				// do ldap look up
				System.out.println("have ldap crl locatoin to work with " + uri.toString());
				System.out.println("LDAP handling has not been fully implemented byeond this line");
			}
		}
		
		// -- HTTP CRL
		if (ciIssuerCRLHTTP != null) {
			request.setAttribute("issuerCRLHTTPRetrieved", true);
			System.out.println("CRL Info thisUpdate: " + ciIssuerCRLHTTP.getThisUpdate().toString());
			System.out.println("CRL Info nextUpdate: " + ciIssuerCRLHTTP.getNextUpdate().toString());
			System.out.println("Cert is revoked: " + ciIssuerCRLHTTP.isRevoked(ci.getX509()));
			request.setAttribute("issuerCRLThisUpdateHTTP", ciIssuerCRLHTTP.getThisUpdate().toString());
			request.setAttribute("issuerCRLNextUpdateHTTP", ciIssuerCRLHTTP.getNextUpdate().toString());
			request.setAttribute("ciIsRevokedHTTP", ciIssuerCRLHTTP.isRevoked(ci.getX509()));
			request.setAttribute("crlLenInDaysHTTP", ciIssuerCRLHTTP.getCRLLenthInDays());
			request.setAttribute("crlNumberOfDaysSinceIssuedHTTP", ciIssuerCRLHTTP.getNumberOfDaysSinceIssued());
			double crlRemaining = ((Integer) 100).doubleValue() - ciIssuerCRLHTTP.getPercentCRLLifeRemaining();
			request.setAttribute("crlPercentUsedHTTP", crlRemaining);
		}
		else {
			request.setAttribute("issuerCRLHTTPRetrieved", false);
		}
		
		// -- LDAP CRL
		
		
		// check if we have intermediate cert
		// this logic doesn't work when the cert is cross signed!
		// much of this needs a rethink to build a better certificate chain
		if(ciIssuer != null) {
			// get the issuer of this cart (should be the root!
			error.append(getIssuerCert(ciIssuer));
		}

		// set attributes to return
		request.setAttribute("error", error.toString());

		request.setAttribute("certSerialNo", ci.getSerialNumber());
		request.setAttribute("issuedTo", ci.getSubjectDN());
		request.setAttribute("notBefore", ci.getNotBefore());
		request.setAttribute("notAfter", ci.getNotAfter());
		request.setAttribute("certIssuer", ci.getCertIssuer());

		request.setAttribute("ocsp", ci.getOCSPURL());
		request.setAttribute("CDPs", ci.getCDPLocations());
		request.setAttribute("CAIssuers", ci.getCAIssuers());

		request.setAttribute("certLenInDays", ci.getCertLenthInDays());
		request.setAttribute("numberOfDaysSinceIssued", ci.getNumberOfDaysSinceIssued());
		request.setAttribute("percentRemaining", ci.getPercentCertLifeRemaining());
		double remaining = ((Integer) 100).doubleValue() - ci.getPercentCertLifeRemaining();
		request.setAttribute("percentUsed", remaining);

		// Intermediate cert info
		request.setAttribute("issuserCACertName", ciIssuer.getSubjectDN());
		request.setAttribute("issuerCertSerialNo", ciIssuer.getSerialNumber());
		request.setAttribute("issuerIssuedTo", ciIssuer.getSubjectDN());
		request.setAttribute("issuerNotBefore", ciIssuer.getNotBefore());
		request.setAttribute("issuerNotAfter", ciIssuer.getNotAfter());
		request.setAttribute("issuerCertIssuer", ciIssuer.getCertIssuer());

		request.setAttribute("issuerocsp", ciIssuer.getOCSPURL());
		request.setAttribute("issuerCDPs", ciIssuer.getCDPLocations());
		request.setAttribute("issuerCAIssuers", ciIssuer.getCAIssuers());

		request.setAttribute("issuerCertLenInDays", ciIssuer.getCertLenthInDays());
		request.setAttribute("issuerNumberOfDaysSinceIssued", ciIssuer.getNumberOfDaysSinceIssued());

		remaining = 0;
		remaining = ((Integer) 100).doubleValue() - ciIssuer.getPercentCertLifeRemaining();
		request.setAttribute("ciIssuerRemaining", remaining);

		// Root CA Info
		// we need to deal with a cross signed cert.
		if( ciRootHTTP != null) {
		
			request.setAttribute("rootCACertName", ciRootHTTP.getSubjectDN());
			request.setAttribute("rootCertSerialNo", ciRootHTTP.getSerialNumber());
			request.setAttribute("rootIssuedTo", ciRootHTTP.getSubjectDN());
			request.setAttribute("rootNotBefore", ciRootHTTP.getNotBefore());
			request.setAttribute("rootNotAfter", ciRootHTTP.getNotAfter());
			request.setAttribute("rootCertIssuer", ciRootHTTP.getCertIssuer());

			request.setAttribute("rootrocsp", ciRootHTTP.getOCSPURL());
			request.setAttribute("rootCDPs", ciRootHTTP.getCDPLocations());
			request.setAttribute("rootCAIssuers", ciRootHTTP.getCAIssuers());

			request.setAttribute("rootCertLenInDays", ciRootHTTP.getCertLenthInDays());
			request.setAttribute("rootNumberOfDaysSinceIssued", ciRootHTTP.getNumberOfDaysSinceIssued());
			remaining = 0;
			remaining = ((Integer) 100).doubleValue() - ciRootHTTP.getPercentCertLifeRemaining();
			System.out.println("HTTP Root CA Cert Remaining: " + remaining);
			request.setAttribute("ciRootRemaining", remaining);

		}
		
		getServletContext().getRequestDispatcher("/index.jsp").forward(request, response);

	}

	private String getCertToWorkWith(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		// response.getWriter().append("doCertStuff");
		System.out.println("doCertStuff");
		StringBuilder error = new StringBuilder();
		// see if we can get the cert

		Part filePart = request.getPart("certFile");

		// make sure it's not null
		if (filePart == null || filePart.getSize() == 0) {
			// response.getWriter().append("Nothing sent<br>");
			error.append("No file was sent in the request...");
			return error.toString();
		}
		// setup to read in the bytes to convert to byte array
		byte[] certByteArray;
		InputStream fileContent = null;
		fileContent = filePart.getInputStream();
		int read = 0;
		final byte[] bytes = new byte[1024];
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();

		while ((read = fileContent.read(bytes)) != -1) {
			System.out.println("We're at: " + read);
			buffer.write(bytes, 0, read);
		}
		buffer.flush();
		certByteArray = buffer.toByteArray();

		if (certByteArray == null) {
			error.append("No file was provided...");
			return error.toString();

		}

		try {
			this.ci = new CertInfo(certByteArray);
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			error.append("There was an issue with the parsing of the cert file....");
			error.append(e.getMessage());
			e.printStackTrace();
		}

		return error.toString();
	}

	private String getIssuerCert(CertInfo ci) {
		// now the issuer
		StringBuilder error = new StringBuilder();

		// check to see if we have a cert info object for the first certificate
		if (ci != null) {
			System.out.println("Have ci now to see if we can get issuer cert");
			ArrayList<URI> cai = ci.getCAIssuers();
			for (int i = 0; i < cai.size(); i++) {
				URI uri = cai.get(i);
				System.out.println("uri to work this: " + uri.toString());

				if (uri.toString().startsWith("ldap")) {
					System.out.println("have a ldap URI");
					error.append( getIssuerCertificateLDAP(uri) );

				} else if (uri.toString().startsWith("http")) {
					System.out.println("have a http URI");
					error.append( getIssuerCertificateHTTP(uri));

				}
			}
			// getIssuerCertificate(ci.)
		} else {
			error.append("Get issuer cert - missing CertInfo for first certifiate");

		}
		return error.toString();
	}

	private String getIssuerCertificateHTTP(URI httpURI) {
		
		StringBuilder error = new StringBuilder();
		GetIssuerCertificateHTTP gic = new GetIssuerCertificateHTTP();
		byte[] caissuerByteArray = null;
		Certificate[] certs = null;
		
		try {
			caissuerByteArray = gic.getCertificateFromURI(httpURI);
		} catch (MalformedURLException e1) {
			error.append("Issue with getting certficate via HTTP. " + e1.getMessage());
			e1.printStackTrace();
		}
		catch (IOException ioe) {
			error.append("IOException - something went wrong, in this case it seems like a stuck redirect loop.");
			ioe.printStackTrace();
		}

		if (caissuerByteArray != null) {
			System.out.println("We have a byte Array!");
			System.out.println("Length of Cert Byte Array: " + caissuerByteArray.length);

			try {
				System.out.println("Now to call CertInfo");
				// this.ciIssuer = new CertInfo(caissuerByteArray);
				// this this for now
				CertInfo getCI = new CertInfo();
				// this needs to change!
				//TODO - this method needs to be changed/renamed to more generalised name.
				certs = getCI.readCertificatesFromPKCS7(caissuerByteArray);
				System.out.println("We have this many certs: " + certs.length);
				// taking out the length check as this should work for a single cert in the
				// array.
				if (certs != null) { // && certs.length > 1
					for (int j = 0; j < certs.length; j++) {
						X509Certificate x509 = (X509Certificate) certs[j];
						System.out.println("HTTP - x509 cert check: " + x509.getSubjectDN().toString() + " Issued by: " + x509.getIssuerDN().toString());
						//System.out.println("HTTP - The ciIssuser is: " + ciIssuer.getCertIssuer());
						/*
						 *  Here is where we need to look at the issuer of ciIsser to match a subject DN of these certs to find the right
						 *  parent signing CA that should then be the root? 
						 *  
						 *  ciIssuer must not be null - otherwise it's the first time through
						 */
						//if(x509.getSubjectDN().toString().equals(x509.getIssuerDN().toString())) {
						if( (
								ciIssuer != null 
								&& ciIssuer.getCertIssuer().equals(x509.getSubjectDN().toString()) 
							)
							|| x509.getSubjectDN().toString().equals(x509.getIssuerDN().toString()) 
								) {
							System.out.println("HTTP - The ciIssuser is: " + ciIssuer.getCertIssuer());
							
							System.out.println("HTTP - ciIssuer issuer matches this certs subjectDN - Get We have root CA Cert.");
							ciRootHTTP = new CertInfo(x509);
							continue;
						}
						else if (ci.getCertIssuer().equals(x509.getSubjectDN().toString())) {
							System.out.println("The cert subject DN matches the ee cert issuer: " + ci.getCertIssuer() + " - " + x509.getSubjectDN().toString());
							ciIssuer = new CertInfo(x509);
							continue;
						}
						else {
							System.out.println("HTTP - Nothing found.");
						}
					}
				}
			} catch (Exception e) {
				// TODO Auto-generated catch block
				error.append("getCertificateHTTP - error occured: " + e.getMessage());
				e.printStackTrace();
			}
			//System.out.println("The CA Issuer is: " + ciIssuer.getSubjectDN());
		}
		return error.toString();
	}
	
	private String getIssuerCertificateLDAP(URI ldapURI) {
		
		StringBuilder error = new StringBuilder();
		System.out.println("LDAP - LDAP URI: " + ldapURI.toString());
		
		GetIssuerCertificateLDAP ldapCert = new  GetIssuerCertificateLDAP();
		
		byte [] certByteArray = ldapCert.getCertificateByteArray(ldapURI);
		System.out.println("getIssuerCertificateLDAP - certByteArray size: " + certByteArray.length);
		// TODO This is not working correctly for finding the right intermediate and root
		try {
			CertInfo getCI = new CertInfo(certByteArray);
			System.out.println("LDAP - ci Cert Issuer: " + ci.getCertIssuer() + " getCI subjectDN: " + getCI.getSubjectDN() );
			// TODO this needs to be correct like the HTTP method
			//if( getCI.getSubjectDN().equals(getCI.getCertIssuer()) ) {
			if( (
					ciIssuerLDAP != null 
					&& ciIssuerLDAP.getCertIssuer().equals(getCI.getSubjectDN().toString()) 
				)
				|| getCI.getSubjectDN().toString().equals(getCI.getCertIssuer()) 
					) {
				System.out.println("LDAP - we have a root ca!");
				ciRootLDAP = getCI;
			}
			else if(ci.getCertIssuer().equals(getCI.getSubjectDN())  ){
				System.out.println("LDAP - we have the Certs issuer CA Cert: ");
				ciIssuerLDAP = getCI;
			}
			else {
				System.out.println("LDAP - Nothing found.");
			}
			System.out.println("LDAP CI is: " + ciIssuerLDAP.getSubjectDN());
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			error.append("There was an issue with getting the certiifcate via LDAP: " + e.getMessage());
			e.printStackTrace();
		}
		return error.toString();
	}
	
	private void getCertCRLHTTP(URI httpURI) {
		GetCRLHTTP crlHttp = new GetCRLHTTP(httpURI);
		try {
			byte [] crlByteArray = crlHttp.getCRLfromURL();
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			System.out.println("Issue with getting the CRL info for this URI: " + httpURI.toString());
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
	}

	
	/***
	 * CRL stuff now
	 */
	
	private void getIssuerCRLHTTP(URI httpURI) {
		
		// get the crl from HTTP 
		GetCRLHTTP getCrlHttp = new GetCRLHTTP(httpURI);
		byte[] crlByteArray;
		
		try {
			crlByteArray = getCrlHttp.getCRLfromURL();
			ciIssuerCRLHTTP = new CRLInfo(crlByteArray);
		} catch (MalformedURLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();

		} catch (CertificateException | CRLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();

		}
		
	}
	
	/*
	private void getIssuerCertifcate(URI issuerURI) {

		GetIssuerCertificateHTTP certHttp = new GetIssuerCertificateHTTP();

		byte[] issuerCert;
		try {
			issuerCert = certHttp.getCertificateFromURI(issuerURI);

			if (issuerCert == null) {
				System.out.println("No byte array returned for getHTTP");
		
			} else {
				ciIssuer = new CertInfo(issuerCert);
				System.out.println("Subject DN of ciIssuer: " + ciIssuer.getSubjectDN());
			}
		
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


	}
*/
	
/*
	private void showCertAttributes(HttpServletResponse resp) throws ServletException, IOException {

		// resp.getWriter().append("Show all<br>" + cert.toString() + "<br><br>");

		resp.getWriter().append("<br><b>Subject DN:</b> " + ci.getSubjectDN().toString() + "<br>");
		resp.getWriter().append("<b>Cert Serial Number:</b> " + ci.getSerialNumber().toString() + "<br>");
		resp.getWriter().append("<b>Valid From:</b> " + ci.getNotBefore().toString() + "<br>");
		resp.getWriter().append("<b>Valid To:</b> " + ci.getNotAfter().toString() + "<br>");
		resp.getWriter().append("<hr />");
		resp.getWriter().append("<b>AIA OCSP: </b>" + ci.getOCSPURL().toString() + "<br>");
		resp.getWriter().append("<b>AIA CA Issuers:</b>" + ci.getAIAURIs().toString() + "<br>");
		resp.getWriter().append("<b>CDP CRL Locations:</b>" + ci.getCDPLocations().toString() + "<br>");

		resp.getWriter().append("<hr />");

	}
*/
}
