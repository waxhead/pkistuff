/**
 * 
 */
package com.sspl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
/**
 * @author pete
 *
 */
public class CertInfo {

	//final static Logger logger = LogManager.getLogger(CertInfo.class);
	
	private X509Certificate cert;

	private URL OCSPURL;
	//private ArrayList<URI> AIAURIs = new ArrayList<URI>();
	private ArrayList<URI> CDPURIs = new ArrayList<URI>();
	private ArrayList<URI> CAIssuers = new ArrayList<URI>();
	private HashMap<String, ArrayList<URI>> AIAURIs = new HashMap<String, ArrayList<URI> >();
	
	private long lengthOfCertInDays;
	private long numberOfDaysSinceIssued;
	private long numberOfDaysRemaining;

	/*
	 * References: 
	 * Handle p7b: (this is what is returned from Defence as it's cross signed
	 * https://stackoverflow.com/questions/57872058/how-to-read-a-p7b-file-programmatically-in-java 
	 */
	
	
	/**
	 * 
	 */
	
	public CertInfo() {
		// place holder for now to call this and work with other methods
		
	}
	public CertInfo(byte[] certificate) throws CertificateException {
		// TODO Auto-generated constructor stub
		System.out.println("Incoming byteArray");
		System.out.println("CertInfo() - Size of incoming byte array: " + certificate.length);
		try { 
			cert = parseCertFile(certificate);
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			System.out.println("CertInfo() - exception: " + e.getMessage());
			e.printStackTrace();
		}
		
		// call the cert parsing
		this.getURIsFromAIA();
		this.getURIsFromCDP();
		this.getCertDaysInfo();
	}
	public CertInfo(X509Certificate x509) throws CertificateException {
		cert = x509;
		System.out.println("CertInfo(x509) called");
		System.out.println("CertInfo(x509) - " + cert.getSubjectDN().toString());
		// call the cert parsing
		
		// hanlde a root Cert where AIA doesn't get set
		if(! cert.getSubjectDN().toString().equals(cert.getIssuerDN().toString())) {
			System.out.println("This is a root cert so not getting AIA");
			this.getURIsFromAIA();
			this.getURIsFromCDP();
		}
		this.getCertDaysInfo();
	}

	// getters Setters
	public X509Certificate getX509() {
		return cert;
	}

	public void setX509(byte[] inByteArray) throws CertificateException {

		this.cert = this.parseCertFile(inByteArray);

	}

	public URL getOCSPURL() {
		return OCSPURL;
	}
	public ArrayList<URI> getCAIssuers() {
		return CAIssuers;
	}
	public HashMap<String, ArrayList<URI>> getAIAURIs() {
		return AIAURIs;
	}
	public ArrayList<URI> getCDPLocations() {
		return CDPURIs;
	}
	public String getSubjectDN() {
		return cert.getSubjectDN().toString();
	}

	public String getCertIssuer() {
		return cert.getIssuerDN().toString();
	}
	public Date getNotBefore() {
		return cert.getNotBefore();
	}

	
	public Date getNotAfter() {
		return cert.getNotAfter();
	}
	
	public BigInteger getSerialNumber() {
		return cert.getSerialNumber();
	}

	public double getPercentCertLifeRemaining() {
		return this.getPercentCertLifeLeft();
	}
	public long getCertLenthInDays() {
		return lengthOfCertInDays;
	}
	public long getNumberOfDaysSinceIssued() {
		return numberOfDaysSinceIssued;
	}
	
	
	public Certificate[] readCertificatesFromPKCS7(byte[] binaryPKCS7Store) throws Exception
	{
	    try (ByteArrayInputStream bais = new ByteArrayInputStream(binaryPKCS7Store);)
	    {
	        CertificateFactory cf = CertificateFactory.getInstance("X.509");
	        Collection<?> c = cf.generateCertificates(bais);

	        List<Certificate> certList = new ArrayList<Certificate>();

	        if (c.isEmpty())
	        {
	            // If there are now certificates found, the p7b file is probably not in binary format.
	            // It may be in base64 format.
	            // The generateCertificates method only understands raw data.
	        	System.out.println("readCertificatesFromPKCS7() - There are no certificates here.");
	        }
	        else
	        {

	            Iterator<?> i = c.iterator();

	            while (i.hasNext())
	            {
	                certList.add((Certificate) i.next());
	            }
	        }

	        java.security.cert.Certificate[] certArr = new java.security.cert.Certificate[certList.size()];

	        return certList.toArray(certArr);
	    }
	}
	
	
	
	//------
	private double getPercentCertLifeLeft() {
		
		//TODO - Clean this up since we are calling the other method to set the day info
		
		//DateTimeFormatter dtf = DateTimeFormatter.ISO_DATE_TIME;

		LocalDateTime now = LocalDateTime.now();
		LocalDateTime from = cert.getNotBefore().toInstant()
			      .atZone(ZoneId.systemDefault())
			      .toLocalDateTime();
		LocalDateTime to = cert.getNotAfter().toInstant()
			      .atZone(ZoneId.systemDefault())
			      .toLocalDateTime();
		//LocalDateTime from = LocalDateTime.parse(cert.getNotBefore().toString(), dtf);
		//LocalDateTime to = LocalDateTime.parse(cert.getNotAfter().toString(), dtf);
		
		lengthOfCertInDays = Duration.between(from, to).toDays();
		
		long daysLeft = Duration.between(now, to).toDays();

		//System.out.println("Number of Days left: " + daysLeft );
		//System.out.println("Number of Days for cert: " + lengthOfCertInDays );
		
		double percentLeft = (((Long)daysLeft).doubleValue()/((Long)lengthOfCertInDays).doubleValue()) * 100;
		
		//System.out.println("Percent left before rounding:  " +  percentLeft);
		return Math.round(percentLeft);
		
	}
	/*
	 * Use this method to get all the day based info for the class
	 */
	private void getCertDaysInfo() {
		//DateTimeFormatter dtf = DateTimeFormatter.ISO_DATE_TIME;
		LocalDateTime now = LocalDateTime.now();
		LocalDateTime from = cert.getNotBefore().toInstant()
			      .atZone(ZoneId.systemDefault())
			      .toLocalDateTime();
		LocalDateTime to = cert.getNotAfter().toInstant()
			      .atZone(ZoneId.systemDefault())
			      .toLocalDateTime();
	
		/*
		LocalDateTime from = LocalDateTime.parse(cert.getNotBefore().toString(), dtf);
		LocalDateTime to = LocalDateTime.parse(cert.getNotAfter().toString(), dtf);
		 */
		lengthOfCertInDays = Duration.between(from, to).toDays();
		numberOfDaysSinceIssued = Duration.between(from, now).toDays();
		System.out.println("numberofdaysSinceIssued: " + numberOfDaysSinceIssued );
		numberOfDaysRemaining = Duration.between(now, to).toDays();
	}
	
	private void getURIsFromAIA() {
		// Need to set up logging!

		/*
		 * This is how I finally figured out how ot do this part.
		 * Example 7.
		 * https://www.programcreek.com/java-api-examples/?api=org.bouncycastle.asn1.x509.AuthorityInformationAccess
		 * 
		 */
		
		// no AIA's in a root!
		if( cert.getExtensionValue(Extension.authorityInfoAccess.getId()) == null ) {
			System.out.println("CertInfo() - getURIsFromAIA() - This is a root cert no AIA");
			return;
		}
		
		
		byte[] bOctets;
		AuthorityInformationAccess aia;
		try {
			bOctets = ((ASN1OctetString) ASN1Primitive.fromByteArray(
					cert.getExtensionValue(Extension.authorityInfoAccess.getId()))).getOctets();
			
			aia =  AuthorityInformationAccess.getInstance(ASN1Sequence.fromByteArray(bOctets));

			URI uri;

			for (int i = 0; i < aia.getAccessDescriptions().length; i++) {
				AccessDescription ad = aia.getAccessDescriptions()[i];

				if (ad.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
					GeneralName gn = ad.getAccessLocation();
					System.out.println("Have OCSP");
					if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
						System.out.println("Have OCSP URI");
						String ocsp = ((ASN1String) gn.getName()).getString();
						
						System.out.println("OCSP from AIA: " + ocsp);

						try {
							uri = new URI(ocsp);
							// handle hashmp arraylist value
							if( AIAURIs.get("ocsp") == null ) {
								AIAURIs.put("ocsp", new ArrayList<URI>());
							}
							AIAURIs.get("ocsp").add(uri);	
							OCSPURL = uri.toURL();
						} catch (URISyntaxException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (MalformedURLException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					continue;
				}
				if (ad.getAccessMethod().equals(AccessDescription.id_ad_caIssuers)) {
					System.out.println("Have CA Issuer");
					GeneralName gn = ad.getAccessLocation();
					// resp.getWriter().append("<b>CA Issuer:</b> " + gn.getName() + "<br>");
					if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
						String ca = ((ASN1String) gn.getName()).getString();
						System.out.println("CA Issuer from AIA: " + ca);
						
						try {
							uri = new URI(ca);
							//System.out.println("CA Issuer from AIA as URI: " + ca.toString());
							CAIssuers.add(uri);
							// not sure if this is really any value
							if( AIAURIs.get("caissuers") == null) {
								AIAURIs.put("caissuers", new ArrayList<URI>());
							}
							AIAURIs.get("caissuers").add(uri);
						} catch (URISyntaxException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					continue;

				}
			}

		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	}

	private void getURIsFromCDP() {

		byte[] bOctets;
		CRLDistPoint cdlDistPoints;
		
		if( cert.getExtensionValue(Extension.cRLDistributionPoints.getId()) == null ) {
			System.out.println("CertInfo() - getURIsFromCDP() - root cert No CDPs");
			return;
		}
		
		try {
			bOctets = ((ASN1OctetString) ASN1Primitive.fromByteArray(
					this.cert.getExtensionValue(Extension.cRLDistributionPoints.getId()))).getOctets();
			
			cdlDistPoints = CRLDistPoint.getInstance(bOctets);
			for (DistributionPoint dp : cdlDistPoints.getDistributionPoints()) {
				// resp.getWriter().append("<br>Might have DP: " + dp.toString() + "<br>");

				DistributionPointName dpn = dp.getDistributionPoint();
				if (dpn != null) {
					if (dpn.getType() == DistributionPointName.FULL_NAME) {
						GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
						for (GeneralName genName : genNames) {
							if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
								String uriStr = DERIA5String.getInstance(genName.getName()).getString();

								URI uri;
								try {
									uri = new URI(uriStr);
									CDPURIs.add(uri);
								} catch (URISyntaxException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
							}
						}
					}
				}
			}
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		

	}

	// need to change this to return  a certificate array
	private X509Certificate parseCertFile(byte[] inFile) throws CertificateException {

		// need an inputstream from the incomfing byte []
		InputStream in = new ByteArrayInputStream(inFile);

		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		X509Certificate x509 = (X509Certificate) certFactory.generateCertificate(in);

		return x509;

	}

	
	private void getIssuerCertificate() {
		// get Authority Information Access extension (will be null if extension is not
		// present)

		System.out.println("In getIssuerCertificate");
		// resp.getWriter().append("In getIssuerCertificate<br>");
		// resp.getWriter().append("see if we can get issuernames<br>");
		try {
			final Collection<List<?>> altNames = cert.getIssuerAlternativeNames();

			if (altNames != null) {
				System.out.println("altNames is not null");
				final List<String> issuerNames = new ArrayList<String>();
				for (final List<?> aC : altNames) {
					if (!aC.isEmpty()) {
						issuerNames.add((String) aC.get(1));
					}

					// resp.getWriter().append("IssuerNames: " + issuerNames.toString() + "<br>");
				}

			} else {
				// resp.getWriter().append("No Issuer Alt Names found<br>");
			}

		} catch (CertificateParsingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

}
