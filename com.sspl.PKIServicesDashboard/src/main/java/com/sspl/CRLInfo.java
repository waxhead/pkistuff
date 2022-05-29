package com.sspl;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

public class CRLInfo {

	private X509CRL crl;
	private long lengthOfCRLInDays;
	private long numberOfDaysSinceIssued;
	private long numberOfDaysRemaining;
	
	
	public CRLInfo() {
		// TODO Auto-generated constructor stub
	}
	public CRLInfo (byte [] crlBytes ) throws CertificateException, CRLException {
		
		try {
			crl = parseCRL(crlBytes);
			getCRLDaysInfo();
			
		} catch (CertificateException | CRLException e) {
			// TODO Auto-generated catch block
			System.out.println("Problem with the incoming bytes to CRL");
			System.out.println(e.getMessage());
			e.printStackTrace();
			throw e;
		}
		
	}
	/*
	pubic CRLInfo(X509CRL crlIn) {
		
	}
	*/
	
	public String getIssuerDN() {
		return crl.getIssuerDN().toString();
	}
	public Date getNextUpdate() {
		return crl.getNextUpdate();
	}
	
	public Date getThisUpdate() {
		return crl.getThisUpdate();
	}
	
	public boolean isRevoked(X509Certificate cert) {
		return crl.isRevoked(cert);
	}

	public double getPercentCRLLifeRemaining() {
		return this.getPercentCRLLifeLeft();
	}
	public long getCRLLenthInDays() {
		return lengthOfCRLInDays;
	}
	public long getNumberOfDaysSinceIssued() {
		return numberOfDaysSinceIssued;
	}
	
	private X509CRL parseCRL(byte [] crlBytesIn) throws CertificateException, CRLException {
		
		InputStream in = new ByteArrayInputStream(crlBytesIn);
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		X509CRL c = (X509CRL) certFactory.generateCRL(in);
		return c;
		
	}
	
	private double getPercentCRLLifeLeft() {
		
		//TODO - Clean this up since we are calling the other method to set the day info
		
		//DateTimeFormatter dtf = DateTimeFormatter.ISO_DATE_TIME;

		LocalDateTime now = LocalDateTime.now();
		LocalDateTime from = crl.getThisUpdate().toInstant()
			      .atZone(ZoneId.systemDefault())
			      .toLocalDateTime();
		LocalDateTime to = crl.getNextUpdate().toInstant()
			      .atZone(ZoneId.systemDefault())
			      .toLocalDateTime();
		//LocalDateTime from = LocalDateTime.parse(cert.getNotBefore().toString(), dtf);
		//LocalDateTime to = LocalDateTime.parse(cert.getNotAfter().toString(), dtf);
		
		lengthOfCRLInDays = Duration.between(from, to).toDays();
		
		long daysLeft = Duration.between(now, to).toDays();

		//System.out.println("Number of Days left: " + daysLeft );
		//System.out.println("Number of Days for cert: " + lengthOfCertInDays );
		
		double percentLeft = (((Long)daysLeft).doubleValue()/((Long)lengthOfCRLInDays).doubleValue()) * 100;
		
		//System.out.println("Percent left before rounding:  " +  percentLeft);
		return Math.round(percentLeft);
		
	}
	
	/*
	 * Use this method to get all the day based info for the class
	 */
	private void getCRLDaysInfo() {
		//DateTimeFormatter dtf = DateTimeFormatter.ISO_DATE_TIME;
		LocalDateTime now = LocalDateTime.now();
		LocalDateTime from = crl.getThisUpdate().toInstant()
			      .atZone(ZoneId.systemDefault())
			      .toLocalDateTime();
		LocalDateTime to = crl.getNextUpdate().toInstant()
			      .atZone(ZoneId.systemDefault())
			      .toLocalDateTime();
	
		/*
		LocalDateTime from = LocalDateTime.parse(cert.getNotBefore().toString(), dtf);
		LocalDateTime to = LocalDateTime.parse(cert.getNotAfter().toString(), dtf);
		 */
		lengthOfCRLInDays = Duration.between(from, to).toDays();
		numberOfDaysSinceIssued = Duration.between(from, now).toDays();
		System.out.println("numberofdaysSinceIssued: " + numberOfDaysSinceIssued );
		numberOfDaysRemaining = Duration.between(now, to).toDays();
	}
	
	

}
