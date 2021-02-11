package com.cyberneid.disigon.sdk.examples;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

import com.cyberneid.disigon.sdk.CACertStore;
import com.cyberneid.disigon.sdk.Disigon;
import com.cyberneid.disigon.sdk.P11Signer;
import com.cyberneid.disigon.sdk.P12Signer;
import com.cyberneid.disigon.sdk.P7MDocument;
import com.cyberneid.disigon.sdk.SimpleCertSelector;
import com.cyberneid.disigon.sdk.util.FileUtil;
import com.qequipe.p11.Certificate;

public class CAdESWithPKCS11Token {

	static boolean CERTIFICATE_BY_PATH = true;
	
	public static void main(String args[])
    {    	
    	// the input file
		String input = "test.txt";
		
		// the output file
		String output = "test.p7m";
		
		// the token pin
		String pin = "12345678";
		
		System.out.println("DISIGON version: " + Disigon.VERSION);
		
		// set true to add the CA certificate to the p7m
		Disigon.setAddCACertificate(true);
		
		// set licensee and product key
		// contact us at https://www.cyberneid.com to get a lincese key
		Disigon.setLicense("<licensee>", "<productkey>");
		
		
		try
		{
			// creates a new instance of P11Signer with the given pkcs11 module
			// you may specify your own PKCS#11 dll
			P11Signer dsign = new P11Signer("bit4xpki");
	
			// open a new session with the HSM
			dsign.open();

			// determine how many active slots are available
			int slotCount = dsign.getSlotsCount(true);		
			System.out.println("slot count: " + slotCount);
			
			// specify the slot 0. Change the index if you want to use another slot
			dsign.setSlot(0);
			
			// login
			dsign.login(pin);

							
			FileInputStream inputFileStream = new FileInputStream(input);
			ByteArrayOutputStream bouts = new ByteArrayOutputStream();
			FileUtil.copy(inputFileStream, bouts);
			
			P7MDocument signedDocument = dsign.sign(bouts.toByteArray(), new SimpleCertSelector(true), true, false, false);
		
			FileOutputStream fouts = new FileOutputStream(output);
			
			fouts.write(signedDocument.toDER());
			fouts.close();
			
			System.out.println("done");
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		} 
    }
}
