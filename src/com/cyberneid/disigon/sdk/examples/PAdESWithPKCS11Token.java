package com.cyberneid.disigon.sdk.examples;

import java.io.FileInputStream;
import java.io.FileOutputStream;

import com.cyberneid.disigon.sdk.Disigon;
import com.cyberneid.disigon.sdk.P11Signer;
import com.cyberneid.disigon.sdk.PAdESGenerator;
import com.cyberneid.disigon.sdk.SimpleCertSelector;

/**
 *  @author UgoChirico
 *  https://www.ugochirico.com
 *  https://www.cyberneid.com
 */
public class PAdESWithPKCS11Token {

	static boolean CERTIFICATE_BY_PATH = true;
	
	public static void main(String args[])
    {    	
    	// the input file
		String input = "TestFEA.pdf";
		
		// the token pin
		String pin = "11223344";
		
		System.out.println("DISIGON version: " + Disigon.VERSION);
		
		// set true to add the CA certificate to the p7m
		Disigon.setAddCACertificate(true);
		
		// set licensee and product key
		// contact us at https://www.cyberneid.com to get a lincese key
		Disigon.setLicense("<licensee>", "<productkey>1");
		
		
		try
		{
			// creates a new instance of P11Signer with the given pkcs11 module
			// you may specify your own PKCS#11 dll
			P11Signer dsign = new P11Signer("/Library/bit4id/pkcs11/libbit4xpki.dylib");
	
			// open a new session with the HSM
			dsign.open();

			// determine how many active slots are available
			int slotCount = dsign.getSlotsCount(true);		
			System.out.println("slot count: " + slotCount);
			
			// specify the slot 0. Change the index if you want to use another slot
			dsign.setSlot(0);
			
			// login
			dsign.login(pin);

			// PAdES generator
			PAdESGenerator pdfSignGen = new PAdESGenerator();
			
			FileInputStream fins = new FileInputStream(input);
			pdfSignGen.load(fins);
			fins.close();				
						
			// visible Signature 
			// la posizione e le dimensioni sono espressi in percentuale (con valori tra 0 e 1) rispetto alle dimensioni della pagina			
			float x = 0.8f;
			float y = 0.1f;
			float w = 0.2f;
			float h = 0.2f;
			
			int page = 0;
						
			// init the pdf signature
			pdfSignGen.init(page, x, y, w, h, null, null, null, null, "Signature" + System.currentTimeMillis(), "ETSI.CAdES.detached", null);
	
			byte signedPDF[] = pdfSignGen.signPDF(dsign, new SimpleCertSelector(true), true, false, null);
			
			String outputFile = "signed_" + input;
			
			FileOutputStream fouts = new FileOutputStream(outputFile);
			fouts.write(signedPDF);
			fouts.close();
			
			fins.close();
			
			// closes the session
			dsign.close();
	
			System.out.println("done");
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		} 
    }
}
