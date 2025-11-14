package com.licel.jcardsim;

import com.licel.jcardsim.samples.SetPublicKeyApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.licel.jcardsim.utils.ByteUtil;
import javacard.framework.AID;
import org.junit.jupiter.api.Test;

import javax.smartcardio.*;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Contains all listing from the documentation
 */
public class SetPublicKeyTest implements SmartCardTest {

    private byte[] testPubKeyBytes = {
        (byte) 0x04, (byte) 0x7C, (byte) 0x15, (byte) 0x8D, (byte) 0x86, (byte) 0xEA, (byte) 0xD9,
        (byte) 0x40, (byte) 0xA1, (byte) 0x32, (byte) 0xCA, (byte) 0xC3, (byte) 0xE5, (byte) 0x11,
        (byte) 0xFE, (byte) 0xF6, (byte) 0xE3, (byte) 0x39, (byte) 0x8C, (byte) 0xAE, (byte) 0xE6,
        (byte) 0x8D, (byte) 0x4A, (byte) 0x5A, (byte) 0x84, (byte) 0x2C, (byte) 0xF3, (byte) 0x3E,
        (byte) 0x1A, (byte) 0x6A, (byte) 0x0D, (byte) 0xF9, (byte) 0x64, (byte) 0x0A, (byte) 0x2A,
        (byte) 0xA3, (byte) 0x9B, (byte) 0xD5, (byte) 0x2B, (byte) 0xB5, (byte) 0x2F, (byte) 0xDA,
        (byte) 0x6C, (byte) 0xED, (byte) 0x68, (byte) 0x92, (byte) 0x54, (byte) 0xC0, (byte) 0x9E,
        (byte) 0xEF, (byte) 0xE1, (byte) 0xD8, (byte) 0x93, (byte) 0x64, (byte) 0x46, (byte) 0x80,
        (byte) 0x49, (byte) 0x49, (byte) 0xF7, (byte) 0x48, (byte) 0xD5, (byte) 0xC0, (byte) 0x2B,
        (byte) 0xA6, (byte) 0x53, 
    };

    @Test
    public void testCodeListingReadme() {
        // setup
        CardSimulator simulator = new CardSimulator();

        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, SetPublicKeyApplet.class);

        simulator.selectApplet(appletAID);

        // Send a test public key into the JavaCard
        CommandAPDU commandAPDU = new CommandAPDU(0x00, 0x09, 0x00, 0x00, testPubKeyBytes);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        // And expect the same public key in return
        assertSW(0x9000, response.getSW());
        assertArrayEquals(testPubKeyBytes, response.getData());
    }
}
