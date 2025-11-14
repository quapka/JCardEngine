/*
 * Copyright 2012 Licel LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.licel.jcardsim.samples;

import javacard.framework.*;
import javacard.security.ECPublicKey;
import javacard.framework.ISO7816;
import javacard.security.KeyBuilder;

// import com.licel.jcardsim.jcmathlib.*;

/**
 * Basic SetPublicKey JavaCard Applet.
 *
 * @author LICEL LLC
 */
public class SetPublicKeyApplet extends Applet {

    /**
     * Instruction: say hello
     */
    private final static byte SAY_HELLO_INS = (byte) 0x01;
    /**
     * Instruction: say echo v2
     */
    private final static byte SAY_ECHO2_INS = (byte) 0x03;
    /**
     * Instruction: get install params
     */
    private final static byte SAY_IPARAMS_INS = (byte) 0x04;
    /**
     * Instruction: NOP
     */
    private final static byte NOP_INS = (byte) 0x02;
    /**
     * Instruction: queue data and return 61xx
     */
    private final static byte SAY_CONTINUE_INS = (byte) 0x06;
    /**
     * Instruction: CKYListObjects (http://pki.fedoraproject.org/images/7/7a/CoolKeyApplet.pdf 2.6.17)
     */
    private final static byte LIST_OBJECTS_INS = (byte) 0x58;
    /**
     * Instruction: "Hello Java Card world!" + Application Specific SW 9XYZ
     */
    private final static byte APPLICATION_SPECIFIC_SW_INS = (byte) 0x7;
    /**
     * Instruction: return maximum data.
     */
    private final static byte MAXIMUM_DATA_INS = (byte) 0x8;

    private final static byte SET_OIDC_PUBKEY = (byte) 0x9;
    public static final short uncompressPubKeySize = 65;
    private ECPublicKey OIDC_PUBLIC_KEY = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
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

    /**
     * Byte array representing "Hello Java Card world!" string.
     */
    private static byte[] helloMessage = new byte[]{
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, // "Hello "
            0x77, 0x6F, 0x72, 0x6C, 0x64, 0x20, 0x21 // "world !"
    };

    private byte[] echoBytes;
    private byte[] initParamsBytes;
    private final byte[] transientMemory;
    private static final short LENGTH_ECHO_BYTES = 256;
    public static boolean jcardengine = false;

    /**
     * Only this class's install method should create the applet object.
     *
     * @param bArray  the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray
     */
    protected SetPublicKeyApplet(byte[] bArray, short bOffset, byte bLength) {
        echoBytes = new byte[LENGTH_ECHO_BYTES];
        if (bLength > 0) {
            byte iLen = bArray[bOffset]; // aid length
            bOffset = (short) (bOffset + iLen + 1);
            byte cLen = bArray[bOffset]; // info length
            bOffset = (short) (bOffset + cLen + 1);
            byte aLen = bArray[bOffset]; // applet data length
            initParamsBytes = new byte[aLen];
            Util.arrayCopyNonAtomic(bArray, (short) (bOffset + 1), initParamsBytes, (short) 0, aLen);
        }
        transientMemory = JCSystem.makeTransientByteArray(LENGTH_ECHO_BYTES, JCSystem.CLEAR_ON_RESET);
        register();
    }

    /**
     * This method is called once during applet instantiation process.
     *
     * @param bArray  the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray
     * @throws ISOException if the install method failed
     */
    public static void install(byte[] bArray, short bOffset, byte bLength)
            throws ISOException {
        new SetPublicKeyApplet(bArray, bOffset, bLength);
    }

    @Override
    public boolean select() {
        return jcardengine;
    }

    /**
     * This method is called each time the applet receives APDU.
     */
    public void process(APDU apdu) {
        // good practice
        if (selectingApplet()) return;
        byte[] buffer = apdu.getBuffer();
        // Now determine the requested instruction:
        switch (buffer[ISO7816.OFFSET_INS]) {
            case SAY_HELLO_INS:
                sayHello(apdu, (short) 0x9000);
                return;
            case SAY_ECHO2_INS:
                sayEcho2(apdu);
                return;
            case SAY_IPARAMS_INS:
                sayIParams(apdu);
                return;
            case SAY_CONTINUE_INS:
                sayContinue(apdu);
                return;
            case LIST_OBJECTS_INS:
                listObjects(apdu);
                return;
            case APPLICATION_SPECIFIC_SW_INS:
                sayHello(apdu, (short) 0x9B00);
                return;
            case MAXIMUM_DATA_INS:
                maximumData(apdu);
                return;
            case NOP_INS:
                return;
            case SET_OIDC_PUBKEY:
                setOIDCPublicKey(apdu);
                break;
            default:
                // We do not support any other INS values
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * Sends hello message to host using given APDU.
     *
     * @param apdu APDU that requested hello message
     * @param sw   response sw code
     */
    private void sayHello(APDU apdu, short sw) {
        // Here all bytes of the APDU are stored
        byte[] buffer = apdu.getBuffer();
        // receive all bytes
        // if P1 = 0x01 (echo)
        short incomeBytes = apdu.setIncomingAndReceive();
        byte[] echo = transientMemory;
        short echoLength;
        if (buffer[ISO7816.OFFSET_P1] == 0x01) {
            echoLength = incomeBytes;
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, echo, (short) 0, incomeBytes);
        } else {
            echoLength = (short) helloMessage.length;
            Util.arrayCopyNonAtomic(helloMessage, (short) 0, echo, (short) 0, (short) helloMessage.length);
        }
        // Tell JVM that we will send data
        apdu.setOutgoing();
        // Set the length of data to send
        apdu.setOutgoingLength(echoLength);
        // Send our message starting at 0 position
        apdu.sendBytesLong(echo, (short) 0, echoLength);
        // Set application specific sw
        if (sw != ISO7816.SW_NO_ERROR) {
            ISOException.throwIt(sw);
        }
    }


    /**
     * echo v2
     */
    private void sayEcho2(APDU apdu) {
        byte buffer[] = apdu.getBuffer();

        short bytesRead = apdu.setIncomingAndReceive();
        short echoOffset = (short) 0;

        while (bytesRead > 0) {
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, echoBytes, echoOffset, bytesRead);
            echoOffset += bytesRead;
            bytesRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }

        apdu.setOutgoing();
        apdu.setOutgoingLength(echoOffset);
        // echo data
        apdu.sendBytesLong(echoBytes, (short) 0, echoOffset);

    }

    /**
     * echo install params
     */
    private void sayIParams(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) initParamsBytes.length);
        // echo install parmas
        apdu.sendBytesLong(initParamsBytes, (short) 0, (short) initParamsBytes.length);
    }

    /**
     * send some hello data, and indicate there's more
     */
    private void sayContinue(APDU apdu) {
        byte[] echo = transientMemory;
        short echoLength = (short) 6;
        Util.arrayCopyNonAtomic(helloMessage, (short) 0, echo, (short) 0, (short) 6);
        apdu.setOutgoing();
        apdu.setOutgoingLength(echoLength);
        apdu.sendBytesLong(echo, (short) 0, echoLength);
        ISOException.throwIt((short) (ISO7816.SW_BYTES_REMAINING_00 | 0x07));
    }


    /**
     * send the maximum amount of data the apdu will accept
     *
     * @param apdu APDU that requested hello message
     */
    private void maximumData(APDU apdu) {
        short maxData = APDU.getOutBlockSize();
        byte[] buffer = apdu.getBuffer();
        Util.arrayFillNonAtomic(buffer, (short) 0, maxData, (byte) 0);
        apdu.setOutgoingAndSend((short) 0, maxData);
    }

    // prototype
    private void listObjects(APDU apdu) {
        byte buffer[] = apdu.getBuffer();

        if (buffer[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt((short) 0x9C11);
        }

        byte expectedBytes = buffer[ISO7816.OFFSET_LC];

        if (expectedBytes < 14) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        ISOException.throwIt((short) 0x9C12);
    }

    private void setOIDCPublicKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short offset = 0;
        OIDC_PUBLIC_KEY.setFieldFP(SecP256r1.p, offset, (short) SecP256r1.p.length);
        OIDC_PUBLIC_KEY.setA(SecP256r1.a, offset, (short) SecP256r1.a.length);
        OIDC_PUBLIC_KEY.setB(SecP256r1.b, offset, (short) SecP256r1.b.length);
        OIDC_PUBLIC_KEY.setG(SecP256r1.G, offset, (short) SecP256r1.G.length);
        OIDC_PUBLIC_KEY.setR(SecP256r1.r, offset, (short) SecP256r1.r.length);
        OIDC_PUBLIC_KEY.setK(SecP256r1.k);
        for (short i = ISO7816.OFFSET_CDATA; i < ISO7816.OFFSET_CDATA + uncompressPubKeySize; i++) {
            System.out.print(String.format("%02X", buffer[i]));
        }
        System.out.println();
        OIDC_PUBLIC_KEY.setW(buffer, (short) ISO7816.OFFSET_CDATA, uncompressPubKeySize);
        // OIDC_PUBLIC_KEY.setW(testPubKeyBytes, (short) 0, (short) uncompressPubKeySize);

        getOIDCPublicKey(apdu);
    }

    private void getOIDCPublicKey(APDU apdu) {
        short keySize = OIDC_PUBLIC_KEY.getW(apdu.getBuffer(), (short) 0);
        apdu.setOutgoingAndSend((short) 0, keySize);
    }

    public static class SecP256r1 {
        public final static short k = 1;

        public final static byte[] p = {
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff
        };

        public final static byte[] a = {
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfc
        };

        public final static byte[] b = {
                (byte) 0x5a, (byte) 0xc6, (byte) 0x35, (byte) 0xd8,
                (byte) 0xaa, (byte) 0x3a, (byte) 0x93, (byte) 0xe7,
                (byte) 0xb3, (byte) 0xeb, (byte) 0xbd, (byte) 0x55,
                (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xbc,
                (byte) 0x65, (byte) 0x1d, (byte) 0x06, (byte) 0xb0,
                (byte) 0xcc, (byte) 0x53, (byte) 0xb0, (byte) 0xf6,
                (byte) 0x3b, (byte) 0xce, (byte) 0x3c, (byte) 0x3e,
                (byte) 0x27, (byte) 0xd2, (byte) 0x60, (byte) 0x4b
        };

        public final static byte[] G = {
                (byte) 0x04,
                (byte) 0x6b, (byte) 0x17, (byte) 0xd1, (byte) 0xf2,
                (byte) 0xe1, (byte) 0x2c, (byte) 0x42, (byte) 0x47,
                (byte) 0xf8, (byte) 0xbc, (byte) 0xe6, (byte) 0xe5,
                (byte) 0x63, (byte) 0xa4, (byte) 0x40, (byte) 0xf2,
                (byte) 0x77, (byte) 0x03, (byte) 0x7d, (byte) 0x81,
                (byte) 0x2d, (byte) 0xeb, (byte) 0x33, (byte) 0xa0,
                (byte) 0xf4, (byte) 0xa1, (byte) 0x39, (byte) 0x45,
                (byte) 0xd8, (byte) 0x98, (byte) 0xc2, (byte) 0x96,
                (byte) 0x4f, (byte) 0xe3, (byte) 0x42, (byte) 0xe2,
                (byte) 0xfe, (byte) 0x1a, (byte) 0x7f, (byte) 0x9b,
                (byte) 0x8e, (byte) 0xe7, (byte) 0xeb, (byte) 0x4a,
                (byte) 0x7c, (byte) 0x0f, (byte) 0x9e, (byte) 0x16,
                (byte) 0x2b, (byte) 0xce, (byte) 0x33, (byte) 0x57,
                (byte) 0x6b, (byte) 0x31, (byte) 0x5e, (byte) 0xce,
                (byte) 0xcb, (byte) 0xb6, (byte) 0x40, (byte) 0x68,
                (byte) 0x37, (byte) 0xbf, (byte) 0x51, (byte) 0xf5
        };

        public final static byte[] r = {
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xbc, (byte) 0xe6, (byte) 0xfa, (byte) 0xad,
                (byte) 0xa7, (byte) 0x17, (byte) 0x9e, (byte) 0x84,
                (byte) 0xf3, (byte) 0xb9, (byte) 0xca, (byte) 0xc2,
                (byte) 0xfc, (byte) 0x63, (byte) 0x25, (byte) 0x51
        };
    }

}
