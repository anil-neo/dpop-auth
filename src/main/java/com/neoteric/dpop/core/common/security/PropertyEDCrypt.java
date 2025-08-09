package com.neoteric.dpop.core.common.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.encrypt.Encryptors;

import java.nio.charset.StandardCharsets;
import java.util.Scanner;

@Slf4j
public class PropertyEDCrypt {

    /**
     * Method to decrypt encrypted properties.
     *
     * @param encryptedStr encryptedProperty
     * @param key          masterKey
     * @param salt         salt
     * @return decryptedString
     */
    public static String decrypt(String encryptedStr, String key, String salt) {
        return Encryptors.text(key, salt).decrypt(encryptedStr);
    }

    public static String encrypt(String plainStr, String key, String salt) {
        return Encryptors.text(key, salt).encrypt(plainStr);
    }

    public static void main(String[] args) {
        usage();
        System.out.print("Please enter your option ==> ");
        Scanner in = new Scanner(System.in, String.valueOf(StandardCharsets.UTF_8));
        options(in.nextLine(), in);
    }

    //eee0a99f400708171e1a6ad0b32b9bde19c8b35b0e8cf01b5bce076c962c7951
    private static void usage() {
        System.out.println("*****************************************************");
        System.out.println("For Encryption enter e or E *************************");
        System.out.println("For Decryption enter d or D *************************");
        System.out.println("To exit the program press x *************************");
    }

    private static void options(String option, Scanner in) {
        switch (option) {
            case "e", "E":
                do {
                    encryptFromCmdLine(in);
                } while (!in.nextLine().equalsIgnoreCase("x"));
            case "d", "D":
                do {
                    decryptFromCmdLine(in);
                } while (!in.nextLine().equalsIgnoreCase("x"));
            case "x", "X":
                System.out.println("Exiting *************************");
                System.exit(0);
            default:
                System.out.println("Wrong option. See the usage!");
                usage();
        }
    }

    public static void encryptFromCmdLine(Scanner in) {
        System.out.print("Enter the value to encrypt **********=> ");
        String plainTxt = in.nextLine();
        System.out.print("Enter the key ***********************=> ");
        String masterKey = in.nextLine();
        System.out.print("Enter the salt **********************=> ");
        String salt = in.nextLine();
        String encryptedStr = encrypt(plainTxt, masterKey, salt);
        System.out.println("Encrypted String::: " + encryptedStr);
    }

    public static void decryptFromCmdLine(Scanner in) {
        System.out.print("Enter the value to decrypt ************=> ");
        String plainTxt = in.nextLine();
        System.out.print("Enter the key ***********************=> ");
        String masterKey = in.nextLine();
        System.out.print("Enter the salt **********************=> ");
        String salt = in.nextLine();
        String decryptedStr = decrypt(plainTxt, masterKey, salt);
        System.out.println("Decrypted String::: " + decryptedStr);
    }

}