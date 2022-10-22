
import BCrypt.java.BCrypt;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import java.security.*;

public class UE {


        private static Boolean finished = false;
        private static Boolean isMatching = false;
        private static String algorithm = "";
        private static String foundPW = "";

        public static void main(String[] args) throws NoSuchAlgorithmException, FileNotFoundException {

            System.out.println("UE1 1 Teil 1");
            System.out.print("Bitte dein PW eingeben:  ");
            Scanner sc = new Scanner(System.in);
            String passwordputted = sc.nextLine();

            // open Methods here
            md5(passwordputted);
            sha256(passwordputted);
            sha256Salt(passwordputted);
                bcrypt(passwordputted);



            System.out.println("UE 1 Teil 2");
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            System.out.print("Bitte gib dein hashed PW aus der Tabelle ein Kollege: ");
            String passwordReaded = "";


            try {
                passwordReaded = br.readLine();
            } catch (IOException e) {
                System.out.println(e.getMessage());
            }
            if (passwordReaded.length() < 6) {
                System.out.println("PW too short!");
                return;
            }
            // define algo in String Array
            final String hashTypes[] = {"MD5", "SHA-224", "SHA-256", "SHA-512"};

            // go through for every hashType that is defined
            for (String hashType : hashTypes) {
                findandWritePW(passwordReaded, hashType);
            }

            // Wenn gefunden - Ausgabe der Infos über den Algorithmus sowie das Passwort im
            // Plaintext
            if (isMatching) {
                System.out.println("Found in Algo " + algorithm);
                System.out.println("PW gefunden: " + foundPW);
            } else
                System.out.println("Sorry, da gibt es kein PW in der Liste!");
        }





        public static void sha256(String password) throws NoSuchAlgorithmException {
            // SHA-256 per getInstance aufrufen
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            String result = toHexString( md.digest(password.getBytes(StandardCharsets.UTF_8)));

            System.out.println("SHA256: " + result);

        }
        public static void sha256Salt(String password) throws NoSuchAlgorithmException {
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            md.update(salt);
            byte[] hashed = md.digest(password.getBytes(StandardCharsets.UTF_8));

            String sb = toHexString(hashed);
            System.out.println( "SHA256 + SALT: " + sb);



        }

        public static String toHexString(byte[] hash) {
            // das byte array umwandeln
            BigInteger number = new BigInteger(1, hash);

            // in einen Hexwert umwandeln
            StringBuilder hexString = new StringBuilder(number.toString(16));

            // Pad with leading zeros
            while (hexString.length() < 64) {
                hexString.insert(0, '0');
            }

            return hexString.toString();
        }

        public static void bcrypt(String password) throws NoSuchAlgorithmException {

            String result = BCrypt.hashpw(password, BCrypt.gensalt(12));
            System.out.println("Bcrypt: " + result);


        }

        public static void md5(String input) {
            try {

                // MD5
                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] messageDigest = md.digest(input.getBytes());
                BigInteger no = new BigInteger(1, messageDigest);

                // to hex
                StringBuilder hashtext = new StringBuilder(no.toString(16));
                while (hashtext.length() < 32) {
                    hashtext.insert(0, "0");
                }
                System.out.println("MD5: " + hashtext.toString());
            }

            // Error Message
            catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        ;



        public static void findandWritePW(String password, String hashType) {
            MessageDigest md;
            try {
                //read passwords of PW Tables

                // IF its not working  use the absolute File URL
                BufferedReader br = new BufferedReader(new FileReader("src/ListofPasswords.txt"));

                // define Filewriter and Path
                FileWriter fw = new FileWriter(new File("src/" + hashType + ".txt"));
                String lineToRead = "";


                // read file with the BufferedReader
                while ((lineToRead = br.readLine()) != null) {
                    md = MessageDigest.getInstance(hashType);
                    md.reset();
                    md.update(lineToRead.getBytes(StandardCharsets.UTF_8));

                    // safe it to byteArray
                    byte[] resultArray = md.digest();

                    System.out.println("" + resultArray);
                    StringBuilder sb = new StringBuilder();

                    // for each in resultarray
                    for (byte b : resultArray) {
                        sb.append(String.format("%02x", b));
                    }
                    // convert into String, after building
                    String finalString = sb.toString();
                    //in File speichern
                    fw.write(finalString);
                    fw.write(System.lineSeparator());
                    fw.flush();

                    System.out.println("finalString = " + finalString );
                    if (finalString.equals(password)) {
                        System.out.println("true");
                        isMatching = true;
                        foundPW = lineToRead;
                        algorithm = hashType;
                        if (!finished) {
                            // close Stream
                            br.close();
                            fw.close();
                            return;
                        }
                    }
                }
                br.close();
                fw.close();


            } catch (IOException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
    }


    /*
        BCrypt: Die Funktion wurde speziell für den Einsatz des PW Hashes entwickelt. Der Algorithmus der durchläuft, ist der BlowFish Algo.
        Der Zweck von BCrypt besteht darin, das Password in einem kryptografischen n-Bit Schlüssel umzuwandeln.
        Im Gegensatz zu einfachen und schnelleren Hash Methoden wie MD5 erzeugt bcrypt mit jedem Vorgang einen anderen HashCode.
        Je höher der Costs wert ist, desto länger braucht der Algorithmus, um einen Hash zu berechnen.

     */

