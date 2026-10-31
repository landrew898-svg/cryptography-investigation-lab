import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5FileFinder {

    // ==============================
    // CONFIGURATION
    // ==============================

    private static int filesChecked = 0;
    private static int totalFiles = 0;

    // ==============================
    // MD5 HASH CALCULATION
    // ==============================

    private static String calculateMD5(File file)
            throws IOException, NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance("MD5");

        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[4096];
            int bytesRead;

            while ((bytesRead = fis.read(buffer)) != -1) {
                md.update(buffer, 0, bytesRead);
            }
        }

        byte[] hashBytes = md.digest();
        StringBuilder hexString = new StringBuilder();

        for (byte b : hashBytes) {
            hexString.append(String.format("%02x", b));
        }

        return hexString.toString();
    }

    // ==============================
    // FILE COUNT (FOR PROGRESS)
    // ==============================

    private static void countFiles(File folder) {
        File[] entries = folder.listFiles();
        if (entries == null) {
            throw new IllegalArgumentException("Cannot list directory: " + folder);
        }
        for (File file : entries) {
            if (java.nio.file.Files.isSymbolicLink(file.toPath())) continue;
            if (file.isFile()) {
                totalFiles++;
            } else if (file.isDirectory()) {
                countFiles(file);
            }
        }
    }

    // ==============================
    // MAIN SEARCH LOGIC
    // ==============================

    private static boolean searchFiles(File folder, String targetMd5) {
        File[] entries = folder.listFiles();
        if (entries == null) {
            throw new IllegalArgumentException("Cannot list directory: " + folder);
        }
        for (File file : entries) {
            if (java.nio.file.Files.isSymbolicLink(file.toPath())) continue;

            if (file.isDirectory()) {
                if (searchFiles(file, targetMd5)) {
                    return true;
                }
            } else {
                filesChecked++;

                try {
                    String fileMD5 = calculateMD5(file);

                    // Show progress every 500 files
                    if (filesChecked % 500 == 0) {
                        System.out.println("Checked " + filesChecked +
                                " / " + totalFiles + " files...");
                    }

                    if (fileMD5.equalsIgnoreCase(targetMd5)) {
                        System.out.println("\nMATCH FOUND!");
                        System.out.println("File Name: " + file.getName());
                        System.out.println("Full Path: " + file.getAbsolutePath());
                        System.out.println("MD5 Hash: " + fileMD5);
                        System.out.println("Files Checked: " + filesChecked);
                        return true;
                    }

                } catch (IOException | NoSuchAlgorithmException e) {
                    throw new IllegalArgumentException("Cannot hash file: " + file, e);
                }
            }
        }
        return false;
    }

    // ==============================
    // PROGRAM ENTRY POINT
    // ==============================

    public static void main(String[] args) {
        try {
            run(args);
        } catch (IllegalArgumentException error) {
            System.err.println("Error: " + error.getMessage());
            System.exit(2);
        }
    }

    private static void run(String[] args) {
        if (args.length != 2 || !args[1].matches("[0-9a-fA-F]{32}")) {
            throw new IllegalArgumentException("Usage: java MD5FileFinder <folder> <32-character-md5>");
        }
        File folder = new File(args[0]);

        if (!folder.exists() || !folder.isDirectory()) {
            throw new IllegalArgumentException("Invalid folder path: " + folder);
        }

        System.out.println("Counting files...");
        countFiles(folder);
        System.out.println("Total files found: " + totalFiles);
        System.out.println("Starting MD5 scan...\n");

        boolean found = searchFiles(folder, args[1]);

        if (!found) {
            System.out.println("\nNo matching file found.");
            System.exit(1);
        }
    }
}
