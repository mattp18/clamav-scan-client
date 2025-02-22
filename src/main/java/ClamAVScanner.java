import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ClamAVScanner {
    private final String clamHost;
    private final int clamPort;

    public ClamAVScanner(String clamHost, int clamPort) {
        this.clamHost = clamHost;
        this.clamPort = clamPort;
    }
    
    /**
     * Scan a file for malware.
     * 
     * @param filePath filePath that contains file to perform scan on.
     */
   public String scanFile(String filePath) {
    try (Socket socket = new Socket(clamHost, clamPort);
         OutputStream out = new BufferedOutputStream(socket.getOutputStream());
         InputStream fileInput = new FileInputStream(filePath);
         InputStream in = socket.getInputStream()) {

        // Set timeout to recieve 
        socket.setSoTimeout(5000);

        out.write("zINSTREAM\0".getBytes());
        out.flush();

        byte[] buffer = new byte[1024];
        int bytesRead;

        while ((bytesRead = fileInput.read(buffer)) != -1) {
            //size of data to be sent
            byte[] sizePrefix = ByteBuffer.allocate(4).putInt(bytesRead).array();
            System.out.println("size of bytesRead in int: " + bytesRead);

            out.write(sizePrefix);
            out.write(buffer, 0, bytesRead);
            out.flush();

            // Check if ClamAV is responding unexpectedly
            if (in.available() > 0) {
                byte[] responseBuffer = readAll(in);
                return "Scan aborted for " + filePath + ". Response: " + new String(responseBuffer, StandardCharsets.US_ASCII);
            }
        }

        // Send termination signal (zero-length chunk)
        out.write(new byte[]{0, 0, 0, 0});
        out.flush();

        // Read ClamAV response
        byte[] response = readAll(in);
        //decode the array of bytes to ASCII
        System.out.println("ClamAV Response: " + new String(response, StandardCharsets.US_ASCII));
        return "File: " + filePath + " -> ClamAV Response: " + new String(response, StandardCharsets.US_ASCII);


    } catch (IOException e) {
        throw new ClamAVException("Error scanning file: " + filePath, e);
    }
}

public void scanFileCompressed(String filePath) {
    try(Socket socket = new Socket(clamHost, clamPort);
        OutputStream out = new BufferedOutputStream(socket.getOutputStream());
        InputStream filInput = new FileInputStream(filePath);
        InputStream in = socket.getInputStream();
        ) {
    } catch(IOException e) {
        e.printStackTrace();
    }
}

/**
 * Scan multiple files for malware.
 * 
 * @param filePaths filePaths of files to be scanned.
 * @return
 */
public Map<String, String> scanFiles(List<String> filePaths) {
    Map<String, String> results = new HashMap<>();
    for(String filePath : filePaths){
        results.put(filePath, scanFile(filePath));
    }
    return results;
}

/**
 * Helper method to read all available data from InputStream.
 * 
 * @param in inputStream from ClamAV server.
 * @return data read from ClamAV server.
 * @throws IOException
 */
private byte[] readAll(InputStream in) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    byte[] temp = new byte[1024];
    int bytesRead;
    while ((bytesRead = in.read(temp)) != -1) {
        buffer.write(temp, 0, bytesRead);
    }
    return buffer.toByteArray();
}
}