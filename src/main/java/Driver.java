public class Driver {
    public static void main(String [] args) {
        ClamAVScanner scanner = new ClamAVScanner("localhost", 3310);
        scanner.scanFile("novirus.txt");
    }
} 