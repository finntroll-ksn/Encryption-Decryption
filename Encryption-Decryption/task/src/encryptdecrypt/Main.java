package encryptdecrypt;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

class InputParameters {
    private String mode = "enc";
    private int key = 0;
    private String data = "";
    private String inputFile = "";
    private String outputFile = "";
    private String alg = "shift";

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public int getKey() {
        return key;
    }

    public void setKey(int key) {
        this.key = key;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;

        if (!this.inputFile.equals("")) {
            this.inputFile = "";
        }
    }

    public String getInputFile() {
        return inputFile;
    }

    public void setInputFile(String inputFile) {
        if (this.data.equals("")) {
            this.inputFile = inputFile;
        }
    }

    public String getOutputFile() {
        return outputFile;
    }

    public void setOutputFile(String outputFile) {
        this.outputFile = outputFile;
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    protected void initParams(InputParameters input, String[] args) {
        for (int i = 0; i < args.length; i += 2) {
            switch (args[i]) {
                case "-mode":
                    this.setMode(args[i + 1]);
                    break;
                case "-key":
                    this.setKey(Integer.parseInt(args[i + 1]));
                    break;
                case "-data":
                    this.setData(args[i + 1]);
                    break;
                case "-in":
                    this.setInputFile(args[i + 1]);
                    break;
                case "-out":
                    this.setOutputFile(args[i + 1]);
                    break;
                case "-alg":
                    this.setAlg(args[i + 1]);
                    break;
                default:
                    break;
            }
        }
    }
}

abstract class EncoderFactory {

    abstract Algorithm chooseAlgorithm(String mode, String algorithm, String filePath, String data, int shift) throws IOException;

    void executeAlgorithm(InputParameters input) {
        try {
            Algorithm algorithm = chooseAlgorithm(input.getMode(), input.getAlg(), input.getInputFile(), input.getData(), input.getKey());

            if (!input.getOutputFile().equals("")) {
                writeFile(algorithm.execute(), input.getOutputFile());
            } else {
                System.out.println(algorithm.execute());
            }
        } catch (Exception e) {
            System.out.println("Error");
        }
    }

    protected static String readString(String fileName) throws IOException {
        return new String(Files.readAllBytes(Paths.get(fileName)));
    }

    private static void writeFile(String data, String path) throws IOException {
        File file = new File(path);

        try (PrintWriter printWriter = new PrintWriter(file)) {
            printWriter.print(data);
        }
    }
}

class Cryptographer extends EncoderFactory {
    @Override
    Algorithm chooseAlgorithm(String mode, String algorithm, String filePath, String data, int shift) throws IOException {
        switch (algorithm) {
            case "shift":
                return mode.equals("enc") ?
                        new ShiftEncryption(filePath.equals("") ? data : readString(filePath), shift) :
                        new ShiftDecryption(filePath.equals("") ? data : readString(filePath), shift);
            case "unicode":
                return mode.equals("enc") ?
                        new UnicodeEncryption(filePath.equals("") ? data : readString(filePath), shift) :
                        new UnicodeDecryption(filePath.equals("") ? data : readString(filePath), shift);
            default:
                return null;
        }
    }
}

interface AlgorithmInterface {
    String UPPER_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    String LOWER_ALPHABET = "abcdefghijklmnopqrstuvwxyz";

    String execute();
}

class Algorithm implements AlgorithmInterface {
    protected char[] string;
    protected int shift;

    Algorithm(String inputData, int key) {
        string = inputData.toCharArray();
        shift = key;
    }

    public String execute() {
        return null;
    }
}

class ShiftEncryption extends Algorithm {

    ShiftEncryption(String inputData, int shift) {
        super(inputData, shift);
    }

    public String execute() {
        int upper_position;
        int lower_position;
        char[] output = new char[string.length];

        for (int i = 0; i < string.length; i++) {
            upper_position = UPPER_ALPHABET.indexOf(string[i]);
            lower_position = LOWER_ALPHABET.indexOf(string[i]);

            if (upper_position != -1) {
                output[i] = (upper_position + shift) > UPPER_ALPHABET.length() ?
                        UPPER_ALPHABET.charAt((upper_position + shift) % UPPER_ALPHABET.length()) :
                        UPPER_ALPHABET.charAt(upper_position + shift);
            } else if (lower_position != -1) {
                output[i] = (lower_position + shift) > LOWER_ALPHABET.length() ?
                        LOWER_ALPHABET.charAt((lower_position + shift) % LOWER_ALPHABET.length()) :
                        LOWER_ALPHABET.charAt(lower_position + shift);
            } else {
                output[i] = string[i];
            }
        }

        return String.valueOf(output);
    }
}

class ShiftDecryption extends Algorithm {

    ShiftDecryption(String inputData, int shift) {
        super(inputData, shift);
    }

    public String execute() {
        int upper_position;
        int lower_position;
        char[] output = new char[string.length];

        for (int i = 0; i < string.length; i++) {
            upper_position = UPPER_ALPHABET.indexOf(string[i]);
            lower_position = LOWER_ALPHABET.indexOf(string[i]);

            if (upper_position != -1) {
                output[i] = (upper_position - shift) < 0 ?
                        UPPER_ALPHABET.charAt(upper_position - shift + UPPER_ALPHABET.length()) :
                        UPPER_ALPHABET.charAt(upper_position - shift);
            } else if (lower_position != -1) {
                output[i] = (lower_position - shift) < 0 ?
                        LOWER_ALPHABET.charAt(lower_position - shift + LOWER_ALPHABET.length()) :
                        LOWER_ALPHABET.charAt(lower_position - shift);
            } else {
                output[i] = string[i];
            }
        }

        return String.valueOf(output);
    }
}

class UnicodeEncryption extends Algorithm {

    UnicodeEncryption(String inputData, int shift) {
        super(inputData, shift);
    }

    public String execute() {
        for (int i = 0; i < string.length; i++) {
            string[i] = (char) (string[i] + shift);
        }

        return String.valueOf(string);
    }

}

class UnicodeDecryption extends Algorithm {

    UnicodeDecryption(String inputData, int shift) {
        super(inputData, shift);
    }

    public String execute() {
        for (int i = 0; i < string.length; i++) {
            string[i] = (char) (string[i] - shift);
        }

        return String.valueOf(string);
    }
}

public class Main {

    public static void main(String[] args) {
        InputParameters input = new InputParameters();
        input.initParams(input, args);

        Cryptographer cryptographer = new Cryptographer();
        cryptographer.executeAlgorithm(input);
    }
}
