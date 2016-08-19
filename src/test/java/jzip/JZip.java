package jzip;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

public class JZip {
	List<String> fileList;

	private int i;

	private Properties CONFIGURATION = null;

	private CommandLineParser cmdParser;
	private Options opt;
	private boolean run;
	private String[] args;
	private String commandline = "";

	public static void main(String[] args) {
		JZip zipper = new JZip();
		int z = zipper.testArith(4, 4);
		 zipper.start();
	}

	private int testArith(int h, long r) {
		int a = 500 + h, b = 3444;
		double c = 4, d = 500000;
		long e = 60000 + r;
		int sum = a + b;
		e = e + e;
		Object o1 = new Object(), o2 = new Object();
		return sum;
	}

	public JZip(String[] args) {
		this.args = args;
		// if (args != null && args.length > 0) {
		// StringBuilder sb = new StringBuilder();
		// for (String s : args) {
		// sb.append(s);
		// }
		// this.commandline = sb.toString();
		// }
	}

	public JZip() {
	}

	private void init() {
		this.run = true;

		this.opt = new Options();
		Option help = new Option("help", "Print help");
		opt.addOption(help);

		Option exit = new Option("exit", "Exit JZip");
		opt.addOption(exit);

		Option loadconfig = OptionBuilder.withArgName("file").hasArg()
				.withDescription(
						"Load the configuration file <file>. All existing configuration properties will be overwritten afterwards.")
				.create("loadconfig");
		opt.addOption(loadconfig);

		Option storeconfig = OptionBuilder.withArgName("file").hasArg()
				.withDescription("Store the current configuration in file <file>").create("storeconfig");
		opt.addOption(storeconfig);

		Option setconfig = OptionBuilder.withArgName("name=value").hasOptionalArgs(2).withValueSeparator('=')
				.withDescription("Assign the value <value> to configuration property <name>").create("setconfig");
		opt.addOption(setconfig);

		Option showConfig = new Option("showconfig", "List all properties");
		opt.addOption(showConfig);

		Option zip = OptionBuilder.withArgName("file> <source").hasOptionalArgs(2)
				.withDescription(
						"Zip all files from directory <source> to archive file <file>. If <source> is not declared then this property is read from the configuration file. <source>'s default is '.'")
				.create("zip");
		opt.addOption(zip);

		Option unzip = OptionBuilder.withArgName("file> <destination").hasOptionalArgs(2)
				.withDescription(
						"Unzip all files from zip <file> into destination folder <destination>. If <destination> is not declared then this propery is read from the configuration file. <destination>'s default is '.'")
				.create("unzip");
		opt.addOption(unzip);
		this.cmdParser = new GnuParser();
	}

	public void start() {
		this.init();

		System.out.println("=== WELCOME to JZip ===");
		String instruction = "";
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		try {
			do {
				if ((this.commandline != null) && !"".equals(this.commandline)) {
					if ("".equals(instruction))
						instruction = this.commandline;
				} else {
					instruction = br.readLine();
				}

				if (instruction == null)
					break;

				if ("help".equals(instruction.trim())) {
					HelpFormatter formatter = new HelpFormatter();
					formatter.printHelp("JZip", opt);
				} else if ("exit".equals(instruction.trim())) {
					this.run = false;
				} else {
					String[] myArgs = instruction.split(" ");
					if (myArgs.length > 0) {
						myArgs[0] = "-" + myArgs[0];
						this.parseAndRun(myArgs);
					}
				}
				if ((this.commandline != null) && !"".equals(this.commandline)) {
					instruction = "exit";
				}
			} while ((instruction != null && this.run));

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void parseAndRun(String[] args) {

		try {
			CommandLine line = this.cmdParser.parse(this.opt, args);
			if (line.hasOption("loadconfig")) {
				String configFile = line.getOptionValue("loadconfig");
				this.loadConfig(configFile);
			}

			if (line.hasOption("storeconfig")) {
				String configFile = line.getOptionValue("storeconfig");
				this.storeConfig(configFile);
			}

			if (line.hasOption("setconfig")) {
				String[] setValue = line.getOptionValues("setconfig");
				if (setValue.length == 2) {
					this.setConfigValue(setValue[0], setValue[1]);
				}
			}

			if (line.hasOption("showconfig")) {
				this.showConfig();
			}

			if (line.hasOption("zip")) {
				String[] zipValue = line.getOptionValues("zip");
				String zipFile = "zipped.zip", sourceFolder = ".";
				if (zipValue != null) {
					if (zipValue.length == 2) {
						zipFile = zipValue[0];
						sourceFolder = zipValue[1];
					} 
					else if (zipValue.length == 1) {
						zipFile = zipValue[0];
						if ((this.CONFIGURATION != null) && (this.CONFIGURATION.contains("zip-source"))) {
							sourceFolder = this.CONFIGURATION.getProperty("zip-source");
						}
					}
				}
				else {
					if ((this.CONFIGURATION != null) && (this.CONFIGURATION.containsKey("zip-source"))) {
						sourceFolder = this.CONFIGURATION.getProperty("zip-source");
					}
				}
				this.zipIt(zipFile, sourceFolder);
			}

			if (line.hasOption("unzip")) {
				String[] unzipValue = line.getOptionValues("unzip");
				String unzipFile, unzipDestination = ".";
				if ((unzipValue != null) && (unzipValue.length > 0)) {
					unzipFile = unzipValue[0];
					if ((this.CONFIGURATION != null) && (this.CONFIGURATION.containsKey("unzip-destination"))) {
						unzipDestination = this.CONFIGURATION.getProperty("unzip-destination");
					}
				} else {
					throw new ParseException("Parameter <file> not found.");
				}
				if ((this.CONFIGURATION != null)
						&& (this.CONFIGURATION.containsKey("unzip-destination-autogenerate"))) {
					if ("true".equals(this.CONFIGURATION.getProperty("unzip-destination-autogenerate").toLowerCase())) {
						File f = new File(unzipDestination);
						if (!f.exists()) {
							f.mkdirs();
						}
					}
				}
				this.unZipIt(unzipFile, unzipDestination);
			}

		} catch (ParseException e) {
			// TODO Auto-generated catch block
			// e.printStackTrace();
			System.err.println("This command is not supported. ");
			System.err.println(e.getMessage());
		}
	}

	public void zipIt(String zipFile, String sourceFolder) {
		this.fileList = new LinkedList<String>();
		this.generateFileList(new File(sourceFolder), sourceFolder);

		byte[] buffer = new byte[32768];

		try {

			FileOutputStream fos = new FileOutputStream(zipFile);
			BufferedOutputStream bos = new BufferedOutputStream(fos, 16384);
			ZipOutputStream zos = new ZipOutputStream(bos);

			System.out.println("Output to Zip : " + zipFile);

			for (String file : this.fileList) {

				System.out.println("File Added : " + file);
				ZipEntry ze = new ZipEntry(file);
				zos.putNextEntry(ze);

				FileInputStream in = new FileInputStream(sourceFolder + File.separator + file);
				BufferedInputStream bin = new BufferedInputStream(in, 32768);

				int len;
				while ((len = bin.read(buffer)) > 0) {
					zos.write(buffer, 0, len);
				}

				in.close();
			}

			zos.closeEntry();
			// remember close it
			zos.close();

			System.out.println("Done");
		} catch (IOException ex) {
			ex.printStackTrace();
		}
	}

	/**
	 * Traverse a directory and get all files, and add the file into fileList
	 * 
	 * @param node
	 *            file or directory
	 */
	public void generateFileList(File node, String sourceFolder) {

		// add file only
		if (node.isFile()) {
			// fileList.add(generateZipEntry(node.getAbsoluteFile().toString(),
			// sourceFolder));
			fileList.add(generateZipEntry(node.getPath(), sourceFolder));
		}

		if (node.isDirectory()) {
			String[] subNote = node.list();
			for (String filename : subNote) {
				generateFileList(new File(node, filename), sourceFolder);
			}
		}

	}

	/**
	 * Format the file path for zip
	 * 
	 * @param file
	 *            file path
	 * @return Formatted file path
	 */
	private String generateZipEntry(String file, String sourceFolder) {
		return file.substring(sourceFolder.length(), file.length());
	}

	/**
	 * Unzip it
	 * 
	 * @param zipFile
	 *            input zip file
	 * @param output
	 *            zip file output folder
	 */
	public void unZipIt(String zipFile, String outputFolder) {

		byte[] buffer = new byte[1024];

		try {

			// create output directory is not exists
			File folder = new File(outputFolder);
			if (!folder.exists()) {
				folder.mkdir();
			}

			// get the zip file content
			ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile));
			// get the zipped file list entry
			ZipEntry ze = zis.getNextEntry();

			while (ze != null && !ze.isDirectory()) {

				String fileName = ze.getName();
				File newFile = new File(outputFolder + File.separator + fileName);

				System.out.println("file unzip : " + newFile.getAbsoluteFile());

				// create all non exists folders
				// else you will hit FileNotFoundException for compressed folder
				new File(newFile.getParent()).mkdirs();

				FileOutputStream fos = new FileOutputStream(newFile);

				int len;
				while ((len = zis.read(buffer)) > 0) {
					fos.write(buffer, 0, len);
				}

				fos.close();
				ze = zis.getNextEntry();
			}

			zis.closeEntry();
			zis.close();

			System.out.println("Done");

		} catch (IOException ex) {
			ex.printStackTrace();
		}
	}

	private void setConfigValue(String name, String value) {
		if (this.CONFIGURATION == null) {
			this.CONFIGURATION = new Properties();
		}
		this.CONFIGURATION.put(name, value);
	}

	private void storeConfig(String file) {
		try {
			File f = new File(file);
			FileOutputStream fos = new FileOutputStream(f);
			this.CONFIGURATION.store(fos, "JZip configuration dump");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void showConfig() {
		if (this.CONFIGURATION != null) {
			Iterator<Object> it = this.CONFIGURATION.keySet().iterator();
			while (it.hasNext()) {
				Object o = it.next();
				System.out.println(o + ": " + this.CONFIGURATION.getProperty((String) o));
			}
		} 
		else {
			System.out.println("No entries");
		}
	}

	private void loadConfig(String file) {
		// URL ucConfig = this.getClass().getResource(file);
		// File f = new File(ucConfig.getFile());
		File f = new File(file);
		if (f.exists()) {
			try {
				FileInputStream fis = new FileInputStream(f);
				CONFIGURATION = new Properties();
				CONFIGURATION.load(fis);
				this.showConfig();
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
}
