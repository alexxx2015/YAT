package edu.tum.uc.jvm.utility.analysis;

import java.io.File;
import java.net.URL;
import java.util.LinkedList;
import java.util.List;

import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import edu.tum.uc.jvm.utility.analysis.StaticAnalysis.NODETYPE;

public class StaticAnalysisReportReader {
	private static String TAG_SOURCES = "sources";
	private static String TAG_SINKS = "sinks";
	private static String TAG_SOURCE = "source";
	private static String TAG_SINK = "sink";
	private static String TAG_ID = "id";
	private static String TAG_LOCATION = "location";
	private static String TAG_POSSIBLE_SIGNATURES = "possible-signatures";
	private static String TAG_SIGNATURE = "signature";
	private static String TAG_PARAM = "param";
	private static String TAG_RETURN = "return";
	private static String TAG_CONTEXT = "context";
	private static String TAG_CREATION_SITES = "creation-sites";
	private static String TAG_CREATION_SITE = "creation-site";
	private static String TAG_CHOPNODE = "chopNode";
	private static String TAG_FLOWS = "flows";
	private static String ATTR_INDEX = "index";
	private static String ATTR_ID = "id";
	private static String ATTR_BYTECODEINDEX = "byteCodeIndex";
	private static String ATTR_OWNERMETHOD = "ownerMethod";
	private static String ATTR_LABEL = "label";
	private static String ATTR_OPERATION = "operation";

	private SAXHandler reader = null;

	private List<SinkSourceReport> sources = new LinkedList<SinkSourceReport>();
	private List<SinkSourceReport> sinks = new LinkedList<SinkSourceReport>();
	private List<Flow> flows = new LinkedList<Flow>();
	private List<CreationSite> creationSites = new LinkedList<CreationSite>();

	private enum REPORT_PARTS {
		SOURCES, SINKS, FLOWS, CREATION_SITES
	}

	public void readReport(String filename) throws Exception {
		try {
			if (this.reader == null) {
				this.reader = new SAXHandler();
			}

			SAXParserFactory factory = SAXParserFactory.newInstance();
			File report = new File(filename);
			// System.out.println("READING REPORT "+report.getAbsolutePath());
			factory.newSAXParser().parse(report, this.reader);
		} catch (Exception e) {
			System.out.println("ERROR " + e.getMessage());
		}
	}

	private class SAXHandler extends DefaultHandler {

		private SinkSourceReport currentELem;
		private Flow currentFlow;
		private REPORT_PARTS currentPart;
		private CreationSite currentCreationSite;

		private boolean id = false;
		private boolean location = false;
		private boolean possibleSignature = false;
		private boolean signature = false;
		private boolean context = false;

		@Override
		public void startElement(String uri, String localName, String qname,
				Attributes attributes) throws SAXException {
			// SOURCES
			if (TAG_SOURCES.equals(qname)) {
				this.currentPart = REPORT_PARTS.SOURCES;
			}
			// SINKS
			else if (TAG_SINKS.equals(qname)) {
				this.currentPart = REPORT_PARTS.SINKS;
			}
			// FLOWS
			else if (TAG_FLOWS.equals(qname)) {
				this.currentPart = REPORT_PARTS.FLOWS;
			}
			// CREATION-SITES
			else if (TAG_CREATION_SITES.equals(qname)) {
				this.currentPart = REPORT_PARTS.CREATION_SITES;
			}
			// CREATION-SITE
			else if (TAG_CREATION_SITE.equals(qname)) {
				this.currentCreationSite = new CreationSite();
			}
			// SOURCE / SINK
			else if (TAG_SOURCE.equals(qname) || TAG_SINK.equals(qname) || TAG_CHOPNODE.equals(qname)) {
				if (!this.currentPart.equals(REPORT_PARTS.FLOWS)) {
					if (TAG_SOURCE.equals(qname)) {
						this.currentELem = new SinkSourceReport(NODETYPE.SOURCE);
					} else if (TAG_SINK.equals(qname)) {
						this.currentELem = new SinkSourceReport(NODETYPE.SINK);
					}
				} else {
					if (TAG_SINK.equals(qname)) {
						this.currentFlow = new Flow();
						this.currentFlow.setSink(attributes.getValue(ATTR_ID));
					} else if (TAG_SOURCE.equals(qname)) {
						this.currentFlow
								.addSource(attributes.getValue(ATTR_ID));
					} else if (TAG_CHOPNODE.equals(qname)){
						int bci = Integer.parseInt(attributes.getValue(ATTR_BYTECODEINDEX));
						String om = attributes.getValue(ATTR_OWNERMETHOD);
						String op = attributes.getValue(ATTR_OPERATION);
						String lbl = attributes.getValue(ATTR_LABEL);
						this.currentFlow.addChopNode(bci, om, lbl, op);
					}
				}
			}
			// ID
			else if (TAG_ID.equals(qname)) {
				this.id = true;
			}
			// LOCATON
			else if (TAG_LOCATION.equals(qname)) {
				this.location = true;
			}
			// POSSIBLE_SIGNATURE
			else if (TAG_POSSIBLE_SIGNATURES.equals(qname)) {
				this.possibleSignature = true;
			}
			// SIGNATURE
			else if (TAG_SIGNATURE.equals(qname)) {
				this.signature = true;
			}
			// PARAM
			else if (TAG_PARAM.equals(qname)) {
				String index = attributes.getValue(ATTR_INDEX);
				if (index != null) {
					this.currentELem.setParam(Integer.parseInt(index));
				}
			}
			// RETURN
			else if (TAG_RETURN.equals(qname)) {
				this.currentELem.set_return(true);
			}
			// CONTEXT
			else if (TAG_CONTEXT.equals(qname)) {
				this.context = true;
			}
		}

		@Override
		public void characters(char[] ch, int start, int length)
				throws SAXException {
			if (this.currentPart != null
					&& !this.currentPart.equals(REPORT_PARTS.FLOWS)) {
				if (this.id) {
					if (this.currentPart
							.equals(StaticAnalysisReportReader.REPORT_PARTS.CREATION_SITES)) {
						this.currentCreationSite.setId(new String(ch, start,
								length));
					} else {
						this.currentELem.setId(new String(ch, start, length));
					}
					this.id = false;
				} else if (this.location) {
					String l = new String(ch, start, length);
					String[] locationComponent = l.split(":");
					String location = "";
					int offset = -100;
					if (locationComponent.length == 2) {
						location = locationComponent[0];
						offset = Integer.parseInt(locationComponent[1]);
					}
					if (this.currentPart.equals(REPORT_PARTS.CREATION_SITES)) {
						this.currentCreationSite.setLocation(location);
						this.currentCreationSite.setOffset(offset);
					} else {
						this.currentELem.setLocation(location);
						this.currentELem.setOffset(offset);
					}
					this.location = false;
				} else if (this.possibleSignature && this.signature) {
					String s = new String(ch, start, length);
					this.currentELem.addSignature(s);
					this.signature = false;
				} else if (this.context) {
					this.currentELem.addContext(new String(ch, start, length));
					this.context = false;
				}
			}
		}

		@Override
		public void endElement(String uri, String localName, String qname)
				throws SAXException {
			// SOURCES
			if (TAG_SOURCES.equals(qname)) {
				// System.out.println("DONE "+qname);
			}
			// SINKS
			else if (TAG_SINKS.equals(qname)) {
				// System.out.println("DONE "+qname);
			}
			// FLOWS
			else if (TAG_FLOWS.equals(qname)) {
			}
			// SOURCE / SINK
			else if (TAG_SOURCE.equals(qname) || TAG_SINK.equals(qname)) {
				if (!this.currentPart.equals(REPORT_PARTS.FLOWS)) {
					if (this.currentPart.equals(REPORT_PARTS.SINKS)) {
						sinks.add(this.currentELem);
					} else if (this.currentPart.equals(REPORT_PARTS.SOURCES)) {
						sources.add(this.currentELem);
					}
				} else {
					if (TAG_SINK.equals(qname)) {
						flows.add(this.currentFlow);
					}
				}
			}
			// ID
			else if (TAG_ID.equals(qname)) {
				this.id = false;
			}
			// LOCATON
			else if (TAG_LOCATION.equals(qname)) {
				this.location = false;
			}
			// POSSIBLE_SIGNATURE
			else if (TAG_POSSIBLE_SIGNATURES.equals(qname)) {
				this.possibleSignature = false;
			}
			// SIGNATURE
			else if (TAG_SIGNATURE.equals(qname)) {
				this.signature = false;
			}
			// ATTR INDEX
			else if (TAG_PARAM.equals(qname)) {
			}
			// RETURN
			else if (TAG_RETURN.equals(qname)) {
			}
			// CONTEXT
			else if (TAG_CONTEXT.equals(qname)) {
				this.context = false;
			}
			// CREATION-SITE
			else if (TAG_CREATION_SITE.equals(qname)) {
				creationSites.add(this.currentCreationSite);
			}
			// CREATION-SITES
			else if (TAG_CREATION_SITES.equals(qname)) {
				// System.out.println("Creation-side end");
			}
		}
	}

	public List<SinkSourceReport> getSources() {
		return sources;
	}

	public List<SinkSourceReport> getSinks() {
		return sinks;
	}

	public List<Flow> getFlows() {
		return flows;
	}

	public List<CreationSite> getCreationSites() {
		return creationSites;
	}
}
