package edu.tum.uc.jvm.utility.analysis;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import edu.tum.uc.jvm.utility.analysis.SinkSourceSpec.TYPE;

public class SinkSourceSpecReader {

	private static final String TAG_SOURCESINK = "sourcesandsink";
	private static final String TAG_SOURCE = "source";
	private static final String TAG_SINK = "sink";

	private static final String ATTR_CLASS = "class";
	private static final String ATTR_SELECTOR = "selector";
	private static final String ATTR_PARAMS = "params";

	private SAXXmlParser reader = null;

	private Set<SinkSourceSpec> sinks = new HashSet<SinkSourceSpec>();
	private Set<SinkSourceSpec> sources = new HashSet<SinkSourceSpec>();

	public void readReport(String filename) {
		try {
			if (this.reader == null) {
				this.reader = new SAXXmlParser();
			}

			SAXParserFactory factory = SAXParserFactory.newInstance();
			File report = new File(filename);
			// System.out.println("READING REPORT "+report.getAbsolutePath());
			factory.newSAXParser().parse(report, this.reader);
		} catch (Exception e) {
			System.err.println("ERROR " + e.getMessage());
		}
	}
	
	public Set<SinkSourceSpec> getSources(){
		return this.sources;
	}
	public Set<SinkSourceSpec> getSinks(){
		return this.sinks;
	}

	private class SAXXmlParser extends DefaultHandler {

		@Override
		public void startElement(String uri, String localName, String qName,
				Attributes attributes) throws SAXException {
			SinkSourceSpec ssr = null;
			if (TAG_SOURCE.equals(qName)) {
				ssr =  new SinkSourceSpec(SinkSourceSpec.TYPE.SOURCE);
			} else if (TAG_SINK.equals(qName)) {
				ssr =  new SinkSourceSpec(SinkSourceSpec.TYPE.SINK);
			}
			
			if(ssr != null){
				ssr.setClazz(attributes.getValue(ATTR_CLASS));
				ssr.setSelector(attributes.getValue(ATTR_SELECTOR));
				ssr.setParams(attributes.getValue(ATTR_PARAMS));
				if(ssr.getType().equals(TYPE.SOURCE))
					sources.add(ssr);
				else if(ssr.getType().equals(TYPE.SINK))
					sinks.add(ssr);
			}

		}

//		@Override
//		public void characters(char[] ch, int start, int length)
//				throws SAXException {
//			// TODO Auto-generated method stub
//			super.characters(ch, start, length);
//		}

//		@Override
//		public void endElement(String uri, String localName, String qName)
//				throws SAXException {
//			// TODO Auto-generated method stub
//			super.endElement(uri, localName, qName);
//		}

	}

}
