package edu.tum.uc.jvm.utility.analysis;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.objectweb.asm.Label;

import edu.tum.uc.jvm.utility.ConfigProperties;
import edu.tum.uc.jvm.utility.analysis.Flow.Chop;

public class StaticAnalysis {

	private static StaticAnalysisReportReader reportreader = new StaticAnalysisReportReader();

	public static enum NODETYPE {
		NONE, SOURCE, SINK, BOTH, ERROR, CHOP_NODE;
	}
	
//	static {
//		String file = ConfigProperties.getProperty(ConfigProperties.PROPERTIES.ANALYSIS_REPORT);
//		StaticAnalysis.importXML(new File(file).getAbsolutePath());
//	}

	// public StaticAnalysis() {
	// this.reportreader = new ReportReader();
	// }

	public static void importXML(String filename) {
		try {
			reportreader = new StaticAnalysisReportReader();
			reportreader.readReport(filename);
		} catch (Exception e) {
		}
	}
	
	public static SinkSourceReport getSinkById(String p_sinkId){
		SinkSourceReport _return = null;
		for(SinkSourceReport s : reportreader.getSinks()){
			if(p_sinkId.equals(s.getId())){
				_return = s;
				break;
			}
		}
		return _return;
	}
	
	public static SinkSourceReport getSourceById(String p_sourceId){
		SinkSourceReport _return = null;
		for(SinkSourceReport s : reportreader.getSources()){
			if(p_sourceId.equals(s.getId())){
				_return = s;
				break;
			}
		}
		return _return;
	}

	public static List<SinkSourceReport> getSinks() {
		return reportreader.getSinks();
	}

	public static List<SinkSourceReport> getSources() {
		return reportreader.getSources();
	}

	public static List<Flow> getFlows() {
		return reportreader.getFlows();
	}

	/*
	 * note that if the same invocation is both, output is only the one in
	 * sinks. (shouldn't matter) in case of error, nodeType.ERROR is returned
	 * and output=null
	 */
	public static List<SinkSourceReport> getType(String fullyQualifiedName, int offset) {
		if (fullyQualifiedName.contains("zipIt")) {
			int u = 0;
			u++;
		}

		List<SinkSourceReport> _return = new LinkedList<SinkSourceReport>();

		Iterator<SinkSourceReport> it = reportreader.getSinks().iterator();
		while (it.hasNext()) {
			SinkSourceReport ss = it.next();
			if (fullyQualifiedName.equals(ss.getLocation())
					&& (offset == ss.getOffset())) {
				_return.add(ss);
			}
		}

		it = reportreader.getSources().iterator();
		while (it.hasNext()) {
			SinkSourceReport ss = it.next();
			if (fullyQualifiedName.equals(ss.getLocation())
					&& (offset == ss.getOffset())) {
				_return.add(ss);
			}
		}
		return _return;
	}

	public static SinkSourceReport getSinkSourceById(String id, NODETYPE type) {
		SinkSourceReport _return = null;
		Iterator<SinkSourceReport> it;
		if (type.equals(NODETYPE.SINK)) {
			it = reportreader.getSinks().iterator();
		} else {
			it = reportreader.getSources().iterator();
		}

		while (it.hasNext()) {
			SinkSourceReport s = it.next();
			if (id.equals(s.getId())) {
				_return = s;
				break;
			}
		}

		if (_return == null) {
			int i = 0;
			i++;
		}

		return _return;
	}

	// TODO: chop not implemented and used yet
	public static List<Chop> getChop(String ownerMethod) {
		if (ownerMethod == null)
			return null;
		List<Flow.Chop> _return = new LinkedList<Flow.Chop>();
		List<Flow> flows = reportreader.getFlows();
		Iterator<Flow> flowIt = flows.iterator();
		while (flowIt.hasNext()) {
			Flow f = flowIt.next();
			if (f.getChopNodes() != null) {
				Iterator<Chop> chopIt = f.getChopNodes().iterator();
				while (chopIt.hasNext()) {
					Chop c = chopIt.next();
					if (ownerMethod.equals(c.getOwnerMethod()))
						_return.add(c);
				}
			}
		}

		return _return;
	}

	public static List<CreationSite> getCreationSite() {
		return reportreader.getCreationSites();
	}

	public static List<CreationSite> getCreationSiteByLabel(String location,
			Label lab) {
		List<CreationSite> _return = new LinkedList<CreationSite>();
		List<CreationSite> allCreationSites = getCreationSite();
		for (int i = 0; i < allCreationSites.size(); i++) {
			CreationSite cs = allCreationSites.get(i);
			if (cs.getOffset() == lab.getOffset()
					&& cs.getLocation().startsWith(location)) {
				_return.add(cs);
			}
		}
		return _return;
	}

	public static List<CreationSite> getCreationSiteByLocation(String location,
			int offset, String type) {
		List<CreationSite> _return = new LinkedList<CreationSite>();
		List<CreationSite> allCreationSites = getCreationSite();
		for (int i = 0; i < allCreationSites.size(); i++) {
			CreationSite cs = allCreationSites.get(i);
			if (cs.getOffset() <= offset
					&& cs.getLocation().startsWith(location)
					&& type.equals(cs.getType())) {
				_return.add(cs);
			}
		}
		return _return;
	}
	
	//Checks if bytecodeOffset in method parentMethodFQN is a source
	public static List<SinkSourceReport> isSource(String parentMethodFQN, int bytecodeOffset){
		List<SinkSourceReport> _return = new LinkedList<SinkSourceReport>();
		for(SinkSourceReport s : contains(parentMethodFQN, bytecodeOffset, getSources())){
			int param = s.getParam();
			if(s.is_return())
				_return.add(s);
			else if(param > 0)
				_return.add(s);
		}
		return _return;
//		return contains(parentMethodFQN, bytecodeOffset, getSources());
	}
	
	//Checks if bytecodeOffset in method parentMethodFQN is a source
	public static List<SinkSourceReport> isSink(String parentMethodFQN, int bytecodeOffset){
		return contains(parentMethodFQN, bytecodeOffset, getSinks());
	}
	public static List<SinkSourceReport> isSinkWithFlow(String parentMethodFQN, int bytecodeOffset){
		List<SinkSourceReport> _return = new LinkedList<SinkSourceReport>();
		List<SinkSourceReport> sinks = contains(parentMethodFQN, bytecodeOffset, getSinks());
		List<Flow> flows = getFlows();
		for(Flow f : flows){
			if(f.getSource() != null && f.getSource().size() != 0)
				for(SinkSourceReport s : sinks){
					if(f.getSink().equals(s.getId()))
						_return.add(s);
				}
		}
		return _return;
	}
	
	private static List<SinkSourceReport> contains(String parentMethodFQN, int bytecodeOffset, List<SinkSourceReport> list){
		List<SinkSourceReport> _return = new LinkedList<SinkSourceReport>();
		for (SinkSourceReport sinksource : list) {
		    if (sinksource.getLocation().equals(parentMethodFQN.replace("|", ".")) && sinksource.getOffset() == bytecodeOffset) {
		    	_return.add(sinksource);
		    }
		}
		return _return;
	}
}
