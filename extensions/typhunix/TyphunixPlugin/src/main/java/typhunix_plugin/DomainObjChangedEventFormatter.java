/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package typhunix_plugin;

import compatability.ChangeManagerBridge;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;

/**
 * Formats Changes to Ghidra Domain Objects
 */
public class DomainObjChangedEventFormatter {

	/**
	 * Class to format changes to ghidra domain objects
	 */
	private DomainObjectChangedEvent event = null;
	private static int id = 1;

	public DomainObjChangedEventFormatter(DomainObjectChangedEvent event) {
		this.event = event;
		DomainObjChangedEventFormatter.id++;
	}

	public String getIdStr() {
		return String.format("%05d", DomainObjChangedEventFormatter.id);
	}

	static public String formatValue(Object value, String prefix) {
		String rType = "null";
		String rVal = "null";
		if (value != null) {
			rType = value.getClass().getName();
			rVal = value.toString();
		}
		rType = "type: " + rType;
		rVal = "valu: " + rVal.toString().replace("\n", String.format("\n%s", "valu: "));
		StringBuffer sb = new StringBuffer();
		sb.append("\n");
		sb.append(rType);
		sb.append("\n");
		sb.append(rVal);
		return sb.toString().replace("\n", String.format("\n%s", prefix));
	}

	private String fmtDomainObjChangeRecord(int recordNum, DomainObjectChangeRecord doRecord) {
		String eventTypeName =
			ChangeManagerBridge.getInstance().codeToString(doRecord.getEventType());
		int eventTypeId =
			ChangeManagerBridge.getInstance().asId(doRecord.getEventType());
		StringBuffer sb = new StringBuffer();

		sb.append("\n>> DomainObjectChangeRecord");
		sb.append(String.format("[%d], event: %s[%d], class: %s\n",
			recordNum, eventTypeName, eventTypeId,
			doRecord.getClass().getName()));
		// Values old and new
		String oldv = DomainObjChangedEventFormatter.formatValue(
			doRecord.getOldValue(), "        old");
		String newv = DomainObjChangedEventFormatter.formatValue(
			doRecord.getNewValue(), "        new");
		sb.append(oldv + "\n" + newv);
		return sb.toString();
	}

	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		String marker = String.format("\nC-%s: ", this.getIdStr());
		String eventInfo = String.format("  SOURCE: %s, sourceType: %s, numChangeRecords: %d\n",
			event.getSource(), event.getSource().getClass().getName(),
			event.numRecords());

		if (ChangeManagerBridge.getInstance().containsRelevantSubEvent(event)) {
			sb.append("\n==== BEGIN ====\n");
			sb.append(eventInfo);
			for (int i = 0; i < event.numRecords(); ++i) {
				DomainObjectChangeRecord doRecord = event.getChangeRecord(i);
				if (ChangeManagerBridge.getInstance().isRelevant(doRecord.getEventType())) {
					sb.append(fmtDomainObjChangeRecord(i, doRecord));
					sb.append("\n==== END   ====\n");
				}
				else {
					sb.append("");
				}
			}
		}
		else {
			sb.append(eventInfo);
		}
		return sb.toString().replace("\n", marker);
	}
}
