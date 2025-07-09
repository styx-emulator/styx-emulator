// SPDX-License-Identifier: BSD-2-Clause
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
package compatability;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.EventType;
import ghidra.program.util.ProgramEvent;

public class ChangeManagerBridge {

    private static ChangeManagerBridge instance;

    private ChangeManagerBridge() {
    }

    public static ChangeManagerBridge getInstance() {
        if (instance == null) {
            instance = new ChangeManagerBridge();
        }
        return instance;
    }

    public static final EventType DOCR_INT_ADDRESS_SET_PROPERTY_MAP_ADDED =
        ProgramEvent.INT_PROPERTY_MAP_ADDED;
    public static final EventType DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED =
        ProgramEvent.INT_PROPERTY_MAP_CHANGED;
    public static final EventType DOCR_INT_ADDRESS_SET_PROPERTY_MAP_REMOVED =
        ProgramEvent.INT_PROPERTY_MAP_REMOVED;

    public static final int DOCR_INT_ADDRESS_SET_PROPERTY_MAP_ADDED_ID =
        DOCR_INT_ADDRESS_SET_PROPERTY_MAP_ADDED.getId();
    public static final int DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED_ID =
        DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED.getId();
    public static final int DOCR_INT_ADDRESS_SET_PROPERTY_MAP_REMOVED_ID =
        DOCR_INT_ADDRESS_SET_PROPERTY_MAP_REMOVED.getId();

    /**
     * When processing DomainObjectEventChanges for Ghidra, this is the list of the
     * ChangeRecord types we want to process (ie emit changes to the typhunix
     * broker.
     */
    private static final Set<ProgramEvent> KEEP_EVENTS = new HashSet<ProgramEvent>(Arrays.asList(
        ProgramEvent.DATA_TYPE_ADDED,
        ProgramEvent.DATA_TYPE_REMOVED,
        ProgramEvent.DATA_TYPE_MOVED,
        ProgramEvent.DATA_TYPE_RENAMED,
        ProgramEvent.DATA_TYPE_CHANGED,
        ProgramEvent.DATA_TYPE_SETTING_CHANGED,
        ProgramEvent.DATA_TYPE_REPLACED,
        ProgramEvent.SYMBOL_RENAMED,
        ProgramEvent.SYMBOL_ADDED));

    /**
    * filterChangeRecords(...)
    *
    * @param event - a DomainObjectChangeEvent which contains 1..N
    *              DomainObjectChangeRecord
    *              objects. If the DomainObjectChange record contains an event we
    *              are interest in,
    *              then filter throughit looking for all the change records we are
    *              interested in.
    *
    * @return a list of DomainObjectChangeRecords we want to process
    */

    public ArrayList<DomainObjectChangeRecord> filterChangeRecords(
            DomainObjectChangedEvent event) {

        ArrayList<DomainObjectChangeRecord> results = new ArrayList<DomainObjectChangeRecord>();

        boolean keepit = false;
        for (ProgramEvent e : KEEP_EVENTS) {
            if (event.contains(e)) {
                keepit = true;
                break;
            }
        }
        if (keepit) {
            for (int i = 0; i < event.numRecords(); ++i) {
                DomainObjectChangeRecord doRecord = event.getChangeRecord(i);
                if (KEEP_EVENTS.contains(doRecord.getEventType())) {
                    results.add(doRecord);
                }
            }
        }
        return results;
    }

    public boolean containsRelevantSubEvent(DomainObjectChangedEvent event) {
        for (ProgramEvent e : KEEP_EVENTS) {
            if (event.contains(e)) {
                return true;
            }
        }
        return false;
    }

    public String codeToString(EventType e) {
        return e.toString();
    }

    public int asId(EventType e) {
        return e.getId();
    }

    public boolean isRelevant(EventType eventType) {
        return KEEP_EVENTS.contains(eventType);
    }

}
