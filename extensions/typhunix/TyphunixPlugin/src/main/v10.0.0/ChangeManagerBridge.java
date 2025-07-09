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
import ghidra.program.util.ChangeManager;

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

    public static final int DOCR_INT_ADDRESS_SET_PROPERTY_MAP_ADDED =
        ChangeManager.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_ADDED;
    public static final int DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED =
        ChangeManager.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED;
    public static final int DOCR_INT_ADDRESS_SET_PROPERTY_MAP_REMOVED =
        ChangeManager.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_REMOVED;

    public static final int DOCR_INT_ADDRESS_SET_PROPERTY_MAP_ADDED_ID =
        DOCR_INT_ADDRESS_SET_PROPERTY_MAP_ADDED;
    public static final int DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED_ID =
        DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED;
    public static final int DOCR_INT_ADDRESS_SET_PROPERTY_MAP_REMOVED_ID =
        DOCR_INT_ADDRESS_SET_PROPERTY_MAP_REMOVED;

    /**
     * When processing DomainObjectEventChanges for Ghidra, this is the list of the
     * ChangeRecord types we want to process (ie emit changes to the typhunix
     * broker.
     */
    private static final Set<Integer> KEEP_EVENTS = new HashSet<Integer>(Arrays.asList(
        ChangeManager.DOCR_DATA_TYPE_ADDED,
        ChangeManager.DOCR_DATA_TYPE_REMOVED,
        ChangeManager.DOCR_DATA_TYPE_MOVED,
        ChangeManager.DOCR_DATA_TYPE_RENAMED,
        ChangeManager.DOCR_DATA_TYPE_CHANGED,
        ChangeManager.DOCR_DATA_TYPE_SETTING_CHANGED,
        ChangeManager.DOCR_DATA_TYPE_REPLACED,
        ChangeManager.DOCR_SYMBOL_RENAMED,
        ChangeManager.DOCR_SYMBOL_ADDED));

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
        for (Integer i : KEEP_EVENTS) {
            if (event.containsEvent(i)) {
                keepit = true;
                break;
            }
        }
        if (keepit) {
            for (int i = 0; i < event.numRecords(); ++i) {
                DomainObjectChangeRecord doRecord = event.getChangeRecord(i);
                switch (doRecord.getEventType()) {
                    case ChangeManager.DOCR_DATA_TYPE_ADDED:
                    case ChangeManager.DOCR_DATA_TYPE_REMOVED:
                    case ChangeManager.DOCR_DATA_TYPE_RENAMED:
                    case ChangeManager.DOCR_DATA_TYPE_MOVED:
                    case ChangeManager.DOCR_DATA_TYPE_CHANGED:
                    case ChangeManager.DOCR_DATA_TYPE_SETTING_CHANGED:
                    case ChangeManager.DOCR_DATA_TYPE_REPLACED:
                    case ChangeManager.DOCR_SYMBOL_RENAMED:
                    case ChangeManager.DOCR_SYMBOL_ADDED:
                        results.add(doRecord);
                    default:
                        ;
                }
            }
        }
        return results;
    }

    public boolean containsRelevantSubEvent(DomainObjectChangedEvent event) {
        for (int e : KEEP_EVENTS) {
            if (event.containsEvent(e)) {
                return true;
            }
        }
        return false;
    }

    public String codeToString(int num) {
        switch (num) {
            ////////////////////////////////////////////////////////////////////////////
            //
            // MEMORY BLOCKS
            //
            ////////////////////////////////////////////////////////////////////////////
            case ChangeManager.DOCR_MEMORY_BLOCK_ADDED:
                return "DOCR_MEMORY_BLOCK_ADDED";
            case ChangeManager.DOCR_MEMORY_BLOCK_REMOVED:
                return "DOCR_MEMORY_BLOCK_REMOVED";
            case ChangeManager.DOCR_MEMORY_BLOCK_CHANGED:
                return "DOCR_MEMORY_BLOCK_CHANGED";
            case ChangeManager.DOCR_MEMORY_BLOCK_MOVED:
                return "DOCR_MEMORY_BLOCK_MOVED";
            case ChangeManager.DOCR_MEMORY_BLOCK_SPLIT:
                return "DOCR_MEMORY_BLOCK_SPLIT";
            case ChangeManager.DOCR_MEMORY_BLOCKS_JOINED:
                return "DOCR_MEMORY_BLOCKS_JOINED";
            case ChangeManager.DOCR_MEMORY_BYTES_CHANGED:
                return "DOCR_MEMORY_BYTES_CHANGED";
            case ChangeManager.DOCR_IMAGE_BASE_CHANGED:
                return "DOCR_IMAGE_BASE_CHANGED";
            ////////////////////////////////////////////////////////////////////////////
            //
            // CODE
            //
            ////////////////////////////////////////////////////////////////////////////
            case ChangeManager.DOCR_CODE_ADDED:
                return "DOCR_CODE_ADDED";
            case ChangeManager.DOCR_CODE_REMOVED:
                return "DOCR_CODE_REMOVED";
            case ChangeManager.DOCR_CODE_MOVED:
                return "DOCR_CODE_MOVED";
            case ChangeManager.DOCR_COMPOSITE_ADDED:
                return "DOCR_COMPOSITE_ADDED";
            case ChangeManager.DOCR_COMPOSITE_REMOVED:
                return "DOCR_COMPOSITE_REMOVED";
            case ChangeManager.DOCR_CODE_REPLACED:
                return "DOCR_CODE_REPLACED";
            case ChangeManager.DOCR_CODE_UNIT_PROPERTY_CHANGED:
                return "DOCR_CODE_UNIT_PROPERTY_CHANGED";
            case ChangeManager.DOCR_CODE_UNIT_PROPERTY_ALL_REMOVED:
                return "DOCR_CODE_UNIT_PROPERTY_ALL_REMOVED";
            case ChangeManager.DOCR_CODE_UNIT_PROPERTY_RANGE_REMOVED:
                return "DOCR_CODE_UNIT_PROPERTY_RANGE_REMOVED";
            ////////////////////////////////////////////////////////////////////////////
            //
            // SYMBOLS
            //
            ////////////////////////////////////////////////////////////////////////////
            case ChangeManager.DOCR_SYMBOL_ADDED:
                return "DOCR_SYMBOL_ADDED";
            case ChangeManager.DOCR_SYMBOL_REMOVED:
                return "DOCR_SYMBOL_REMOVED";
            case ChangeManager.DOCR_SYMBOL_SOURCE_CHANGED:
                return "DOCR_SYMBOL_SOURCE_CHANGED";
            case ChangeManager.DOCR_SYMBOL_ANCHORED_FLAG_CHANGED:
                return "DOCR_SYMBOL_ANCHORED_FLAG_CHANGED";
            case ChangeManager.DOCR_SYMBOL_SET_AS_PRIMARY:
                return "DOCR_SYMBOL_SET_AS_PRIMARY";
            case ChangeManager.DOCR_SYMBOL_RENAMED:
                return "DOCR_SYMBOL_RENAMED";
            case ChangeManager.DOCR_EXTERNAL_ENTRY_POINT_ADDED:
                return "DOCR_EXTERNAL_ENTRY_POINT_ADDED";
            case ChangeManager.DOCR_EXTERNAL_ENTRY_POINT_REMOVED:
                return "DOCR_EXTERNAL_ENTRY_POINT_REMOVED";
            case ChangeManager.DOCR_SYMBOL_SCOPE_CHANGED:
                return "DOCR_SYMBOL_SCOPE_CHANGED";
            case ChangeManager.DOCR_SYMBOL_ASSOCIATION_ADDED:
                return "DOCR_SYMBOL_ASSOCIATION_ADDED";
            case ChangeManager.DOCR_SYMBOL_ASSOCIATION_REMOVED:
                return "DOCR_SYMBOL_ASSOCIATION_REMOVED";
            case ChangeManager.DOCR_SYMBOL_DATA_CHANGED:
                return "DOCR_SYMBOL_DATA_CHANGED";
            case ChangeManager.DOCR_SYMBOL_ADDRESS_CHANGED:
                return "DOCR_SYMBOL_ADDRESS_CHANGED";
            ////////////////////////////////////////////////////////////
            //
            // REFERENCES
            //
            /////////////////////////////////////////////////////////////
            case ChangeManager.DOCR_MEM_REFERENCE_ADDED:
                return "DOCR_MEM_REFERENCE_ADDED";
            case ChangeManager.DOCR_MEM_REFERENCE_REMOVED:
                return "DOCR_MEM_REFERENCE_REMOVED";
            case ChangeManager.DOCR_MEM_REF_TYPE_CHANGED:
                return "DOCR_MEM_REF_TYPE_CHANGED";
            case ChangeManager.DOCR_MEM_REF_PRIMARY_SET:
                return "DOCR_MEM_REF_PRIMARY_SET";
            case ChangeManager.DOCR_MEM_REF_PRIMARY_REMOVED:
                return "DOCR_MEM_REF_PRIMARY_REMOVED";
            case ChangeManager.DOCR_EXTERNAL_PATH_CHANGED:
                return "DOCR_EXTERNAL_PATH_CHANGED";
            case ChangeManager.DOCR_EXTERNAL_NAME_ADDED:
                return "DOCR_EXTERNAL_NAME_ADDED";
            case ChangeManager.DOCR_EXTERNAL_NAME_REMOVED:
                return "DOCR_EXTERNAL_NAME_REMOVED";
            case ChangeManager.DOCR_EXTERNAL_NAME_CHANGED:
                return "DOCR_EXTERNAL_NAME_CHANGED";
            ////////////////////////////////////////////////////////////////////////////
            //
            // EQUATES
            //
            ////////////////////////////////////////////////////////////////////////////
            case ChangeManager.DOCR_EQUATE_ADDED:
                return "DOCR_EQUATE_ADDED";
            case ChangeManager.DOCR_EQUATE_REMOVED:
                return "DOCR_EQUATE_REMOVED";
            case ChangeManager.DOCR_EQUATE_REFERENCE_ADDED:
                return "DOCR_EQUATE_REFERENCE_ADDED";
            case ChangeManager.DOCR_EQUATE_REFERENCE_REMOVED:
                return "DOCR_EQUATE_REFERENCE_REMOVED";
            case ChangeManager.DOCR_EQUATE_RENAMED:
                return "DOCR_EQUATE_RENAMED";
            ////////////////////////////////////////////////////////////////////////////
            //
            // MODULES and FRAGMENTS
            //
            ////////////////////////////////////////////////////////////////////////////
            case ChangeManager.DOCR_DOCUMENT_CHANGED:
                return "DOCR_DOCUMENT_CHANGED";
            case ChangeManager.DOCR_GROUP_ADDED:
                return "DOCR_GROUP_ADDED";
            case ChangeManager.DOCR_GROUP_REMOVED:
                return "DOCR_GROUP_REMOVED";
            case ChangeManager.DOCR_GROUP_RENAMED:
                return "DOCR_GROUP_RENAMED";
            case ChangeManager.DOCR_GROUP_COMMENT_CHANGED:
                return "DOCR_GROUP_COMMENT_CHANGED";
            case ChangeManager.DOCR_GROUP_ALIAS_CHANGED:
                return "DOCR_GROUP_ALIAS_CHANGED";
            case ChangeManager.DOCR_MODULE_REORDERED:
                return "DOCR_MODULE_REORDERED";
            case ChangeManager.DOCR_FRAGMENT_MOVED:
                return "DOCR_FRAGMENT_MOVED";
            case ChangeManager.DOCR_GROUP_REPARENTED:
                return "DOCR_GROUP_REPARENTED";
            case ChangeManager.DOCR_EOL_COMMENT_CHANGED:
                return "DOCR_EOL_COMMENT_CHANGED";
            case ChangeManager.DOCR_PRE_COMMENT_CHANGED:
                return "DOCR_PRE_COMMENT_CHANGED";
            case ChangeManager.DOCR_POST_COMMENT_CHANGED:
                return "DOCR_POST_COMMENT_CHANGED";
            case ChangeManager.DOCR_REPEATABLE_COMMENT_CREATED:
                return "DOCR_REPEATABLE_COMMENT_CREATED";
            case ChangeManager.DOCR_REPEATABLE_COMMENT_ADDED:
                return "DOCR_REPEATABLE_COMMENT_ADDED";
            case ChangeManager.DOCR_PLATE_COMMENT_CHANGED:
                return "DOCR_PLATE_COMMENT_CHANGED";
            case ChangeManager.DOCR_REPEATABLE_COMMENT_CHANGED:
                return "DOCR_REPEATABLE_COMMENT_CHANGED";
            case ChangeManager.DOCR_REPEATABLE_COMMENT_REMOVED:
                return "DOCR_REPEATABLE_COMMENT_REMOVED";
            case ChangeManager.DOCR_REPEATABLE_COMMENT_DELETED:
                return "DOCR_REPEATABLE_COMMENT_DELETED";
            ////////////////////////////////////////////////////////////////////////////
            //
            // CATEGORY and DATA
            //
            ////////////////////////////////////////////////////////////////////////////
            case ChangeManager.DOCR_CATEGORY_ADDED:
                return "DOCR_CATEGORY_ADDED";
            case ChangeManager.DOCR_CATEGORY_REMOVED:
                return "DOCR_CATEGORY_REMOVED";
            case ChangeManager.DOCR_CATEGORY_RENAMED:
                return "DOCR_CATEGORY_RENAMED";
            case ChangeManager.DOCR_CATEGORY_MOVED:
                return "DOCR_CATEGORY_MOVED";
            case ChangeManager.DOCR_DATA_TYPE_ADDED:
                return "DOCR_DATA_TYPE_ADDED";
            case ChangeManager.DOCR_DATA_TYPE_REMOVED:
                return "DOCR_DATA_TYPE_REMOVED";
            case ChangeManager.DOCR_DATA_TYPE_RENAMED:
                return "DOCR_DATA_TYPE_RENAMED";
            case ChangeManager.DOCR_DATA_TYPE_MOVED:
                return "DOCR_DATA_TYPE_MOVED";
            case ChangeManager.DOCR_DATA_TYPE_CHANGED:
                return "DOCR_DATA_TYPE_CHANGED";
            case ChangeManager.DOCR_DATA_TYPE_SETTING_CHANGED:
                return "DOCR_DATA_TYPE_SETTING_CHANGED";
            case ChangeManager.DOCR_DATA_TYPE_REPLACED:
                return "DOCR_DATA_TYPE_REPLACED";
            case ChangeManager.DOCR_SOURCE_ARCHIVE_ADDED:
                return "DOCR_SOURCE_ARCHIVE_ADDED";
            case ChangeManager.DOCR_SOURCE_ARCHIVE_CHANGED:
                return "DOCR_SOURCE_ARCHIVE_CHANGED";
            ////////////////////////////////////////////////////////////////////////////
            //
            // BOOKMARKS
            //
            ////////////////////////////////////////////////////////////////////////////
            case ChangeManager.DOCR_BOOKMARK_TYPE_ADDED:
                return "DOCR_BOOKMARK_TYPE_ADDED";
            case ChangeManager.DOCR_BOOKMARK_TYPE_REMOVED:
                return "DOCR_BOOKMARK_TYPE_REMOVED";
            case ChangeManager.DOCR_BOOKMARK_ADDED:
                return "DOCR_BOOKMARK_ADDED";
            case ChangeManager.DOCR_BOOKMARK_REMOVED:
                return "DOCR_BOOKMARK_REMOVED";
            case ChangeManager.DOCR_BOOKMARK_CHANGED:
                return "DOCR_BOOKMARK_CHANGED";
            ////////////////////////////////////////////////////////////////////////////
            //
            // PROGRAMS
            //
            ////////////////////////////////////////////////////////////////////////////
            case ChangeManager.DOCR_LANGUAGE_CHANGED:
                return "DOCR_LANGUAGE_CHANGED";
            case ChangeManager.DOCR_REGISTER_VALUES_CHANGED:
                return "DOCR_REGISTER_VALUES_CHANGED";
            case ChangeManager.DOCR_OBJECT_CREATED:
                return "DOCR_OBJECT_CREATED";
            ///////////////////////////////////////////////////////////////////////
            //
            // Trees
            //
            ////////////////////////////////////////////////////////////////////////
            case ChangeManager.DOCR_TREE_RESTORED:
                return "DOCR_TREE_RESTORED";
            case ChangeManager.DOCR_TREE_CREATED:
                return "DOCR_TREE_CREATED";
            case ChangeManager.DOCR_TREE_REMOVED:
                return "DOCR_TREE_REMOVED";
            case ChangeManager.DOCR_TREE_RENAMED:
                return "DOCR_TREE_RENAMED";
            ////////////////////////////////////////////////////////////////////////////
            //
            // FUNCTIONS
            //
            ////////////////////////////////////////////////////////////////////////////
            case ChangeManager.DOCR_FUNCTION_TAG_CHANGED:
                return "DOCR_FUNCTION_TAG_CHANGED";
            case ChangeManager.DOCR_FUNCTION_TAG_CREATED:
                return "DOCR_FUNCTION_TAG_CREATED";
            case ChangeManager.DOCR_FUNCTION_TAG_DELETED:
                return "DOCR_FUNCTION_TAG_DELETED";
            case ChangeManager.DOCR_FUNCTION_ADDED:
                return "DOCR_FUNCTION_ADDED";
            case ChangeManager.DOCR_FUNCTION_REMOVED:
                return "DOCR_FUNCTION_REMOVED";
            case ChangeManager.DOCR_FUNCTION_CHANGED:
                return "DOCR_FUNCTION_CHANGED";
            case ChangeManager.DOCR_VARIABLE_REFERENCE_ADDED:
                return "DOCR_VARIABLE_REFERENCE_ADDED";
            case ChangeManager.DOCR_VARIABLE_REFERENCE_REMOVED:
                return "DOCR_VARIABLE_REFERENCE_REMOVED";
            case ChangeManager.DOCR_FUNCTION_BODY_CHANGED:
                return "DOCR_FUNCTION_BODY_CHANGED";
            case ChangeManager.DOCR_TAG_ADDED_TO_FUNCTION:
                return "DOCR_TAG_ADDED_TO_FUNCTION";
            case ChangeManager.DOCR_TAG_REMOVED_FROM_FUNCTION:
                return "DOCR_TAG_REMOVED_FROM_FUNCTION";
            ////////////////////////////////////////////////////////////////////////////
            //
            // DOCR_FUNCTION_CHANGED - Sub Event Types
            //
            ////////////////////////////////////////////////////////////////////////////
            case ChangeManager.FUNCTION_CHANGED_PURGE:
                return "FUNCTION_CHANGED_PURGE";
            case ChangeManager.FUNCTION_CHANGED_INLINE:
                return "FUNCTION_CHANGED_INLINE";
            case ChangeManager.FUNCTION_CHANGED_NORETURN:
                return "FUNCTION_CHANGED_NORETURN";
            case ChangeManager.FUNCTION_CHANGED_CALL_FIXUP:
                return "FUNCTION_CHANGED_CALL_FIXUP";
            case ChangeManager.FUNCTION_CHANGED_RETURN:
                return "FUNCTION_CHANGED_RETURN";
            case ChangeManager.FUNCTION_CHANGED_PARAMETERS:
                return "FUNCTION_CHANGED_PARAMETERS";
            case ChangeManager.FUNCTION_CHANGED_THUNK:
                return "FUNCTION_CHANGED_THUNK";
            ////////////////////////////////////////////////////////////////////////////
            //
            // MISC
            //
            ////////////////////////////////////////////////////////////////////////////
            case ChangeManager.DOCR_EXTERNAL_REFERENCE_ADDED:
                return "DOCR_EXTERNAL_REFERENCE_ADDED";
            case ChangeManager.DOCR_EXTERNAL_REFERENCE_REMOVED:
                return "DOCR_EXTERNAL_REFERENCE_REMOVED";
            ////////////////////////////////////////////////////////////////////////////
            case ChangeManager.DOCR_FALLTHROUGH_CHANGED:
                return "DOCR_FALLTHROUGH_CHANGED";
            case ChangeManager.DOCR_FLOWOVERRIDE_CHANGED:
                return "DOCR_FLOWOVERRIDE_CHANGED";
            ////////////////////////////////////////////////////////////////////////////
            case ChangeManager.DOCR_CUSTOM_FORMAT_ADDED:
                return "DOCR_CUSTOM_FORMAT_ADDED";
            case ChangeManager.DOCR_CUSTOM_FORMAT_REMOVED:
                return "DOCR_CUSTOM_FORMAT_REMOVED";
            ////////////////////////////////////////////////////////////////////////////
            //
            // AddressSetPropertyMap
            //
            ////////////////////////////////////////////////////////////////////////////
            case ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_REMOVED:
                return "DOCR_ADDRESS_SET_PROPERTY_MAP_REMOVED";
            case ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED:
                return "DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED";
            case ChangeManager.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_ADDED:
                return "DOCR_INT_ADDRESS_SET_PROPERTY_MAP_ADDED";
            case ChangeManager.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_REMOVED:
                return "DOCR_INT_ADDRESS_SET_PROPERTY_MAP_REMOVED";
            case ChangeManager.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED:
                return "DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED";
            ////////////////////////////////////////////////////////////////////////////
            //
            // MODULES and FRAGMENTS
            //
            ////////////////////////////////////////////////////////////////////////////
            case ChangeManager.DOCR_CODE_UNIT_USER_DATA_CHANGED:
                return "DOCR_CODE_UNIT_USER_DATA_CHANGED";
            case ChangeManager.DOCR_USER_DATA_CHANGED:
                return "DOCR_USER_DATA_CHANGED";

            default:
                return "UNDEFINED(" + num + ")";
        }
    }

    public int asId(int event) {
        return event;
    }

    public boolean isRelevant(int eventType) {
        return KEEP_EVENTS.contains(eventType);
    }

}
