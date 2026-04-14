/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import org.opensearch.securityanalytics.rules.condition.*;
import org.opensearch.securityanalytics.rules.exceptions.*;
import org.opensearch.securityanalytics.rules.modifiers.SigmaListModifier;
import org.opensearch.securityanalytics.rules.modifiers.SigmaModifier;
import org.opensearch.securityanalytics.rules.modifiers.SigmaModifierFacade;
import org.opensearch.securityanalytics.rules.modifiers.SigmaValueModifier;
import org.opensearch.securityanalytics.rules.types.SigmaNull;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.types.SigmaTypeFacade;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.*;
import java.util.stream.Collectors;

public class SigmaAlias {

    private Map<String, String> aliases;

    public SigmaAlias(Map<String, String> aliases) {
        this.aliases = aliases;
    }

    public static SigmaAlias fromDict(Map<String, Object> aliasMap) throws SigmaAliasError {
        Map<String, String> aliases = new HashMap<>();
        for (String item : aliasMap.keySet()) {
            try {
                aliases.put(item, (String) aliasMap.get(item));
            } catch (Exception e) {
                throw new SigmaAliasError("Sigma correlation rule error while mapping alias");
            }
        }
        return new SigmaAlias(aliases);
    }

    public Map<String, String> getAliases() {
        return aliases;
    }
}