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

public class SigmaAliases {

    private Map<String, SigmaAlias> aliases;

    public SigmaAliases(Map<String, SigmaAlias> aliases)  {
        this.aliases = aliases;
    }

    protected static SigmaAliases fromDict(Map<String, Object> aliasesMap) throws SigmaAliasesError {
        Map<String, SigmaAlias> aliases = new HashMap<>();
        for (String key: aliasesMap.keySet()) {
            try {
                aliases.put(key, SigmaAlias.fromDict((Map<String, Object>) aliasesMap.get(key)));
            } catch (SigmaAliasError e) {
                throw new SigmaAliasesError(e.getMessage());
            }
        }
        return new SigmaAliases(aliases);
    }

    public Map<String, SigmaAlias> getAliases() {
        return aliases;
    }
}