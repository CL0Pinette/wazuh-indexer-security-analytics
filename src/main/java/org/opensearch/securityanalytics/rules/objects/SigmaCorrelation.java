/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import com.jayway.jsonpath.internal.filter.ValueNodes;
import org.opensearch.action.StepListener;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.fetch.subphase.FetchSourceContext;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.rules.aggregation.AggregationItem;
import org.opensearch.securityanalytics.rules.exceptions.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.opensearch.securityanalytics.util.RuleValidator.*;

public class SigmaCorrelation {

    public static final String EVENT_COUNT = "event_count";
    public static final String VALUE_COUNT = "value_count";
    public static final String TEMPORAL = "temporal";
    public static final String TEMPORAL_ORDERED = "temporal_ordered";
    public static final String VALUE_SUM = "value_sum";
    public static final String VALUE_AVG = "value_avg";
    public static final String VALUE_PERCENTILE = "value_percentile";


    private static final  List<String> allowedTypes = List.of(EVENT_COUNT, VALUE_COUNT, TEMPORAL, TEMPORAL_ORDERED, VALUE_SUM, VALUE_AVG, VALUE_PERCENTILE);

    private String type;

    private List<String> rules;

    private List<String> groupBys;

    private SigmaAliases aliases;

    private String timespan;

    private SigmaCorrelationCondition condition;

    public SigmaCorrelation(String type, List<String> rules, List<String> groupBys, SigmaAliases aliases, String timespan, SigmaCorrelationCondition condition) {
        this.type = type;
        this.rules = rules;
        this.groupBys =groupBys;
        this.aliases = aliases;
        this.timespan = timespan;
        this.condition = condition;
    }

    @SuppressWarnings("unchecked")
    protected static SigmaCorrelation fromDict(Map<String, Object> correlationMap) throws SigmaCorrelationError, SigmaModifierError, SigmaValueError, SigmaRegularExpressionError {
        String type = null;
        if (correlationMap.containsKey("type")) {
            type = (String) correlationMap.get("type");
            if (!allowedTypes.contains(type)) {
                throw new SigmaCorrelationError("Sigma correlation rule type must be in (event_count, value_count, temporal, temporal_ordered, value_sum, value_avg, value_percentile)");
            }
        }

        List<String> rules = new ArrayList<>();
        if (correlationMap.containsKey("rules") && correlationMap.get("rules") instanceof List) {
            rules.addAll((List<String>) correlationMap.get("rules"));
            for (String rule: rules) {
                // TODO: verify if rule exists
            }
        } else {
            throw new SigmaCorrelationError("Sigma correlation rule must contain at least one rule");
        }

        List<String> groupBys = new ArrayList<>();
        if (correlationMap.containsKey("group-by") && correlationMap.get("group-by") instanceof List) {
            groupBys.addAll((List<String>) correlationMap.get("group-by"));
            for (String groupBy: groupBys) {
                // TODO: verify if field exists
            }
        } else {
            throw new SigmaCorrelationError("Sigma correlation rule must contain at least one group-by");
        }

        SigmaAliases aliases = null;
        if (correlationMap.containsKey("aliases") && correlationMap.get("aliases") instanceof Map) {
            try {
                aliases = SigmaAliases.fromDict((Map<String, Object>) correlationMap.get("aliases"));
            } catch (SigmaAliasesError e) {
                throw new SigmaCorrelationError(e.getMessage());
            }
        }

        String timespan = null;
        if (correlationMap.containsKey("timespan")) {
            timespan = (String) correlationMap.get("timespan");
        }else {
            throw new SigmaCorrelationError("Sigma correlation rule timespan cannot be null");
        }

        SigmaCorrelationCondition condition = null;
        if (correlationMap.containsKey("condition") && correlationMap.get("condition") instanceof Map) {
            try {
                condition = SigmaCorrelationCondition.fromDict((Map<String, Object>) correlationMap.get("condition"));
            } catch (SigmaCorrelationConditionError e) {
                throw new SigmaCorrelationError(e.getMessage());
            }
        } else {
            throw new SigmaCorrelationError("Sigma correlation rule must contain one condition");
        }

        return new SigmaCorrelation(type, rules, groupBys, aliases, timespan, condition);
    }

    public String getType() {
        return type;
    }

    public List<String> getRules() {
        return rules;
    }

    public List<String> getGroupBys() {
        return groupBys;
    }

    public SigmaAliases getAliases() {
        return aliases;
    }

    public String getTimespan() {
        return timespan;
    }

    public SigmaCorrelationCondition getCondition() {
        return condition;
    }
}