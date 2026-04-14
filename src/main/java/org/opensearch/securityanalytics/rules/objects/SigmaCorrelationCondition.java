/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.apache.commons.lang3.tuple.Pair;
import org.opensearch.securityanalytics.rules.aggregation.AggregationItem;
import org.opensearch.securityanalytics.rules.aggregation.AggregationTraverseVisitor;
import org.opensearch.securityanalytics.rules.condition.*;
import org.opensearch.securityanalytics.rules.condition.aggregation.AggregationLexer;
import org.opensearch.securityanalytics.rules.condition.aggregation.AggregationParser;
import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaCorrelationConditionError;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.*;

public class SigmaCorrelationCondition {

    private Integer gt;

    private Integer gte;

    private Integer lt;

    private Integer lte;

    private Integer eq;

    private Integer neq;

    private List<String> fields;

    public SigmaCorrelationCondition( Integer gt, Integer gte, Integer lt, Integer lte, Integer eq, Integer neq, List<String> fields) {
        this.gt = gt;
        this.gte = gte;
        this.lt = lt;
        this.lte = lte;
        this.eq = eq;
        this.neq = neq;
        this.fields = fields;
    }

    public static SigmaCorrelationCondition fromDict(Map<String, Object> conditionMap) throws SigmaCorrelationConditionError {
        Integer gt = null;
        if (conditionMap.containsKey("gt")) {
            gt = (Integer) conditionMap.get("gt");
        }

        Integer gte = null;
        if (conditionMap.containsKey("gte")) {
            gte = (Integer) conditionMap.get("gte");
        }

        Integer lt = null;
        if (conditionMap.containsKey("lt")) {
            lt = (Integer) conditionMap.get("lt");
        }

        Integer lte = null;
        if (conditionMap.containsKey("lte")) {
            lte = (Integer) conditionMap.get("lte");
        }

        Integer eq = null;
        if (conditionMap.containsKey("eq")) {
            eq = (Integer) conditionMap.get("eq");
        }

        Integer neq = null;
        if (conditionMap.containsKey("neq")) {
            neq = (Integer) conditionMap.get("neq");
        }

        List<String> fields = null;
        if (conditionMap.containsKey("field") && conditionMap.get("field") instanceof List) {
            fields = (List<String>) conditionMap.get("field");
        } else if (conditionMap.containsKey("field") && conditionMap.get("field") instanceof String) {
            fields = List.of((String)conditionMap.get("field"));
        }
        return new SigmaCorrelationCondition(gt, gte, lt, lte, eq, neq, fields);
    }

    public Integer getGt() {
        return gt;
    }

    public Integer getGte() {
        return gte;
    }

    public Integer getLt() {
        return lt;
    }

    public Integer getLte() {
        return lte;
    }

    public Integer getEq() {
        return eq;
    }

    public Integer getNeq() {
        return neq;
    }

    public List<String> getFields() {
        return fields;
    }
}