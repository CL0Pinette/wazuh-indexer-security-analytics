/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.exceptions;

public class SigmaCorrelationError extends SigmaError {

    public SigmaCorrelationError(String message) {
        super(message);
    }
}