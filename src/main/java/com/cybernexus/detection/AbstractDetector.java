package com.cybernexus.detection;

/** Shared string helpers for concrete detectors. */
public abstract class AbstractDetector implements Detector {
    protected boolean containsIgnoreCase(String text, String fragment) {
        return text != null && fragment != null
                && text.toLowerCase().contains(fragment.toLowerCase());
    }

    protected String lower(String text) {
        return text == null ? "" : text.toLowerCase();
    }
}
