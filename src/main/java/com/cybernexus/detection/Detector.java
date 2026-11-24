package com.cybernexus.detection;

import java.util.List;

/** Strategy for inspecting one kind of user input. */
public interface Detector {
    String getType();

    List<String> detect(String input);
}
