/*
 * Copyright (C) 2016 The Android Open Source Project
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

package com.android.apksigner;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Command-line tool for signing APKs and for checking whether an APK's signature are expected to
 * verify on Android devices.
 */
public class ApkSignerTool {

    private static final String VERSION = "0.0.0";
    private static final String USAGE_PAGE_GENERAL = "usage_general.txt";

    public static void main(String[] params) throws Exception {
        GeneralOptions generalOptions = new GeneralOptions();
        OptionsParser optionsParser = new OptionsParser(params);
        String optionName;
        while ((optionName = optionsParser.nextOption()) != null) {
            if (("h".equals(optionName)) || ("help".equals(optionName))) {
                printUsage(USAGE_PAGE_GENERAL);
                return;
            } else if ("version".equals(optionName)) {
                System.out.println(VERSION);
                return;
            } else if (("v".equals(optionName)) || ("verbose".equals(optionName))) {
                generalOptions.verbose = optionsParser.getOptionalBooleanValue(true);
            } else if ("Wall".equals(optionName)) {
                generalOptions.warningsTreatedAsErrors =
                        optionsParser.getOptionalBooleanValue(true);
            } else {
                throw new ParameterException(
                        "Unsupported option: " + optionsParser.getOptionOriginalForm()
                                + ". See --help for supported options.");
            }
        }

        params = optionsParser.getRemainingParams();
        if (params.length == 0) {
            printUsage(USAGE_PAGE_GENERAL);
            return;
        }
        String cmd = params[0];
        try {
            if ("sign".equals(cmd)) {
                sign(generalOptions, Arrays.copyOfRange(params, 1, params.length));
                return;
            } else if ("verify".equals(cmd)) {
                verify(generalOptions, Arrays.copyOfRange(params, 1, params.length));
                return;
            } else if ("help".equals(cmd)) {
                printUsage(USAGE_PAGE_GENERAL);
                return;
            } else if ("version".equals(cmd)) {
                System.out.println(VERSION);
                return;
            } else {
                throw new ParameterException(
                        "Unsupported command: " + cmd + ". See --help for supported commands");
            }
        } catch (ParameterException | OptionsParser.OptionsException e) {
            System.err.println(e.getMessage());
            System.exit(1);
            return;
        }
    }

    private static void sign(GeneralOptions generalOptions, String[] params) throws Exception {
        throw new ParameterException("sign command not yet implemented");
    }

    private static void verify(GeneralOptions generalOptions, String[] params) throws Exception {
        throw new ParameterException("verify command not yet implemented");
    }

    private static void printUsage(String page) {
        try (BufferedReader in =
                new BufferedReader(
                        new InputStreamReader(
                                ApkSignerTool.class.getResourceAsStream(page),
                                StandardCharsets.UTF_8))) {
            String line;
            while ((line = in.readLine()) != null) {
                System.out.println(line);
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to read " + page + " resource");
        }
    }

    private static class GeneralOptions {
        boolean verbose;
        boolean warningsTreatedAsErrors;
    }

    /**
     * Indicates that there is an issue with command-line parameters provided to this tool.
     */
    private static class ParameterException extends Exception {
        private static final long serialVersionUID = 1L;

        ParameterException(String message) {
            super(message);
        }
    }
}
