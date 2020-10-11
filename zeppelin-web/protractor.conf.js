/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
var baseConfig = {
  baseUrl: 'http://localhost:8080/',
  directConnect: true,
  capabilities: {
    browserName: 'chrome',
  },
  allScriptsTimeout: 300000, // 5 min

  framework: 'jasmine',
  specs: ['e2e/**/*.js'],
  jasmineNodeOpts: {
    showTiming: true,
    showColors: true,
    isVerbose: true,
    includeStackTrace: false,
    defaultTimeoutInterval: 300000, // 5 min
    print: function() {}, // remove protractor dot reporter, we are using jasmine-spec-reporter
  },

  onPrepare: function() {
    // should be false for angular apps
    // browser.ignoreSynchronization = true;

    browser.manage().timeouts().pageLoadTimeout(300000);
    // with the implicitlyWait() this will even though you expect the element not to be there
    browser.manage().timeouts().implicitlyWait(30000);

    // add reporter to display executed tests in console
    var SpecReporter = require('jasmine-spec-reporter').SpecReporter;
    jasmine.getEnv().addReporter(new SpecReporter({
      spec: {
        displayStacktrace: true
      }
    }));
  },
};

var chromeOptions = {
  args: ['--disable-gpu', '--no-sandbox']
}

baseConfig.capabilities.chromeOptions = chromeOptions;

exports.config = baseConfig;
