// Karma configuration
// Generated on Tue Jul 25 2017 09:02:14 GMT-0600 (MDT)

var PATH = require("path");

module.exports = function(config) {
  config.set({
    // base path that will be used to resolve all patterns (eg. files, exclude)
    basePath: ".",

    // frameworks to use
    // available frameworks: https://npmjs.org/browse/keyword/karma-adapter
    frameworks: ["mocha"],

    // list of files / patterns to load in the browser
    files: [
      "test/**/*-test.js"
    ],

    // preprocess matching files before serving them to the browser
    // available preprocessors: https://npmjs.org/browse/keyword/karma-preprocessor
    preprocessors: {
      "test/**/*-test.js": ["webpack", "sourcemap"]
    },

    // test results reporter to use
    // possible values: "dots", "progress"
    // available reporters: https://npmjs.org/browse/keyword/karma-reporter
    reporters: ["mocha", "coverage-istanbul"],

    // webpack configuration
    webpack: {
      devtool: "inline-source-map",
      module: {
        rules: [
          {
            test: /\.js$/,
            use: { loader: "istanbul-instrumenter-loader" },
            include: PATH.resolve("lib")
          }
        ]
      }
    },
    webpackMiddleware: {
      stats: "errors-only"
    },

    // coverage configuration
    coverageIstanbulReporter: {
      reports: ["html", "text-summary"],
      dir: PATH.resolve("coverage/%browser%"),
      fixWebpackSourcePaths: true
    },

    // web server port
    port: 9876,
    // enable / disable colors in the output (reporters and logs)
    colors: true,
    // level of logging
    // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
    logLevel: config.LOG_INFO,
    // enable / disable watching file and executing tests whenever any file changes
    autoWatch: false,

    customLaunchers: {
      "FirefoxHeadless": {
        base: "Firefox",
        flags: ["-headless"]
      }
    },

    // start these browsers
    // available browser launchers: https://npmjs.org/browse/keyword/karma-launcher
    browsers: ["FirefoxHeadless"],

    // Continuous Integration mode
    // if true, Karma captures browsers, runs the tests and exits
    singleRun: true,

    // Concurrency level
    // how many browser should be started simultaneous
    concurrency: Infinity
  })
}
