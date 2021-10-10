import * as path from "path";
import * as log4js from "log4js";

const configure = function() {
    log4js.configure(path.join(__dirname, "log4js.json"));
}

const logger = function(name) {
    const dateFileLog = log4js.getLogger(name);
    // dateFileLog.level = log4js.levels.INFO;
    dateFileLog.level = "debug";
    return dateFileLog;
}

const useLog = function() {
    return log4js.connectLogger(log4js.getLogger("app"), {level: "debug"});
}

export { useLog, logger, configure };
