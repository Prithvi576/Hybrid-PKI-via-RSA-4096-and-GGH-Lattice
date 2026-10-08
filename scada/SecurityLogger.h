#pragma once

#include <string>

class SecurityLogger {
public:

    void info(const std::string& message);

    void warning(const std::string& message);

    void alert(const std::string& message);

private:

    void writeLog(
        const std::string& level,
        const std::string& message
    );
};
