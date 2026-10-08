#include "SecurityLogger.h"

#include <fstream>
#include <iostream>
#include <ctime>

void SecurityLogger::writeLog(
    const std::string& level,
    const std::string& message)
{
    std::ofstream logFile(
        "scada_security.log",
        std::ios::app
    );

    if (!logFile.is_open())
    {
        std::cerr << "Unable to open log file"
                  << std::endl;
        return;
    }

    std::time_t currentTime = std::time(nullptr);

    std::string timeString =
        std::ctime(&currentTime);

    // Remove newline added by ctime()
    if (!timeString.empty() &&
        timeString.back() == '\n')
    {
        timeString.pop_back();
    }

    logFile << "[" << timeString << "] "
            << "[" << level << "] "
            << message
            << std::endl;

    logFile.close();

    // Also display on terminal
    std::cout << "[" << level << "] "
              << message
              << std::endl;
}


void SecurityLogger::info(
    const std::string& message)
{
    writeLog("INFO", message);
}


void SecurityLogger::warning(
    const std::string& message)
{
    writeLog("WARNING", message);
}


void SecurityLogger::alert(
    const std::string& message)
{
    writeLog("ALERT", message);
}