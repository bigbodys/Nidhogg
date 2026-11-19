#include "pch.h"
#include "Logger.h"

/*
* Description:
* Log is responsible for logging messages to the debugger.
* Output goes through DbgPrint so it is visible without an IHVDRIVER filter mask.
*
* Parameters:
* @logLevel [_In_ LogLevel]    -- The log level.
* @format   [_In_ const char*] -- The format string.
* @argList  [_In_ va_list]     -- The argument list.
*
* Returns:
* There is no return value.
*/
void Logger::Log(_In_ LogLevel logLevel, _In_ const char* format, _In_ va_list argList) const {
    if (logLevel < LogLevel::Debug || logLevel > LogLevel::Error)
        return;

    if (level > logLevel)
        return;

    char prefix[sizeof(LOGGING_PREFIX) + MAX_LOG_LEVEL_PREFIX_LEN] = { 0 };
    NTSTATUS status = RtlStringCbPrintfA(prefix, sizeof(prefix),
        LOGGING_PREFIX "%s]: ",
        LogLevelPrefixes[static_cast<int>(logLevel)]);

    const char* prefixText = NT_SUCCESS(status) ? prefix : NO_PREFIX_LOGGING;
    char message[512] = { 0 };
    size_t prefixLength = 0;

    if (!NT_SUCCESS(RtlStringCbCopyA(message, sizeof(message), prefixText)) ||
        !NT_SUCCESS(RtlStringCbLengthA(message, sizeof(message), &prefixLength)) ||
        prefixLength >= sizeof(message) - 1) {
        DbgPrint("%s(log format failed)\n", NO_PREFIX_LOGGING);
        return;
    }

    RtlStringCbVPrintfA(message + prefixLength, sizeof(message) - prefixLength, format, argList);
    DbgPrint("%s", message);
}

/*
* Description:
* Debug is responsible for logging debug messages to the debugger.
*
* Parameters:
* @format [_In_ const char*] -- The format string.
* @...    [_In_]             -- The arguments.
*
* Returns:
* There is no return value.
*/
void Logger::Debug(const char* format, ...) const {
    va_list argList;
    va_start(argList, format);
    Log(LogLevel::Debug, format, argList);
    va_end(argList);
}

/*
* Description:
* Info is responsible for logging info messages to the debugger.
*
* Parameters:
* @format [_In_ const char*] -- The format string.
* @...    [_In_]             -- The arguments.
*
* Returns:
* There is no return value.
*/
void Logger::Info(const char* format, ...) const {
    va_list argList;
    va_start(argList, format);
    Log(LogLevel::Info, format, argList);
    va_end(argList);
}

/*
* Description:
* Warning is responsible for logging warning messages to the debugger.
*
* Parameters:
* @format [_In_ const char*] -- The format string.
* @...    [_In_]             -- The arguments.
*
* Returns:
* There is no return value.
*/
void Logger::Warning(const char* format, ...) const {
    va_list argList;
    va_start(argList, format);
    Log(LogLevel::Warning, format, argList);
    va_end(argList);
}

/*
* Description:
* Error is responsible for logging error messages to the debugger.
*
* Parameters:
* @format [_In_ const char*] -- The format string.
* @...    [_In_]             -- The arguments.
*
* Returns:
* There is no return value.
*/
void Logger::Error(const char* format, ...) const {
    va_list argList;
    va_start(argList, format);
    Log(LogLevel::Error, format, argList);
    va_end(argList);
}
