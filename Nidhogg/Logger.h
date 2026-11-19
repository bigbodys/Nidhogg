#pragma once
#include "pch.h"

#define LOGGING_PREFIX "[XXXX :: "
constexpr CHAR NO_PREFIX_LOGGING[] = "[XXXX]: ";
constexpr ULONG64 LOG_LEVELS_COUNT = 4;
constexpr SIZE_T MAX_LOG_LEVEL_PREFIX_LEN = 12;

enum class LogLevel {
	Debug,
	Info,
	Warning,
	Error
};
constexpr LogLevel DefaultLogLevel = LogLevel::Debug;

class Logger {
private:
	LogLevel level;
	static constexpr const char* LogLevelPrefixes[LOG_LEVELS_COUNT] = {
		"Debug",
		"Info",
		"Warning",
		"Error"
	};

public:
	constexpr Logger() : Logger(DefaultLogLevel) {}
	constexpr Logger(_In_ LogLevel level) : level(level) {}
	~Logger() = default;
	void Log(_In_ LogLevel logLevel, _In_ const char* format, _In_ va_list argList) const;
	void Debug(const char* format, ...) const;
	void Info(const char* format, ...) const;
	void Warning(const char* format, ...) const;
	void Error(const char* format, ...) const;
};
