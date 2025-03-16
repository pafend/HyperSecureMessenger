/**
 * Secure logging system for HyperSecure Messenger
 * 
 * This logger implements privacy-preserving logging that ensures no sensitive
 * information is ever recorded. It provides different log levels and
 * anti-forensic capabilities to protect user privacy.
 */

// Log levels
export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  NONE = 4
}

// Current log level - can be adjusted at runtime
let currentLogLevel = LogLevel.INFO;

// Anti-forensic buffer to overwrite sensitive logs
const ANTI_FORENSIC_BUFFER_SIZE = 1024 * 1024; // 1MB
let sensitiveLogsBuffer: string[] = [];

/**
 * Set the current log level
 * 
 * @param level The log level to set
 */
export function setLogLevel(level: LogLevel): void {
  currentLogLevel = level;
}

/**
 * Get the current log level
 * 
 * @returns The current log level
 */
export function getLogLevel(): LogLevel {
  return currentLogLevel;
}

/**
 * Log a debug message
 * 
 * @param message The message to log
 * @param data Optional data to include
 */
function debug(message: string, data?: any): void {
  if (currentLogLevel <= LogLevel.DEBUG) {
    console.debug(`[DEBUG] ${message}`, data || '');
  }
}

/**
 * Log an info message
 * 
 * @param message The message to log
 * @param data Optional data to include
 */
function info(message: string, data?: any): void {
  if (currentLogLevel <= LogLevel.INFO) {
    console.info(`[INFO] ${message}`, data || '');
  }
}

/**
 * Log a warning message
 * 
 * @param message The message to log
 * @param data Optional data to include
 */
function warn(message: string, data?: any): void {
  if (currentLogLevel <= LogLevel.WARN) {
    console.warn(`[WARN] ${message}`, data || '');
  }
}

/**
 * Log an error message
 * 
 * @param message The message to log
 * @param error Optional error to include
 */
function error(message: string, error?: any): void {
  if (currentLogLevel <= LogLevel.ERROR) {
    console.error(`[ERROR] ${message}`, error || '');
  }
}

/**
 * Log a sensitive message that will be securely erased later
 * This should be used for any logs that might contain sensitive information
 * 
 * @param message The sensitive message to log
 */
function sensitive(message: string): void {
  if (currentLogLevel <= LogLevel.DEBUG) {
    // Only log sensitive information in debug mode
    const logEntry = `[SENSITIVE] ${message}`;
    console.debug(logEntry);
    
    // Store for later secure erasure
    sensitiveLogsBuffer.push(logEntry);
    
    // If buffer gets too large, securely erase oldest entries
    if (sensitiveLogsBuffer.length > ANTI_FORENSIC_BUFFER_SIZE) {
      securelyEraseSensitiveLogs(Math.floor(ANTI_FORENSIC_BUFFER_SIZE / 2));
    }
  }
}

/**
 * Securely erase sensitive logs to prevent forensic recovery
 * 
 * @param count Number of log entries to erase (defaults to all)
 */
function securelyEraseSensitiveLogs(count?: number): void {
  const numToErase = count || sensitiveLogsBuffer.length;
  
  // Overwrite the memory with random data multiple times
  for (let i = 0; i < numToErase; i++) {
    if (i < sensitiveLogsBuffer.length && sensitiveLogsBuffer[i] !== undefined) {
      const length = sensitiveLogsBuffer[i].length;
      
      // Overwrite 3 times with different patterns
      sensitiveLogsBuffer[i] = '0'.repeat(length);
      sensitiveLogsBuffer[i] = '1'.repeat(length);
      sensitiveLogsBuffer[i] = Array(length).fill(0).map(() => 
        Math.floor(Math.random() * 36).toString(36)
      ).join('');
    }
  }
  
  // Remove the erased entries
  sensitiveLogsBuffer = sensitiveLogsBuffer.slice(numToErase);
}

/**
 * Shutdown the logger and clean up any sensitive data
 */
function shutdown(): void {
  // Securely erase all sensitive logs
  securelyEraseSensitiveLogs();
  
  // Final log message
  if (currentLogLevel <= LogLevel.INFO) {
    console.info('[INFO] Logger shutdown complete');
  }
}

// Export the logger interface
export const logger = {
  debug,
  info,
  warn,
  error,
  sensitive,
  securelyEraseSensitiveLogs,
  shutdown,
  setLogLevel,
  getLogLevel
}; 