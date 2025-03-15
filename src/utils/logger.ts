/**
 * Logger utility for HyperSecure Messenger
 * Provides secure logging with sensitive data protection
 */

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LoggerOptions {
  level: LogLevel;
  enableConsole: boolean;
  redactSensitiveData: boolean;
}

const DEFAULT_OPTIONS: LoggerOptions = {
  level: 'info',
  enableConsole: true,
  redactSensitiveData: true
};

class SecureLogger {
  private options: LoggerOptions;
  
  constructor(options: Partial<LoggerOptions> = {}) {
    this.options = {
      ...DEFAULT_OPTIONS,
      ...options
    };
  }
  
  private shouldLog(level: LogLevel): boolean {
    const levels: Record<LogLevel, number> = {
      debug: 0,
      info: 1,
      warn: 2,
      error: 3
    };
    
    return levels[level] >= levels[this.options.level];
  }
  
  private formatMessage(level: LogLevel, message: string, meta?: unknown): string {
    const timestamp = new Date().toISOString();
    let metaStr = '';
    
    if (meta) {
      if (this.options.redactSensitiveData) {
        meta = this.redactSensitiveData(meta);
      }
      
      metaStr = typeof meta === 'string' ? meta : JSON.stringify(meta);
    }
    
    return `[${timestamp}] [${level.toUpperCase()}] ${message}${metaStr ? ` ${metaStr}` : ''}`;
  }
  
  private redactSensitiveData(data: unknown): unknown {
    if (typeof data !== 'object' || data === null) {
      return data;
    }
    
    // Clone to avoid mutating the original
    const cloned = Array.isArray(data) ? [...data] : { ...data };
    
    const sensitiveKeys = [
      'password', 'token', 'key', 'secret', 'auth', 
      'credential', 'private', 'seed', 'mnemonic'
    ];
    
    Object.keys(cloned).forEach(key => {
      const lowerKey = key.toLowerCase();
      
      // Redact sensitive fields
      if (sensitiveKeys.some(sk => lowerKey.includes(sk))) {
        (cloned as Record<string, unknown>)[key] = '[REDACTED]';
      } 
      // Recursively process nested objects
      else if (typeof (cloned as Record<string, unknown>)[key] === 'object' && (cloned as Record<string, unknown>)[key] !== null) {
        (cloned as Record<string, unknown>)[key] = this.redactSensitiveData((cloned as Record<string, unknown>)[key]);
      }
    });
    
    return cloned;
  }
  
  public debug(message: string, meta?: unknown): void {
    if (this.shouldLog('debug')) {
      const formattedMessage = this.formatMessage('debug', message, meta);
      if (this.options.enableConsole) {
        console.debug(formattedMessage);
      }
    }
  }
  
  public info(message: string, meta?: unknown): void {
    if (this.shouldLog('info')) {
      const formattedMessage = this.formatMessage('info', message, meta);
      if (this.options.enableConsole) {
        console.info(formattedMessage);
      }
    }
  }
  
  public warn(message: string, meta?: unknown): void {
    if (this.shouldLog('warn')) {
      const formattedMessage = this.formatMessage('warn', message, meta);
      if (this.options.enableConsole) {
        console.warn(formattedMessage);
      }
    }
  }
  
  public error(message: string, meta?: unknown): void {
    if (this.shouldLog('error')) {
      const formattedMessage = this.formatMessage('error', message, meta);
      if (this.options.enableConsole) {
        console.error(formattedMessage);
      }
    }
  }
}

// Create and export the default logger instance
export const logger = new SecureLogger(); 