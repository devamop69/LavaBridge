const fs = require('fs');
const path = require('path');

// Load environment variables and config
require('dotenv').config();
const config = require('./config');

// Get the database directory from configuration
const databaseDir = config.database.dir;

// Ensure the database directory exists
if (!fs.existsSync(databaseDir)) {
  fs.mkdirSync(databaseDir, { recursive: true });
}

/**
 * Load data from a JSON file
 * @param {string} filename - The name of the file to load
 * @param {any} defaultValue - The default value to return if the file doesn't exist
 * @returns {any} The parsed JSON data or the default value
 */
function loadData(filename, defaultValue = {}) {
  const filePath = path.join(databaseDir, filename);
  try {
    if (fs.existsSync(filePath)) {
      const data = fs.readFileSync(filePath, 'utf8');
      return JSON.parse(data);
    }
    
    // If file doesn't exist, create it with the default value
    saveData(filename, defaultValue);
    return defaultValue;
  } catch (error) {
    console.error(`Error loading data from ${filePath}:`, error);
    return defaultValue;
  }
}

/**
 * Save data to a JSON file
 * @param {string} filename - The name of the file to save to
 * @param {any} data - The data to save
 * @returns {boolean} True if successful, false otherwise
 */
function saveData(filename, data) {
  const filePath = path.join(databaseDir, filename);
  try {
    // Create temporary file first to prevent data corruption
    const tempPath = `${filePath}.tmp`;
    fs.writeFileSync(tempPath, JSON.stringify(data, null, 2), 'utf8');
    
    // Rename to final filename (atomic operation)
    fs.renameSync(tempPath, filePath);
    return true;
  } catch (error) {
    console.error(`Error saving data to ${filePath}:`, error);
    return false;
  }
}

/**
 * Convert a Map to a serializable object
 * @param {Map} map - The Map to convert
 * @returns {Object} A serializable object
 */
function mapToObject(map) {
  const obj = {};
  map.forEach((value, key) => {
    // Handle Date objects for proper serialization
    obj[key] = serializeValue(value);
  });
  return obj;
}

/**
 * Convert a value to a serializable format, handling special cases
 * @param {any} value - The value to serialize
 * @returns {any} The serialized value
 */
function serializeValue(value) {
  if (value === null || value === undefined) {
    return value;
  }
  
  if (value instanceof Date) {
    return { __type: 'Date', iso: value.toISOString() };
  }
  
  if (Array.isArray(value)) {
    return value.map(item => serializeValue(item));
  }
  
  if (typeof value === 'object') {
    const obj = {};
    Object.entries(value).forEach(([k, v]) => {
      obj[k] = serializeValue(v);
    });
    return obj;
  }
  
  return value;
}

/**
 * Convert a serialized object back to a Map
 * @param {Object} obj - The object to convert
 * @returns {Map} A Map instance
 */
function objectToMap(obj) {
  const map = new Map();
  if (obj) {
    Object.entries(obj).forEach(([key, value]) => {
      map.set(key, deserializeValue(value));
    });
  }
  return map;
}

/**
 * Convert serialized values back to their original types
 * @param {any} value - The value to deserialize
 * @returns {any} The deserialized value
 */
function deserializeValue(value) {
  if (value === null || value === undefined) {
    return value;
  }
  
  // Special case for our Date serialization format
  if (value && typeof value === 'object' && value.__type === 'Date' && value.iso) {
    return new Date(value.iso);
  }
  
  if (Array.isArray(value)) {
    return value.map(item => deserializeValue(item));
  }
  
  if (typeof value === 'object') {
    // Handle known date field names for backward compatibility
    const dateFields = ['startTime', 'lastActive', 'lastChecked', 'lastStatusChange', 'timestamp'];
    
    const obj = {};
    Object.entries(value).forEach(([k, v]) => {
      if (typeof v === 'string' && dateFields.includes(k)) {
        try {
          const date = new Date(v);
          if (!isNaN(date.getTime())) {
            obj[k] = date;
            return;
          }
        } catch (e) {
          // Not a valid date string, continue with normal processing
        }
      }
      
      obj[k] = deserializeValue(v);
    });
    return obj;
  }
  
  return value;
}

/**
 * Ensure database files exist
 */
function ensureDatabaseFiles() {
  // Make sure all required database files exist
  loadData(config.database.connectionDb, {});
  loadData(config.database.ipUsageDb, {});
  loadData(config.database.backendStatusDb, {});
}

// Initialize database files
ensureDatabaseFiles();

module.exports = {
  loadData,
  saveData,
  mapToObject,
  objectToMap,
  ensureDatabaseFiles
}; 