/**
 * Utilities for YAML parsing and processing
 */
import yaml from 'js-yaml';
import _ from 'lodash';

// List of Kubernetes resource kinds that can be scanned for security issues
export const SCANNABLE_KINDS = [
  // Pod resources and workloads
  'Pod', 'Deployment', 'DaemonSet', 'StatefulSet', 'ReplicaSet', 'Job', 'CronJob',
  // RBAC resources - only Role and ClusterRole are actually scanned
  'Role', 'ClusterRole'
];

/**
 * Check if a document is of a kind that can be scanned for security issues
 * @param {Object} doc - The Kubernetes resource document
 * @returns {boolean} - True if the resource can be scanned
 */
export const isScannableKind = (doc) => {
  if (!doc || typeof doc !== 'object' || !doc.kind) {
    return false;
  }
  return SCANNABLE_KINDS.includes(doc.kind);
};

/**
 * Parse YAML content, handling multiple documents
 * @param {string} content - YAML content to parse
 * @returns {{parsed: Object|Array, isMultiDoc: boolean}} - Parsed data and flag for multiple documents
 */
export const parseYamlContent = (content) => {
  // Parse the YAML content with loadAll to handle multiple documents
  const documents = yaml.loadAll(content);
  
  const isMultiDoc = documents.length > 1;
  const parsedData = isMultiDoc ? documents : documents[0];
  
  return { 
    parsed: parsedData, 
    isMultiDoc,
    documents
  };
};

/**
 * Convert YAML data back to string format
 * @param {Object|Array} data - YAML data to convert
 * @param {boolean} isMultiDoc - Whether the data is multiple documents
 * @returns {string} - YAML string representation
 */
export const yamlDataToString = (data, isMultiDoc) => {
  const dumpOptions = { 
    indent: 2,
    quotingType: '"', // Force double quotes
    forceQuotes: true // Make sure strings are quoted
  };
  
  if (isMultiDoc) {
    return data.map(doc => yaml.dump(doc, dumpOptions)).join('---\n');
  }
  return yaml.dump(data, dumpOptions);
};

/**
 * Convert a single document to YAML string
 * @param {Object} doc - Single YAML document to convert
 * @returns {string} - YAML string representation
 */
export const documentToString = (doc) => {
  return yaml.dump(doc, { 
    indent: 2,
    quotingType: '"', // Force double quotes
    forceQuotes: true // Make sure strings are quoted
  });
};

/**
 * Extract document types and structure for display
 * @param {Array|Object} data - YAML data
 * @returns {Array} - Array of document info objects
 */
export const getDocumentInfo = (data) => {
  if (!data) return [];
  
  if (Array.isArray(data)) {
    return data.map((doc, index) => ({
      index,
      kind: doc?.kind || 'Unknown',
      name: doc?.metadata?.name || '',
      isScannable: isScannableKind(doc),
      namespace: doc?.metadata?.namespace || 'default'
    }));
  }
  
  return [{
    index: 0,
    kind: data?.kind || 'Unknown',
    name: data?.metadata?.name || '',
    isScannable: isScannableKind(data),
    namespace: data?.metadata?.namespace || 'default'
  }];
};

/**
 * Create a deep clone of YAML data
 * @param {Object|Array} data - Data to clone
 * @returns {Object|Array} - Cloned data
 */
export const cloneYamlData = (data) => {
  return _.cloneDeep(data);
};