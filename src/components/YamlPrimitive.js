import React, { useState, useRef, useEffect } from 'react';
import { getSeverityColors } from '../utils/severityUtils';

/**
 * Component for displaying primitive values with security highlighting
 */
const YamlPrimitive = ({ value, path, keyName, securityIssues, setSelectedIssue }) => {
  const [isHovered, setIsHovered] = useState(false);
  const elementRef = useRef(null);
  
  // Force key name to lowercase for case-insensitive comparison
  const lowerKeyName = keyName ? keyName.toLowerCase() : '';
  
  let valueDisplay;
  
  // We'll check for medium severity after finding the securityIssue
  if (typeof value === 'string') {
    // Special handling for dangerous capabilities
    if (path.includes('capabilities') && ['SYS_ADMIN', 'NET_ADMIN', 'ALL'].includes(value)) {
      // High severity for dangerous capabilities
      valueDisplay = <span className="text-red-400">"{value}"</span>;
    } else {
      valueDisplay = <span className="text-emerald-400">"{value}"</span>;
    }
  } else if (typeof value === 'number') {
    valueDisplay = <span className="text-blue-400">{value}</span>;
  } else if (typeof value === 'boolean') {
    // Force key name to lowercase for case-insensitive comparison
    const lowerKey = keyName ? keyName.toLowerCase() : '';
    
    // IMPORTANT: Only apply security-related colors when it's an insecure value (true for most flags)
    // Default for all other boolean values should be neutral
    if (value === true && ['privileged'].includes(lowerKey)) {
      // Critical severity - privileged:true
      valueDisplay = <span className="text-purple-400">{value.toString()}</span>;
    } else if (value === true && ['hostnetwork', 'hostpid', 'hostipc'].includes(lowerKey)) {
      // High severity - host*:true flags
      valueDisplay = <span className="text-red-400">{value.toString()}</span>;
    } else if (value === true && ['automountserviceaccounttoken'].includes(lowerKey)) {
      // Medium severity - but only when true
      valueDisplay = <span className="text-yellow-500">{value.toString()}</span>;
    } else if (value === true && ['allowprivilegeescalation'].includes(lowerKey)) {
      // Low severity for allowPrivilegeEscalation: true
      valueDisplay = <span className="text-yellow-400">{value.toString()}</span>;
    } else {
      // All other booleans including secure values (false for security flags)
      valueDisplay = <span className="text-gray-300">{value.toString()}</span>;
    }
  } else if (value === null || value === undefined) {
    valueDisplay = <span className="text-gray-500">null</span>;
  } else if (Array.isArray(value) && (keyName === 'verbs' || keyName === 'apiGroups' || keyName === 'resources')) {
    // Special handling for RBAC arrays to highlight individual dangerous values
    valueDisplay = renderRbacArray(value, keyName);
  } else {
    valueDisplay = <span className="text-gray-300">{String(value)}</span>;
  }
  
  // Special detection for known security-sensitive boolean and other values
  const isPotentialIssue = isSecuritySensitiveValue(value, keyName, lowerKeyName, path);
  
  // Check for paths following array pattern like "rules[0]" that might match this value
  const isInArray = (keyName && ['verbs', 'resources', 'apiGroups'].includes(keyName)) || 
                    ['verbs', 'resources', 'apigroups'].includes(lowerKeyName);
  const arrayIndex = path.match(/\[(\d+)\]/) ? path.match(/\[(\d+)\]/)[1] : null;
  
  // More precise issue matching to avoid highlighting parent nodes for child issues
  // Only consider secure settings
  const isSecureSetting = (
    (lowerKeyName === 'allowprivilegeescalation' && value === false) || // Only false is secure
    (lowerKeyName === 'runasuser' && typeof value === 'number' && value !== 0)
  );

  // Only look for security issues if it's not a secure setting
  const securityIssue = isSecureSetting ? null : findSecurityIssue(
    securityIssues, 
    path, 
    keyName, 
    value, 
    lowerKeyName, 
    isInArray, 
    arrayIndex,
    isPotentialIssue
  );
  
  useEffect(() => {
    if (isHovered && securityIssue && elementRef.current) {
      setSelectedIssue({
        issue: securityIssue,
        element: elementRef.current
      });
    }
  }, [isHovered, securityIssue, setSelectedIssue]);
  
  if (securityIssue) {
    // For Medium severity issues, only apply styling for specific insecure settings 
    if (securityIssue.severity === 'Medium' && typeof value !== 'object') {
      // Skip secure values - don't apply highlighting
      if ((keyName === 'allowPrivilegeEscalation' && value === false) || 
          (keyName === 'runAsUser' && value !== 0)) {
        // Don't change the valueDisplay for secure values
      } else if (typeof value === 'string') {
        valueDisplay = <span className="text-yellow-500">"{value}"</span>;
      } else if (typeof value === 'number' || typeof value === 'boolean') {
        valueDisplay = <span className="text-yellow-500">{String(value)}</span>;
      }
    }
    
    // Determine highlight colors based on severity
    const { borderClass, ringClass, bgClass, textClass } = getSeverityColors(securityIssue.severity);
    
    // For the special case of RBAC arrays with detailed highlighting
    if (Array.isArray(value) && (keyName === 'verbs' || keyName === 'apiGroups' || keyName === 'resources') && securityIssue) {
      return renderRbacArrayWithHighlighting(value, keyName, securityIssue, isInArray, arrayIndex, elementRef, isHovered, { borderClass, ringClass, bgClass, textClass }, setIsHovered);
    }

    // Skip highlighting secure settings - use already calculated isSecureSetting
    if (isSecureSetting) {
      return valueDisplay; // Return without security highlighting
    }
    
    return (
      <div 
        ref={elementRef}
        className="relative inline-block security-issue"
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        data-issue-id={securityIssue.path}
      >
        <span 
          className={`${bgClass} ${textClass} py-0.5 px-1 rounded border ${borderClass} ${isHovered ? `ring-2 ${ringClass}` : ''}`}
        >
          {valueDisplay}
        </span>
      </div>
    );
  }
  
  return valueDisplay;
};

// Helper function to determine if a value is security sensitive
const isSecuritySensitiveValue = (value, keyName, lowerKeyName, path) => {
  return (
    // Boolean security issues - only when set to true 
    (typeof value === 'boolean' && value === true && 
     ['privileged', 'hostnetwork', 'hostpid', 'hostipc', 'allowprivilegeescalation',
      'automountserviceaccounttoken'].includes(lowerKeyName)) ||
    // String/value security issues - only when runAsUser is 0
    (lowerKeyName === 'runasuser' && value === 0) ||
    // Check for dangerous capabilities - highlight individual capabilities, not the parent key
    (typeof value === 'string' && 
     (['sys_admin', 'net_admin', 'all'].includes(value.toLowerCase())) && 
     path.includes('capabilities')) ||
    // RBAC specific values - resources, verbs, apiGroups with wildcards or dangerous values
    ((['verbs', 'resources', 'apigroups'].includes(lowerKeyName)) && 
     Array.isArray(value) && 
     // Check for wildcards or dangerous values
     (value.includes('*') || 
      (lowerKeyName === 'resources' && value.some(resource => 
         ['pods', 'deployments', 'secrets', 'serviceaccounts', 'roles', 'clusterroles', 'rolebindings', 'clusterrolebindings'].includes(resource.toLowerCase().split('/')[0])
       )) ||
      (lowerKeyName === 'verbs' && value.some(verb => 
         ['create', 'update', 'patch', 'delete', 'deletecollection', 'impersonate', 'bind', 'escalate', 'get', 'list', 'watch'].includes(verb.toLowerCase())
       ))
     )
    )
  );
};

// Helper function to render RBAC arrays
const renderRbacArray = (value, keyName) => {
  return (
    <span className="text-gray-300">
      ['
      {value.map((item, index) => {
        let itemClass = "text-emerald-400"; // Default color for safe values
        
        if (keyName === 'verbs') {
          // Determine color based on verb severity
          if (item === '*') {
            itemClass = "text-purple-300 bg-purple-900/30 border border-purple-700 rounded px-1 py-0.5 shadow-sm"; // Critical - wildcard
          } else if (['create', 'update', 'patch', 'delete', 'deletecollection', 'impersonate', 'bind', 'escalate'].includes(item)) {
            itemClass = "text-red-300 bg-red-900/30 border border-red-700 rounded px-1 py-0.5 shadow-sm"; // High severity verbs
          } else if (['get', 'list', 'watch'].includes(item)) {
            itemClass = "text-yellow-300 bg-yellow-900/20 border border-yellow-600 rounded px-1 py-0.5 shadow-sm"; // Medium severity verbs
          }
        } else if (keyName === 'resources') {
          // For resources, highlight sensitive ones
          if (item === '*') {
            itemClass = "text-purple-300 bg-purple-900/30 border border-purple-700 rounded px-1 py-0.5 shadow-sm"; // Critical - wildcard 
          } else if (['secrets', 'pods', 'deployments', 'serviceaccounts', 'roles', 'clusterroles', 'rolebindings', 'clusterrolebindings'].includes(item.split('/')[0])) {
            itemClass = "text-red-300 bg-red-900/20 border border-red-700 rounded px-1 py-0.5 shadow-sm"; // Sensitive resources
          }
        } else if (keyName === 'apiGroups') {
          // For apiGroups, highlight wildcards
          if (item === '*') {
            itemClass = "text-purple-300 bg-purple-900/30 border border-purple-700 rounded px-1 py-0.5 shadow-sm"; // Critical - wildcard
          } else if (item === 'rbac.authorization.k8s.io') {
            itemClass = "text-red-300 bg-red-900/20 border border-red-700 rounded px-1 py-0.5 shadow-sm"; // Sensitive resources
          }
        }
        
        return (
          <React.Fragment key={index}>
            {index > 0 && ', '}
            <span className={itemClass}>
              "{item}"
            </span>
          </React.Fragment>
        );
      })}
      ']
    </span>
  );
};

// Helper function to find security issues
const findSecurityIssue = (securityIssues, path, keyName, value, lowerKeyName, isInArray, arrayIndex, isPotentialIssue) => {
  return securityIssues.find(issue => {
    // For RBAC verb issues 
    if ((keyName === 'verbs' || lowerKeyName === 'verbs') && Array.isArray(value) && isInArray) {
      // Check if this is a direct match to a verb in this array
      if (issue.path === path) {
        return true;
      }
      
      // For single-document YAMLs, path may not include document prefix
      // Check if the non-document part of the paths match
      const issuePath = issue.path.replace(/^document\[\d+\]\./, '');
      const simplePath = path.replace(/^document\[\d+\]\./, '');
      if (issuePath === simplePath) {
        return true;
      }
    }
    
    // Direct path match is the most specific
    if (issue.path === path) {
      return true;
    }
    
    // For single-document YAMLs, check if the non-document part of paths match
    const issuePath = issue.path.replace(/^document\[\d+\]\./, '');
    const simplePath = path.replace(/^document\[\d+\]\./, '');
    if (issuePath === simplePath) {
      return true;
    }
    
    // Match by key name for primitive values with specific issues
    if (keyName && issue.key === keyName) {
      // For boolean fields, only highlight if the value matches the issue (true for security flags)
      // Include allowprivilegeescalation as a known security flag
      const knownSecurityFlags = ['privileged', 'hostnetwork', 'hostpid', 'hostipc', 'allowprivilegeescalation'];
      
      if (typeof value === 'boolean' && knownSecurityFlags.includes(lowerKeyName)) {
        return value === true; // Only highlight if value is true (the insecure value)
      }
      // For runAsUser, only highlight if it's 0 (root)
      if (lowerKeyName === 'runasuser') {
        return value === 0; // Only highlight if runAsUser is 0 (root)
      }
      // For other cases - more careful matching
      return issue.value === value;
    }
    
    // Special matching for RBAC array items
    if (isInArray && arrayIndex) {
      // Check for direct match to this specific array item
      if (issue.path === path) {
        return true;
      }
      
      // More general check for rule-level issues
      if (issue.path.includes(`rules[${arrayIndex}]`)) {
        return true;
      }
    }
    
    // Special handling for potential security issues
    if (isPotentialIssue) {
      // For runAsUser=0 (root)
      if (lowerKeyName === 'runasuser' && value === 0 && issue.key && issue.key.toLowerCase() === 'runasuser') {
        return true;
      }
      
      // For dangerous capability values
      if (typeof value === 'string' && 
          (['sys_admin', 'net_admin', 'all'].includes(value.toLowerCase())) && 
          path.includes('capabilities') &&
          issue.value === value) {
        return true;
      }
      
      // For arrays with wildcards or dangerous values 
      if (['verbs', 'resources', 'apigroups'].includes(lowerKeyName) && Array.isArray(value)) {
        // Match on wildcard
        if (value.includes('*') && (issue.path.includes(keyName) || issue.path.toLowerCase().includes(lowerKeyName))) {
          return true;
        }
        
        // Match on dangerous verbs mentioned in the issue - only if path doesn't already match exactly
        if ((lowerKeyName === 'verbs') && 
            issue.value && 
            typeof issue.value === 'string') {
          // Extract verb from the issue value (like "create pods" or "* pods")
          const verbFromIssue = issue.value.split(' ')[0].toLowerCase();
          // Case insensitive check for verb in array
          if (verbFromIssue && value.some(v => v.toLowerCase() === verbFromIssue)) {
            return true;
          }
        }
        
        // Match on sensitive resources
        if ((lowerKeyName === 'resources') && 
            issue.value && 
            typeof issue.value === 'string') {
          // Extract resource from the issue value (like "create pods" or "get secrets")
          const parts = issue.value.split(' ');
          const resourceFromIssue = parts.length > 1 ? parts[1].toLowerCase() : null;
          // Case insensitive check for resource in array
          if (resourceFromIssue && value.some(r => r.toLowerCase() === resourceFromIssue)) {
            return true;
          }
        }
      }
    }
    
    return false;
  });
};

// Helper function to render RBAC arrays with security highlighting
const renderRbacArrayWithHighlighting = (value, keyName, securityIssue, isInArray, arrayIndex, elementRef, isHovered, styles, setIsHovered) => {
  const { borderClass, ringClass, bgClass } = styles;
  
  // Get dangerous value directly from the security issue or extract it from the compound issue value
  let dangerousValue;
  
  if (isInArray && arrayIndex) {
    // Direct match to this specific array item
    dangerousValue = securityIssue.value;
  } else if (securityIssue.value) {
    // Extract from compound value
    if (keyName === 'verbs') {
      dangerousValue = securityIssue.value.split(' ')[0];
    } else if (keyName === 'resources') {
      // For resources, extract the second part (e.g., "create pods" -> "pods")
      const parts = securityIssue.value.split(' ');
      dangerousValue = parts.length > 1 ? parts[1] : '*';
    } else if (keyName === 'apiGroups') {
      // For apiGroups, normally it's just '*'
      dangerousValue = '*';
    }
  }
  
  return (
    <div 
      ref={elementRef}
      className="relative inline-block security-issue"
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      data-issue-id={securityIssue.path}
    >
      <span 
        className={`${bgClass} py-0.5 px-1 rounded border ${borderClass} ${isHovered ? `ring-2 ${ringClass}` : ''}`}
      >
        <span className="text-inherit">
          ['
          {value.map((item, index) => {
            // Check if this is the dangerous item
            let isHighlighted = false;
            let isDangerous = false;
            
            if (keyName === 'verbs') {
              // Direct match if this is a specific verb issue
              if (isInArray && arrayIndex) {
                isHighlighted = securityIssue.value === item;
              } else {
                // Otherwise use extracted dangerous value
                isHighlighted = item === dangerousValue || (item === '*' && dangerousValue === '*');
              }
              isDangerous = ['create', 'update', 'patch', 'delete', 'deletecollection', 'impersonate', 'bind', 'escalate', '*'].includes(item);
            } else if (keyName === 'resources') {
              isHighlighted = item === dangerousValue || (item === '*' && dangerousValue === '*');
              isDangerous = ['secrets', 'pods', 'deployments', 'serviceaccounts', 'roles', 'clusterroles', 'rolebindings', 'clusterrolebindings', '*'].includes(item.split('/')[0]);
            } else if (keyName === 'apiGroups') {
              isHighlighted = item === '*';
              isDangerous = item === '*' || item === 'rbac.authorization.k8s.io';
            }
            
            // Determine color based on whether it's the highlighted item
            let itemClass = "text-emerald-400"; // Default color for safe items
            
            if (isHighlighted) {
              // Use security issue severity color for the specific item
              itemClass = securityIssue.severity === 'Critical' ? "text-purple-400" :
                         securityIssue.severity === 'High' ? "text-red-400" :
                         securityIssue.severity === 'Medium' ? "text-yellow-500" :
                         "text-yellow-400";
            } else if (isDangerous) {
              // Use a lighter version of the appropriate color for other dangerous items
              if (item === '*') {
                itemClass = "text-purple-400/70";  // Wildcard is Critical severity
              } else if (keyName === 'verbs' && ['create', 'update', 'patch', 'delete', 'deletecollection', 'impersonate', 'bind', 'escalate'].includes(item)) {
                itemClass = "text-red-400/70"; // High severity verbs
              } else if (keyName === 'verbs' && ['get', 'list', 'watch'].includes(item)) {
                itemClass = "text-yellow-500"; // Medium severity verbs - bright yellow for compatibility
              } else if (keyName === 'resources' && ['secrets', 'pods', 'deployments', 'serviceaccounts', 'roles', 'clusterroles'].includes(item.split('/')[0])) {
                itemClass = "text-red-400/70"; // Sensitive resources
              } else if (keyName === 'apiGroups' && item === 'rbac.authorization.k8s.io') {
                itemClass = "text-red-400/70"; // RBAC API group
              } else {
                itemClass = "text-yellow-500"; // Medium severity - bright yellow for compatibility
              }
            }
            
            return (
              <React.Fragment key={index}>
                {index > 0 && ', '}
                <span className={itemClass}>
                  "{item}"
                </span>
              </React.Fragment>
            );
          })}
          ']
        </span>
      </span>
    </div>
  );
};

export default YamlPrimitive;