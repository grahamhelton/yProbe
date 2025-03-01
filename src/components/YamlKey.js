import React, { useState, useRef, useEffect } from 'react';

/**
 * Component for displaying object keys with security highlighting
 */
const YamlKey = ({ keyName, path, securityIssues, indentLevel, setSelectedIssue }) => {
  const [isHovered, setIsHovered] = useState(false);
  const elementRef = useRef(null);
  
  // Force keyname to lowercase for case-insensitivity
  const lowerKeyName = keyName ? keyName.toLowerCase() : '';
  
  // Check if this key is a security-sensitive field
  const isSecurityKey = [
    // Privilege escalation related
    'privileged', 'hostnetwork', 'hostpid', 'hostipc', 'hostpath',
    // RBAC related - don't include 'verbs' or 'rules' here as we don't want to highlight them
    'roleref', 'subjects', 'serviceaccountname', 'automountserviceaccounttoken'
  ].includes(lowerKeyName);
  
  // securityContext itself shouldn't be highlighted - only the actual issue fields inside it
  const isSecurityContextKey = keyName === 'securityContext';
  
  // Special detection for RBAC rules
  const isRBACRulesKey = (keyName === 'roleRef' || keyName === 'subjects');
  
  // Find relevant security issue - more targeted matching to avoid parent keys being highlighted
  const securityIssue = findSecurityIssue(securityIssues, path, keyName, lowerKeyName, isSecurityKey, isSecurityContextKey, isRBACRulesKey);
  
  useEffect(() => {
    if (isHovered && securityIssue && elementRef.current) {
      setSelectedIssue({
        issue: securityIssue,
        element: elementRef.current
      });
    }
  }, [isHovered, securityIssue, setSelectedIssue]);
  
  if (securityIssue) {
    // Get colors based on severity
    const { textColorClass, ringColorClass } = getSeverityColorClasses(securityIssue.severity);
    
    return (
      <div 
        ref={elementRef}
        className="relative security-issue"
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        data-issue-id={securityIssue.path}
      >
        <div 
          className={`font-medium ${textColorClass} mr-2 ${isHovered ? `ring-1 ${ringColorClass} rounded px-1` : ''}`}
        >
          {keyName}:
        </div>
      </div>
    );
  }
  
  return <div className="font-medium text-green-400 mr-2">{keyName}:</div>;
};

// Helper function to get colors for keys based on severity
const getSeverityColorClasses = (severity) => {
  // Map to specific text color classes for keys
  let textColorClass = 'text-red-300';     // High (default)
  let ringColorClass = 'ring-red-400';     // High (default)
  
  // Updated color scheme: Critical=purple, High=red, Medium=orange, Low=yellow
  if (severity === 'Critical') {
    textColorClass = 'text-purple-300';
    ringColorClass = 'ring-purple-400';
  } else if (severity === 'Medium') {
    textColorClass = 'text-yellow-500';
    ringColorClass = 'ring-yellow-500';
  } else if (severity === 'Low') {
    textColorClass = 'text-yellow-300';
    ringColorClass = 'ring-yellow-400';
  }
  
  return { textColorClass, ringColorClass };
};

// Helper function to find relevant security issue
const findSecurityIssue = (securityIssues, path, keyName, lowerKeyName, isSecurityKey, isSecurityContextKey, isRBACRulesKey) => {
  return securityIssues.find(issue => {
    // NEVER highlight the 'rules' key
    if (keyName === 'rules') {
      return false;
    }
    
    // Special handling for security flags that are only issues when true
    if (lowerKeyName === 'allowprivilegeescalation' || lowerKeyName === 'automountserviceaccounttoken') {
      // Look for an issue that matches this specific path AND has value=true
      return issue.path === path && issue.value === true;
    }
    
    // Direct path match
    if (issue.path === path) return true;
    
    // For securityContext, only highlight if the issue is directly about securityContext
    // not its children
    if (isSecurityContextKey) {
      return issue.key === 'securityContext' && !issue.path.includes('.');
    }
    
    // Special handling for RBAC rules
    if (isRBACRulesKey && issue.path.includes(keyName)) {
      return true;
    }
    
    // All other security keys
    if (isSecurityKey && (issue.key === keyName)) {
      return true;
    }
    
    // NEVER highlight these RBAC array keys - we only want to highlight the dangerous values inside them
    if (keyName === 'verbs' || keyName === 'apiGroups' || keyName === 'resources' || keyName === 'rules') {
      return false;
    }
    
    return false;
  });
};

export default YamlKey;