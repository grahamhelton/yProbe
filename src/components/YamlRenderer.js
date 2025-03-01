import React from 'react';
import YamlPrimitive from './YamlPrimitive';
import YamlKey from './YamlKey';

/**
 * Main YAML renderer component that recursively renders YAML data
 * with security highlighting
 */
const YamlRenderer = ({ data, path = '', securityIssues, indentLevel = 0, setSelectedIssue }) => {
  // Handle null/undefined values
  if (data === null || data === undefined) {
    return <YamlPrimitive value={null} path={path} securityIssues={securityIssues} setSelectedIssue={setSelectedIssue} />;
  }
  
  // Handle primitive values
  if (typeof data !== 'object') {
    const keyName = path.split('.').pop();
    return <YamlPrimitive 
      value={data} 
      path={path} 
      keyName={keyName} 
      securityIssues={securityIssues} 
      setSelectedIssue={setSelectedIssue}
    />;
  }
  
  // Handle arrays
  if (Array.isArray(data)) {
    return (
      <div className="ml-4">
        {data.map((item, index) => (
          <div key={`${path}-${index}`} className="flex">
            <div className="text-gray-500 mr-2">- </div>
            <div className="flex-grow">
              <YamlRenderer 
                data={item} 
                path={`${path}[${index}]`} 
                securityIssues={securityIssues}
                indentLevel={indentLevel + 1}
                setSelectedIssue={setSelectedIssue}
              />
            </div>
          </div>
        ))}
      </div>
    );
  }
  
  // Check if this is a rules object in a Role/ClusterRole
  const isRBACRules = path && path.endsWith('.rules');
  
  // Handle objects
  return (
    <div className={`ml-4 ${indentLevel > 0 ? 'border-l border-gray-800' : ''}`}>
      {Object.entries(data).map(([key, value]) => {
        const childPath = path ? `${path}.${key}` : key;
        
        // Check if this is a rule in a Role/ClusterRole rules array
        const isRBACRule = isRBACRules && !isNaN(key);
        
        // Check if this rule has any security issues
        const ruleIssue = isRBACRule ? findRuleSecurityIssue(securityIssues, key) : null;
        const hasRuleIssue = !!ruleIssue;
        
        // Determine rule box style based on whether there's an issue and severity
        let ruleBoxClassName = '';
        if (isRBACRule) {
          ruleBoxClassName = getRuleBoxClassName(hasRuleIssue, ruleIssue);
        }
        
        return (
          <div 
            key={`${path}-${key}`} 
            className={ruleBoxClassName}
            data-issue-id={hasRuleIssue ? `rules[${key}]` : undefined}
            data-rule-index={key}
          >
            <div className="flex">
              <YamlKey 
                keyName={key} 
                path={childPath} 
                securityIssues={securityIssues}
                indentLevel={indentLevel}
                setSelectedIssue={setSelectedIssue}
              />
              {typeof value === 'object' && value !== null ? 
                null : 
                <YamlRenderer 
                  data={value} 
                  path={childPath} 
                  securityIssues={securityIssues}
                  indentLevel={indentLevel + 1}
                  setSelectedIssue={setSelectedIssue}
                />
              }
            </div>
            {typeof value === 'object' && value !== null && (
              <div className={isRBACRule ? 'pl-2 border-l-2 border-purple-800/30' : ''}>
                <YamlRenderer 
                  data={value} 
                  path={childPath} 
                  securityIssues={securityIssues}
                  indentLevel={indentLevel + 1}
                  setSelectedIssue={setSelectedIssue}
                />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

// Helper function to find security issues for RBAC rules
const findRuleSecurityIssue = (securityIssues, ruleIndex) => {
  return securityIssues.find(issue => 
    issue.path.includes(`rules[${ruleIndex}]`) || 
    (issue.path.includes('rules') && issue.path.includes(ruleIndex)) ||
    (issue.key === 'rules' && !isNaN(ruleIndex))
  );
};

// Helper function to get rule box class name based on severity
const getRuleBoxClassName = (hasIssue, issue) => {
  if (!hasIssue) {
    return 'mt-2 mb-2 p-2 border rounded border-purple-800/30';
  }
  
  // Style based on severity
  switch (issue.severity) {
    case 'Critical':
      return 'mt-2 mb-2 p-2 border rounded border-purple-600 bg-purple-900/30 shadow-inner';
    case 'High':
      return 'mt-2 mb-2 p-2 border rounded border-red-600 bg-red-900/30 shadow-inner';
    case 'Medium':
      return 'mt-2 mb-2 p-2 border rounded border-yellow-600 bg-yellow-900/20 shadow-inner';
    case 'Low':
      return 'mt-2 mb-2 p-2 border rounded border-yellow-500 bg-yellow-900/10 shadow-inner';
    default:
      return 'mt-2 mb-2 p-2 border rounded border-purple-800/30 shadow-sm';
  }
};

export default YamlRenderer;