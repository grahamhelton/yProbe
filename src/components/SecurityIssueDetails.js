import React from 'react';
import { getSeverityColors, getCategoryIcon, getSecurityRecommendation } from '../utils/severityUtils';

/**
 * Component for displaying security issue details in the sidebar
 */
const SecurityIssueDetails = ({ selectedIssue, onFixIssue, onUndo, canUndo }) => {
  // Removed standalone undo button
  
  if (!selectedIssue || !selectedIssue.issue) return null;
  
  const { issue, severity, description, documentIndex, category } = selectedIssue.issue;
  
  // Get colors based on severity
  const { borderClass, iconClass } = getSeverityColors(severity);
  
  // Get icon based on category
  const { path: iconPath } = getCategoryIcon(category);
  
  // Get security recommendation
  const recommendation = getSecurityRecommendation(selectedIssue.issue);
  
  return (
    <div className={`p-4 rounded bg-gray-800 border ${borderClass} shadow-lg`}>
      <div className="flex justify-between mb-2">
        {documentIndex !== undefined && (
          <div className="text-xs bg-blue-900/50 text-blue-300 rounded px-2 py-1 inline-block">
            Document {documentIndex + 1}
          </div>
        )}
        
        {category && (
          <div className={`text-xs rounded px-2 py-1 inline-flex items-center ${
            category === 'RBAC' ? 'bg-purple-900/50 text-purple-300' : 'bg-gray-900/50 text-gray-300'
          }`}>
            <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={iconPath} />
            </svg>
            {category}
          </div>
        )}
      </div>
      
      <h3 className={`text-lg font-bold ${iconClass} mb-2`}>{issue}</h3>
      <div className="flex items-center mb-3">
        <span className="font-semibold text-xs text-white mr-2">Severity:</span>
        <span className={`text-xs px-2 py-0.5 rounded ${
          severity === 'Critical' ? 'bg-purple-900 text-purple-200' :
          severity === 'High' ? 'bg-red-900 text-red-200' :
          severity === 'Medium' ? 'bg-transparent text-yellow-500 border-yellow-500' :
          'bg-transparent text-yellow-400 border-yellow-400'
        }`}>
          {severity}
        </span>
      </div>
      <div className="text-sm text-gray-300 mb-4">{description}</div>
      
      {/* Security Recommendation */}
      <div className="mb-4">
        <h4 className="text-blue-400 text-sm font-semibold flex items-center mb-2">
          <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
          Recommendation
        </h4>
        <div className="text-sm bg-blue-900/20 p-3 rounded border border-blue-800/40 text-gray-300">
          {recommendation}
        </div>
      </div>
      
      {/* Fix button for individual issue - only show for privilege escalation issues, never for RBAC */}
      {category !== 'RBAC' && (
        <button 
          onClick={() => onFixIssue(selectedIssue.issue)}
          className="w-full py-2 px-3 bg-green-700 hover:bg-green-600 text-white rounded-md flex items-center justify-center transition-all"
        >
          <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
          Fix This Issue
        </button>
      )}
      
      {/* For RBAC issues, show message about manual review needed */}
      {category === 'RBAC' && (
        <div className="text-sm text-blue-300 bg-blue-900/30 p-2 rounded border border-blue-700 mt-3">
          <span className="font-semibold">Manual Review Required:</span> RBAC permissions should be carefully reviewed and customized based on your application's specific needs and security requirements.
        </div>
      )}
    </div>
  );
};

export default SecurityIssueDetails;