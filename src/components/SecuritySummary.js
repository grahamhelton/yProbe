import React from 'react';
import { groupSecurityIssuesByCategory } from '../utils/securityUtils';

/**
 * Component for displaying a summary of security issues
 */
const SecuritySummary = ({ 
  securityIssues, 
  onClickFixAll, 
  onUndo,
  canUndo = false,
  documentSpecific = false, 
  hideFixAllButton = false 
}) => {
  if (!securityIssues || securityIssues.length === 0) return null;
  
  // Group issues by category for the summary
  const issuesByCategory = groupSecurityIssuesByCategory(securityIssues);
  
  // Check if there are any RBAC issues
  const hasRbacIssues = issuesByCategory.RBAC && issuesByCategory.RBAC.length > 0;
  
  // Check if there are any pod security issues
  const hasPodIssues = 
    (issuesByCategory.PrivilegeEscalation && issuesByCategory.PrivilegeEscalation.length > 0) || 
    (issuesByCategory.Other && issuesByCategory.Other.length > 0);
  
  // We'll simplify this by just using the total count, no details by severity
  // since the highlighting in the code will provide the severity information
  
  // Removed special undo case
  
  // Determine the right bg color and icon based on the type of issues
  const isPodIssue = hasPodIssues;
  const isRbacIssue = hasRbacIssues;
  
  // Set background and border colors based on issue type
  let bgColor = "bg-red-900/40";
  let borderColor = "border-red-600/90";
  let textColor = "text-red-300";
  let icon = (
    <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
    </svg>
  );
  
  // For RBAC, use purple theme
  if (!isPodIssue && isRbacIssue) {
    bgColor = "bg-purple-900/40";
    borderColor = "border-purple-600/90";
    textColor = "text-purple-300";
    icon = (
      <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
      </svg>
    );
  }
  
  return (
    <div className={`mb-4 p-2 ${bgColor} border ${borderColor} rounded shadow-md backdrop-blur-sm`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          {/* Compact severity summary */}
          <div className="flex items-center space-x-2">
            {/* Only show pod security issue type if there are pod issues */}
            {isPodIssue && (
              <div className={`font-bold text-xs ${textColor} flex items-center`}>
                {icon}
                <span>Pod Security Issues</span>
              </div>
            )}
            
            {/* Show RBAC if there are RBAC issues */}
            {isRbacIssue && isPodIssue && (
              <div className="font-bold text-xs text-purple-400 flex items-center ml-2">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
                <span>RBAC Security Issues</span>
              </div>
            )}
            
            {/* Only show RBAC if there are no pod issues */}
            {isRbacIssue && !isPodIssue && (
              <div className={`font-bold text-xs ${textColor} flex items-center`}>
                {icon}
                <span>RBAC Security Issues</span>
              </div>
            )}
          </div>
          
          {/* We're removing the total count here to avoid confusion */}
          
          <span className="text-xs text-gray-400 italic">
            Hover over highlighted items
          </span>
        </div>
        
        {/* Fix All button - only shown for Pod issues */}
        {securityIssues.length > 0 && !hideFixAllButton && onClickFixAll && isPodIssue && (
          <button 
            className="px-2 py-1 bg-red-700 hover:bg-red-600 text-white rounded transition-all text-xs flex items-center whitespace-nowrap"
            onClick={onClickFixAll}
          >
            {icon}
            {documentSpecific ? 'Fix Pod Issues' : 'Fix All Issues'}
          </button>
        )}
      </div>
    </div>
  );
};

export default SecuritySummary;