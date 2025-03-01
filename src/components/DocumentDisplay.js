import React, { useState } from 'react';
import YamlRenderer from './YamlRenderer';
import SecuritySummary from './SecuritySummary';
import { isScannableKind, documentToString } from '../utils/yamlUtils';

/**
 * Component for displaying a single YAML document with headers
 * and scan capability status
 */
const DocumentDisplay = ({ document, index, securityIssues, setSelectedIssue, onFixAll, onUndo, canUndo = false }) => {
  // State for copy tooltip
  const [showCopyTooltip, setShowCopyTooltip] = useState(false);
  
  // Determine if this is part of a multi-document YAML
  const isMultiDoc = securityIssues.some(issue => issue.path && issue.path.startsWith('document['));
  if (!document) return null;
  
  // Function to copy document YAML to clipboard
  const handleCopyYaml = () => {
    const yamlString = documentToString(document);
    navigator.clipboard.writeText(yamlString).then(
      () => {
        setShowCopyTooltip(true);
        setTimeout(() => setShowCopyTooltip(false), 2000);
      },
      () => {
        // Silently fail - avoid console errors in production
        setShowCopyTooltip(false);
      }
    );
  };
  
  // Check if this document kind is scannable
  const isScannable = isScannableKind(document);
  
  // Get document-specific issues
  const documentIssues = securityIssues.filter(issue => 
    issue.documentIndex === undefined || issue.documentIndex === index
  );

  // Define whether this is a Pod workload for issue filtering
  // (Used for determining which issues to show in the security summary)
  const isPodWorkload = document.kind === 'Pod' || 
    document.kind === 'Deployment' || 
    document.kind === 'StatefulSet' || 
    document.kind === 'DaemonSet' || 
    document.kind === 'ReplicaSet' || 
    document.kind === 'Job' || 
    document.kind === 'CronJob';
  
  // Keep all security issues for display
  const filteredIssues = documentIssues;

  // Simplified function to count if there are any security issues
  // We don't need exact counts anymore, just presence of issues
  const hasAnySecurityIssues = (issues) => {
    return issues && issues.length > 0;
  };
  
  // Determine if this document has security issues
  const hasSecurityIssues = hasAnySecurityIssues(filteredIssues);
  
  return (
    <div className="border border-gray-700 rounded-md p-4 bg-gray-900/50 mb-8">
      <div className="mb-2 flex items-center justify-between">
        <div className="flex items-center">
          <div className="font-bold text-blue-400 flex items-center">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Document {index + 1}: {document.kind || 'Unknown'} {document.metadata?.name || ''}
          </div>
          
          <div className="flex items-center gap-2">
            {/* Copy YAML Button */}
            <div className="relative ml-2">
              <button 
                className="text-xs text-blue-500 hover:text-blue-400 border border-blue-500/40 hover:border-blue-400/60 rounded px-2 py-0.5 bg-blue-900/10 flex items-center transition-colors"
                onClick={handleCopyYaml}
              >
                <svg xmlns="http://www.w3.org/2000/svg" className="h-3 w-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7v8a2 2 0 002 2h6M8 7V5a2 2 0 012-2h4.586a1 1 0 01.707.293l4.414 4.414a1 1 0 01.293.707V15a2 2 0 01-2 2h-2M8 7H6a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2v-2" />
                </svg>
                Copy YAML
              </button>
              
              {/* Copy Success Tooltip */}
              {showCopyTooltip && (
                <div className="absolute top-full mt-1 left-0 text-xs text-green-400 bg-gray-900 border border-green-500/50 px-2 py-1 rounded shadow-lg whitespace-nowrap z-10">
                  Copied to clipboard!
                </div>
              )}
            </div>
            
            {/* Undo button - only show if undo is available and in multi-doc view */}
            {isMultiDoc && canUndo && onUndo && (
              <button 
                className="text-xs text-indigo-500 hover:text-indigo-400 border border-indigo-500/40 hover:border-indigo-400/60 rounded px-2 py-0.5 bg-indigo-900/10 flex items-center transition-colors"
                onClick={onUndo}
                title="Undo last security fix"
              >
                <svg xmlns="http://www.w3.org/2000/svg" className="h-3 w-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6" />
                </svg>
                Undo Last Fix
              </button>
            )}
          </div>
        </div>
        
        {/* Show security status */}
        <div className="flex items-center">
          {isScannable ? (
            hasSecurityIssues ? (
              <span className="text-xs text-red-400 border border-red-500/50 rounded px-2 py-0.5 bg-red-900/20 flex items-center">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-3 w-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                Security Issues Found
              </span>
            ) : (
              <span className="text-xs text-green-400 border border-green-500/50 rounded px-2 py-0.5 bg-green-900/20 flex items-center">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-3 w-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
                Secure
              </span>
            )
          ) : (
            <span className="text-xs text-yellow-400 border border-yellow-500/50 rounded px-2 py-0.5 bg-yellow-900/20 flex items-center">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-3 w-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              Not scanned for security
            </span>
          )}
        </div>
      </div>
      
      {/* Detailed warning for unscannable documents */}
      {!isScannable && (
        <div className="mb-3 text-xs text-yellow-300/80 italic">
          {document.kind === 'RoleBinding' || document.kind === 'ClusterRoleBinding' ? 
            `${document.kind} resources cannot be scanned for security issues. Only the referenced Roles/ClusterRoles contain the actual permissions.` :
            `${document.kind} resources cannot be scanned for security issues. Only Pod workloads and Role/ClusterRole resources are analyzed.`
          }
        </div>
      )}
      
      {/* Document-specific security summary */}
      {hasSecurityIssues && (
        <SecuritySummary 
          securityIssues={filteredIssues}
          onClickFixAll={() => onFixAll(document, index)}
          documentSpecific={true}
        />
      )}
      
      {/* Render the YAML document */}
      <YamlRenderer 
        data={document} 
        path={index === 0 && !isMultiDoc ? '' : `document[${index}]`}
        securityIssues={documentIssues}
        setSelectedIssue={setSelectedIssue}
      />
    </div>
  );
};

export default DocumentDisplay;