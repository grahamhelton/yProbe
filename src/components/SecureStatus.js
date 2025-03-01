import React from 'react';

/**
 * Component for displaying status messages when no security issues are found
 */
const SecureStatus = ({ isFixed, yamlData, error, securityIssues }) => {
  // If no data, or there's an error, or there are security issues, don't show the success message
  if (!yamlData || error || (securityIssues && securityIssues.length > 0)) return null;
  
  if (isFixed) {
    return (
      <div className="mb-4 p-3 bg-green-900/30 border-2 border-green-600/80 rounded animate-pulse">
        <div className="font-bold text-green-400 flex items-center">
          <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
          All Security Issues Fixed! 🎉
        </div>
        <p className="text-sm text-white mt-1">
          The YAML manifest has been updated to secure all pod specifications.
        </p>
      </div>
    );
  }
  
  return (
    <div className="mb-4 p-3 bg-green-900/30 border-2 border-green-600/80 rounded animate-pulse">
      <div className="font-bold text-green-400 flex items-center">
        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
        </svg>
        No Security Issues Detected! 🎉
      </div>
      <p className="text-sm text-white mt-1">
        This YAML manifest does not have any insecure pod specifications.
      </p>
    </div>
  );
};

export default SecureStatus;