import React from 'react';

/**
 * Component for displaying demo info banners
 */
const DemoTitle = ({ demoType, showDemo }) => {
  if (!demoType || !showDemo) return null;
  
  let title, description, bgClass, iconClass;
  
  switch(demoType) {
    case 'secure':
      title = "Secure Deployment Example";
      description = "This Kubernetes Deployment follows security best practices";
      bgClass = "bg-green-900/30 border-green-700";
      iconClass = "text-green-400";
      break;
    case 'insecure':
      title = "Insecure Deployment Example";
      description = "This Deployment has multiple security issues that need to be fixed";
      bgClass = "bg-red-900/30 border-red-700";
      iconClass = "text-red-400";
      break;
    case 'rbac':
      title = "RBAC Security Issues Example";
      description = "This example shows dangerous RBAC permissions with wildcards";
      bgClass = "bg-purple-900/30 border-purple-700";
      iconClass = "text-purple-400";
      break;
    default:
      return null;
  }
  
  return (
    <div className={`mb-4 p-3 rounded border ${bgClass}`}>
      <div className={`font-bold ${iconClass} flex items-center`}>
        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        {title}
      </div>
      <p className="text-sm text-white mt-1">{description}</p>
    </div>
  );
};

export default DemoTitle;