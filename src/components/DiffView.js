import React from 'react';
import yaml from 'js-yaml';
import { diffLines } from 'diff';

/**
 * Component for displaying a side-by-side diff view of YAML changes
 */
const DiffView = ({ originalData, currentData }) => {
  if (!originalData || !currentData) return null;
  
  // Convert data to YAML strings
  const originalYaml = yaml.dump(originalData, { indent: 2 });
  const currentYaml = yaml.dump(currentData, { indent: 2 });
  
  // Calculate differences
  const differences = diffLines(originalYaml, currentYaml);
  
  return (
    <div className="mb-4">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Original (Before) Column */}
        <div className="p-4 bg-gray-800/70 backdrop-blur-sm rounded shadow-xl border border-gray-700 border-b-red-500/40 border-r-red-500/40">
          <div className="font-bold text-red-400 mb-3 flex items-center">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Before (Original)
          </div>
          <div className="font-mono">
            <pre className="whitespace-pre-wrap text-sm">
              {differences.map((part, index) => (
                <span 
                  key={index}
                  className={
                    part.added ? 'hidden' : 
                    part.removed ? 'bg-red-900/80 text-red-200 rounded px-1 py-0.5 border border-red-700' : 
                    'text-gray-300'
                  }
                >
                  {part.value}
                </span>
              ))}
            </pre>
          </div>
        </div>
        
        {/* Fixed (After) Column */}
        <div className="p-4 bg-gray-800/70 backdrop-blur-sm rounded shadow-xl border border-gray-700 border-b-green-500/40 border-r-green-500/40">
          <div className="font-bold text-green-400 mb-3 flex items-center">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
            After (Fixed)
          </div>
          <div className="font-mono">
            <pre className="whitespace-pre-wrap text-sm">
              {differences.map((part, index) => (
                <span 
                  key={index}
                  className={
                    part.removed ? 'hidden' : 
                    part.added ? 'bg-green-900/80 text-green-200 rounded px-1 py-0.5 border border-green-700' : 
                    'text-gray-300'
                  }
                >
                  {part.value}
                </span>
              ))}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DiffView;