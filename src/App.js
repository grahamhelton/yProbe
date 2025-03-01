import React, { useState, useRef, useCallback, useEffect } from 'react';
import _ from 'lodash';
import Confetti from 'react-confetti';

// Import utilities
import { parseYamlContent, yamlDataToString, isScannableKind } from './utils/yamlUtils';
import { scanForSecurityIssues } from './utils/scanUtils';
import { fixSingleSecurityIssue, fixAllSecurityIssues } from './utils/securityUtils';

// Import components
import Documentation from './components/Documentation';
import SecurityIssueDetails from './components/SecurityIssueDetails';
import ConnectionLine from './components/ConnectionLine';
import Starfield from './components/Starfield';
import DemoTitle from './components/DemoTitle';
import DiffView from './components/DiffView';
import DocumentDisplay from './components/DocumentDisplay';
import DropZone from './components/DropZone';
import FileControls from './components/FileControls';
import SecureStatus from './components/SecureStatus';

// Import demo data
import DEMO_YAMLS from './data/demoYamls';

// App component
function App() {
  const [yamlData, setYamlData] = useState(null);
  const [yamlString, setYamlString] = useState('');
  const [originalYamlData, setOriginalYamlData] = useState(null);
  const [showDiff, setShowDiff] = useState(false);
  const [securityIssues, setSecurityIssues] = useState([]);
  const [error, setError] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [selectedIssue, setSelectedIssue] = useState(null);
  const [copySuccess, setCopySuccess] = useState(false);
  const [fixSuccess, setFixSuccess] = useState(false);
  const [isFixed, setIsFixed] = useState(false);
  const [fixedCount, setFixedCount] = useState(0);
  const [showConfetti, setShowConfetti] = useState(false);
  const [showStarfield] = useState(true);
  const [showDemo, setShowDemo] = useState(false);
  const [demoType, setDemoType] = useState(null);
  const [showDocumentation, setShowDocumentation] = useState(false);
  const [isMultiDoc, setIsMultiDoc] = useState(false);
  const [windowDimensions, setWindowDimensions] = useState({
    width: window.innerWidth,
    height: window.innerHeight
  });
  // History for undo feature
  const [yamlHistory, setYamlHistory] = useState([]);
  const [canUndo, setCanUndo] = useState(false);
  
  const dropRef = useRef(null);

  // Update window dimensions when window resizes
  useEffect(() => {
    const handleResize = () => {
      setWindowDimensions({
        width: window.innerWidth,
        height: window.innerHeight
      });
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);
  
  // Update sidebar position when selected issue changes or on scroll
  useEffect(() => {
    if (selectedIssue && selectedIssue.element) {
      // Function to update sidebar position based on selected element
      const updateSidebarPosition = () => {
        const sidebarElement = document.getElementById('security-sidebar');
        if (sidebarElement && selectedIssue.element) {
          const elementRect = selectedIssue.element.getBoundingClientRect();
          const viewportHeight = window.innerHeight;
          const sidebarHeight = sidebarElement.offsetHeight;
          
          // Calculate vertical center alignment with the element
          let idealTop = elementRect.top + (elementRect.height / 2) - (sidebarHeight / 2);
          
          // Ensure the sidebar doesn't go off-screen (in the fixed position context)
          const maxTop = viewportHeight - sidebarHeight - 20;
          const minTop = 20;
          
          // Apply bounds
          const finalTop = Math.min(Math.max(idealTop, minTop), maxTop);
          
          // Update the sidebar's position
          sidebarElement.style.top = `${finalTop}px`;
        }
      };
      
      // Update immediately and on scroll/resize
      updateSidebarPosition();
      window.addEventListener('scroll', updateSidebarPosition);
      window.addEventListener('resize', updateSidebarPosition);
      
      return () => {
        window.removeEventListener('scroll', updateSidebarPosition);
        window.removeEventListener('resize', updateSidebarPosition);
      };
    }
  }, [selectedIssue]);

  /**
   * Parse YAML content and check for security issues
   */
  const parseYaml = useCallback((content) => {
    try {
      // Parse the YAML content
      const { parsed: parsedData, isMultiDoc: isMulti, documents } = parseYamlContent(content);
      setIsMultiDoc(isMulti);
      
      // Store the original YAML string and data
      setYamlString(content);
      setOriginalYamlData(_.cloneDeep(parsedData));
      
      // Reset history when loading new content
      setYamlHistory([]);
      
      // Check for unsupported kinds (will still display them, but with a warning)
      let unsupportedKinds = [];
      
      if (isMulti) {
        documents.forEach(doc => {
          if (doc && doc.kind && !isScannableKind(doc)) {
            unsupportedKinds.push(doc.kind);
          }
        });
      } else if (parsedData && parsedData.kind && !isScannableKind(parsedData)) {
        unsupportedKinds.push(parsedData.kind);
      }
      
      // Scan for security issues
      const allIssues = scanForSecurityIssues(parsedData, isMulti);
      setSecurityIssues(allIssues);
      
      // Set warning message for unscannable resources
      const hasUnsupportedKinds = unsupportedKinds.length > 0;
      if (hasUnsupportedKinds) {
        setError(`Warning: ${unsupportedKinds.join(', ')} cannot be scanned for security issues`);
      } else {
        setError(null);
      }
      
      // Reset diff view when loading new YAML
      setShowDiff(false);
      
      // Show confetti if there are no security issues
      setShowConfetti(allIssues.length === 0 && !hasUnsupportedKinds);
      
      // After 5 seconds, hide the confetti
      if (allIssues.length === 0 && !hasUnsupportedKinds) {
        setTimeout(() => {
          setShowConfetti(false);
        }, 5000);
      }
      
      setYamlData(parsedData);
      
    } catch (err) {
      setError(`Error parsing YAML: ${err.message}`);
      setYamlData(null);
      setOriginalYamlData(null);
      setSecurityIssues([]);
      setYamlString('');
      setShowConfetti(false);
      setShowDiff(false);
    }
  }, []);
  
  /**
   * Handle drag over events for the drop zone
   */
  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  /**
   * Handle drag leave events for the drop zone
   */
  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  /**
   * Handle file drop events
   */
  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    
    // Clear any selected issue when loading a new file
    setSelectedIssue(null);
    
    // Reset demo mode when dropping a new file
    setShowDemo(false);
    
    const files = Array.from(e.dataTransfer.files);
    
    if (files.length === 0) {
      setError("No files dropped");
      return;
    }
    
    const file = files[0];
    
    if (file.type !== 'application/x-yaml' && !file.name.endsWith('.yaml') && !file.name.endsWith('.yml')) {
      setError("Please drop a YAML file (.yaml or .yml)");
      return;
    }
    
    const reader = new FileReader();
    reader.onload = (event) => {
      parseYaml(event.target.result);
    };
    reader.onerror = () => {
      setError("Failed to read file");
    };
    reader.readAsText(file);
  }, [parseYaml]);

  /**
   * Handle paste events for YAML content
   */
  const handlePaste = useCallback((e) => {
    const clipboardData = e.clipboardData || window.clipboardData;
    const pastedText = clipboardData.getData('text');
    
    // Clear any selected issue when pasting new content
    setSelectedIssue(null);
    
    // Reset demo mode when pasting content
    setShowDemo(false);
    
    if (pastedText) {
      parseYaml(pastedText);
    }
  }, [parseYaml]);

  /**
   * Handle fixing a single security issue
   */
  const handleFixSingleIssue = useCallback((issue) => {
    if (!yamlData) return;
    
    // Save the current state to history before making changes
    setYamlHistory(prevHistory => [
      ...prevHistory, 
      { 
        data: _.cloneDeep(yamlData), 
        string: yamlString,
        issues: [...securityIssues]
      }
    ]);
    setCanUndo(true);
    
    // Get the document index from the issue (or default to 0 for single docs)
    const documentIndex = issue.documentIndex !== undefined ? issue.documentIndex : 0;
    
    if (isMultiDoc && Array.isArray(yamlData)) {
      // For multi-doc YAML, fix only the specific document
      const clonedData = _.cloneDeep(yamlData);
      const documentToFix = clonedData[documentIndex];
      
      if (documentToFix) {
        // Apply the fix to just this document
        const fixedDocument = fixSingleSecurityIssue(documentToFix, issue);
        
        // Update the document in the array
        clonedData[documentIndex] = fixedDocument;
        
        // Update the full YAML data and string
        setYamlData(clonedData);
        setYamlString(yamlDataToString(clonedData, true));
        
        // Re-scan for security issues
        const remainingIssues = scanForSecurityIssues(clonedData, true);
        setSecurityIssues(remainingIssues);
        
        // Clear selected issue
        setSelectedIssue(null);
        
        // Show confetti if all issues are fixed
        if (remainingIssues.length === 0) {
          setShowConfetti(true);
          setIsFixed(true);
          setTimeout(() => setShowConfetti(false), 5000);
        }
      }
    } else {
      // For single-doc YAML, fix the entire document
      const clonedData = _.cloneDeep(yamlData);
      
      // Apply the fix for the specific issue
      const fixedData = fixSingleSecurityIssue(clonedData, issue);
      
      // Convert back to YAML string
      const fixedYamlString = yamlDataToString(fixedData, false);
      
      // Update state
      setYamlData(fixedData);
      setYamlString(fixedYamlString);
      
      // Re-scan for security issues
      const remainingIssues = scanForSecurityIssues(fixedData, false);
      setSecurityIssues(remainingIssues);
      
      // Clear selected issue
      setSelectedIssue(null);
      
      // Show confetti if all issues are fixed
      if (remainingIssues.length === 0) {
        setShowConfetti(true);
        setIsFixed(true);
        setTimeout(() => setShowConfetti(false), 5000);
      }
    }
    
    // Show success feedback
    setFixSuccess(true);
    setTimeout(() => setFixSuccess(false), 2000);
  }, [yamlData, isMultiDoc, yamlString, securityIssues]);
  
  /**
   * Handle fixing all security issues
   * Not actively used but kept for future enhancements
   */
  // eslint-disable-next-line no-unused-vars
  const fixAllIssues = useCallback(() => {
    if (!yamlData || securityIssues.length === 0) return;
    
    // Store the number of issues that will be fixed
    const issuesCount = securityIssues.length;
    
    // Fix each issue individually instead of using fixAllSecurityIssues
    let currentData = _.cloneDeep(yamlData);
    
    // Collect only the actual detected security issues by key type
    const issuesByDocument = {};
    
    // Group issues by document for more efficient processing
    securityIssues.forEach(issue => {
      const documentIndex = issue.documentIndex !== undefined ? issue.documentIndex : 0;
      
      if (!issuesByDocument[documentIndex]) {
        issuesByDocument[documentIndex] = [];
      }
      
      // Add the issue to the correct document group
      issuesByDocument[documentIndex].push(issue);
    });
    
    // Process issues for each document separately
    Object.entries(issuesByDocument).forEach(([docIndexStr, issues]) => {
      const documentIndex = parseInt(docIndexStr, 10);
      const documentToFix = isMultiDoc && Array.isArray(currentData) 
        ? currentData[documentIndex] 
        : currentData;
      
      if (!documentToFix) return;
      
      // Make a working copy of this document
      let workingDoc = _.cloneDeep(documentToFix);
      
      // Apply fixes one by one to this document - but ONLY the ones that exist
      const uniqueIssueTypes = {};
      
      // Group issues by type to avoid fixing the same thing twice
      issues.forEach(issue => {
        const containerStr = issue.containerIndex !== undefined ? `-${issue.containerIndex}` : '';
        const uniqueId = `${issue.key}${containerStr}`;
        uniqueIssueTypes[uniqueId] = issue;
      });
      
      // Apply each unique issue fix
      Object.values(uniqueIssueTypes).forEach(issue => {
        // Create a minimal issue object with only what's needed to apply the fix correctly
        const specificIssue = {
          key: issue.key,
          value: issue.value,
          containerIndex: issue.containerIndex,
          // Add a flag to indicate this is from "Fix Pod Issues" button - this helps our fixers
          // avoid adding unnecessary security settings
          fromFixAllButton: true,
          // Critical: Include severity and category to help fixers be more precise
          severity: issue.severity,
          category: issue.category
        };
        
        // Apply only this specific fix
        workingDoc = fixSingleSecurityIssue(workingDoc, specificIssue);
      });
      
      // Update the data with fixed document
      if (isMultiDoc && Array.isArray(currentData)) {
        currentData[documentIndex] = workingDoc;
      } else {
        currentData = workingDoc;
      }
    });
    
    // Convert to YAML string
    const fixedYamlString = yamlDataToString(currentData, isMultiDoc);
    
    // Save the current state to history before making changes
    setYamlHistory(prevHistory => [
      ...prevHistory, 
      { 
        data: _.cloneDeep(yamlData), 
        string: yamlString,
        issues: [...securityIssues]
      }
    ]);
    setCanUndo(true);
    
    // Update state
    setYamlData(currentData);
    setYamlString(fixedYamlString);
    setSelectedIssue(null);
    
    // Set UI feedback
    setFixSuccess(true);
    setIsFixed(true);
    setFixedCount(issuesCount);
    
    // Re-scan for issues
    const remainingIssues = scanForSecurityIssues(currentData, isMultiDoc);
    setSecurityIssues(remainingIssues);
    
    // Show confetti if all issues are fixed
    if (remainingIssues.length === 0) {
      setShowConfetti(true);
      setTimeout(() => setShowConfetti(false), 5000);
    }
    
    // Reset feedback after delay
    setTimeout(() => setFixSuccess(false), 3000);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [yamlData, securityIssues, isMultiDoc]);
  
  /**
   * Handle copy YAML to clipboard
   */
  const handleCopyYaml = useCallback(() => {
    navigator.clipboard.writeText(yamlString).then(
      () => {
        setCopySuccess(true);
        setTimeout(() => setCopySuccess(false), 2000);
      },
      () => {
        setError("Failed to copy YAML to clipboard");
      }
    );
  }, [yamlString]);
  
  /**
   * Handle download YAML as file
   */
  const handleDownloadYaml = useCallback(() => {
    if (!yamlString) return;
    
    // Create safe filename
    let filename = "manifest.yaml";
    
    if (yamlData) {
      if (Array.isArray(yamlData) && yamlData.length > 0) {
        const firstDoc = yamlData[0];
        if (firstDoc.kind && firstDoc.metadata?.name) {
          filename = `${firstDoc.kind.toLowerCase()}-${firstDoc.metadata.name}.yaml`;
        } else if (firstDoc.kind) {
          filename = `${firstDoc.kind.toLowerCase()}.yaml`;
        }
      } else if (yamlData.kind) {
        if (yamlData.metadata?.name) {
          filename = `${yamlData.kind.toLowerCase()}-${yamlData.metadata.name}.yaml`;
        } else {
          filename = `${yamlData.kind.toLowerCase()}.yaml`;
        }
      }
    }
    
    // Create a blob with the YAML content
    const blob = new Blob([yamlString], { type: 'text/yaml' });
    
    // Create download link and trigger click
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    
    // Cleanup
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 0);
  }, [yamlString, yamlData]);
  
  /**
   * Handle undo action for security fixes
   */
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const handleUndo = useCallback(() => {
    if (yamlHistory.length === 0) return;
    
    // Get the last state from history
    const lastState = yamlHistory[yamlHistory.length - 1];
    
    // Apply the previous state
    setYamlData(lastState.data);
    setYamlString(lastState.string);
    setSecurityIssues(lastState.issues);
    setSelectedIssue(null);
    
    // Remove the used history item
    setYamlHistory(prevHistory => prevHistory.slice(0, -1));
    
    // Update canUndo flag
    setCanUndo(yamlHistory.length > 1);
    
    // Show feedback
    setFixSuccess(false);
    setIsFixed(lastState.issues.length === 0);
  }, [yamlHistory]);
  
  /**
   * Clear all current data
   */
  const handleClear = useCallback(() => {
    setYamlData(null);
    setOriginalYamlData(null);
    setError(null);
    setSecurityIssues([]);
    setSelectedIssue(null);
    setYamlString('');
    setIsFixed(false);
    setFixedCount(0);
    setShowConfetti(false);
    setShowDiff(false);
    setYamlHistory([]);
    setCanUndo(false);
  }, []);
  
  /**
   * Handle demo selection
   */
  const handleDemoSelect = useCallback((type) => {
    if (DEMO_YAMLS[type]) {
      parseYaml(DEMO_YAMLS[type]);
      setDemoType(type);
      setShowDemo(true);
      
      // Hide diff view for RBAC resources
      if (type === 'rbac') {
        setShowDiff(false);
      }
      
      // Clear selected issue when loading demo YAML
      setSelectedIssue(null);
    }
  }, [parseYaml]);

  // Render the main application
  return (
    <div className="flex flex-col min-h-screen bg-transparent text-gray-200 p-4 font-mono">
      {/* Documentation modal */}
      {showDocumentation && (
        <Documentation onClose={() => setShowDocumentation(false)} />
      )}
      
      {/* Background - either starfield or gradient */}
      {showStarfield ? (
        <Starfield />
      ) : (
        <div className="fixed inset-0 z-0 bg-gradient-to-b from-gray-800 to-black"></div>
      )}
      
      {/* Confetti effect when no security issues */}
      {showConfetti && (
        <Confetti
          width={windowDimensions.width}
          height={windowDimensions.height}
          recycle={false}
          numberOfPieces={500}
          gravity={0.25}
          colors={['#10B981', '#34D399', '#6EE7B7', '#A7F3D0', '#ECFDF5']}
        />
      )}
      
      {/* Header with glow effect */}
      <div className="relative z-10">
        <h1 className="text-3xl font-bold text-center mb-2 text-white bg-clip-text bg-gradient-to-r from-emerald-500 via-green-400 to-teal-500 drop-shadow-[0_0_20px_rgba(16,185,129,0.8)]">yProbe</h1>
        <p className="text-center text-green-400/80 mb-2">Kubernetes YAML Manifest Sanity Checker</p>
        <div className="flex justify-center items-center gap-4 mb-6">
          <span className="text-center text-red-400/90 text-sm flex items-center">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            Insecure Pod Specs
          </span>
          <span className="text-center text-purple-400/90 text-sm flex items-center">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
            RBAC Permissions
          </span>
        </div>
        <p className="text-center text-blue-400/80 text-sm mb-6">Supports Pod workloads and Role/ClusterRole resources</p>
      </div>
      
      {/* Main content area */}
      <div className="relative z-10 flex-1 flex gap-5 mb-4 overflow-auto">
        {/* YAML Content Area */}
        <div 
          ref={dropRef}
          className={`flex-1 flex flex-col border-2 border-dashed rounded-lg p-4 transition-all ${
            isDragging ? 'border-green-500 bg-green-900/20 shadow-[0_0_15px_rgba(16,185,129,0.4)]' : 'border-gray-700'
          } ${yamlData ? 'items-start overflow-auto' : ''}`}
          style={{ maxWidth: selectedIssue ? 'calc(100% - 380px)' : '100%' }}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onPaste={handlePaste}
          tabIndex="0"
        >
          {yamlData ? (
            <div className="w-full font-mono text-sm">
              <div className="flex justify-between mb-4">
                <h2 className="text-xl font-semibold text-green-400 flex items-center">
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  YAML Content
                </h2>
                
                <FileControls 
                  showDiff={originalYamlData && showDiff && 
                    (!yamlData?.kind || (yamlData?.kind !== 'Role' && yamlData?.kind !== 'ClusterRole'))}
                  onToggleDiff={() => {
                    // Only toggle diff view for non-Role resources
                    if (!yamlData?.kind || (yamlData?.kind !== 'Role' && yamlData?.kind !== 'ClusterRole')) {
                      setShowDiff(!showDiff);
                      setSelectedIssue(null);
                    }
                  }}
                  onCopyYaml={handleCopyYaml}
                  onDownloadYaml={handleDownloadYaml}
                  onClear={handleClear}
                  onUndo={handleUndo}
                  copySuccess={copySuccess}
                  fixSuccess={fixSuccess}
                  fixedCount={fixedCount}
                  isMultiDoc={isMultiDoc}
                  canUndo={canUndo}
                />
              </div>
              
              <div className="p-4 bg-gray-800/70 backdrop-blur-sm rounded shadow-xl border border-gray-700 border-b-green-500/40 border-r-green-500/40">
                {/* Demo title when in demo mode */}
                {showDemo && (
                  <DemoTitle demoType={demoType} showDemo={showDemo} />
                )}
                
                {/* Security status messages */}
                <SecureStatus 
                  isFixed={isFixed}
                  yamlData={yamlData}
                  error={error}
                  securityIssues={securityIssues}
                />
                
                {/* Removed global RBAC security summary */}
                
                {/* Before/After comparison view */}
                {showDiff && originalYamlData && yamlData ? (
                  <DiffView 
                    originalData={originalYamlData}
                    currentData={yamlData}
                  />
                ) : (
                  <>
                    {/* For multiple documents, render document list */}
                    {isMultiDoc && Array.isArray(yamlData) ? (
                      <div className="space-y-8">
                        {yamlData.map((document, index) => (
                          <DocumentDisplay
                            key={index}
                            document={document}
                            index={index}
                            securityIssues={securityIssues}
                            setSelectedIssue={setSelectedIssue}
                            onFixAll={(doc, docIndex) => {
                              // This will fix pod security issues for just this document
                              if (doc) {
                                // Save the current state to history before making changes
                                setYamlHistory(prevHistory => [
                                  ...prevHistory, 
                                  { 
                                    data: _.cloneDeep(yamlData), 
                                    string: yamlString,
                                    issues: [...securityIssues]
                                  }
                                ]);
                                setCanUndo(true);
                                
                                const fixedDoc = fixAllSecurityIssues(doc);
                                const newYamlData = [...yamlData];
                                newYamlData[docIndex] = fixedDoc;
                                
                                // Update the data and re-scan for issues
                                setYamlData(newYamlData);
                                setYamlString(yamlDataToString(newYamlData, true));
                                const remainingIssues = scanForSecurityIssues(newYamlData, true);
                                setSecurityIssues(remainingIssues);
                                
                                // Show feedback
                                setFixSuccess(true);
                                setTimeout(() => setFixSuccess(false), 3000);
                              }
                            }}
                            onUndo={handleUndo}
                            canUndo={canUndo}
                          />
                        ))}
                      </div>
                    ) : (
                      /* Single document - use DocumentDisplay for consistency with multi-doc case */
                      <DocumentDisplay
                        document={yamlData}
                        index={0}
                        securityIssues={securityIssues}
                        setSelectedIssue={setSelectedIssue}
                        onFixAll={(doc) => {
                          // This will fix pod security issues for the single document
                          if (doc) {
                            // Save the current state to history before making changes
                            setYamlHistory(prevHistory => [
                              ...prevHistory, 
                              { 
                                data: _.cloneDeep(yamlData), 
                                string: yamlString,
                                issues: [...securityIssues]
                              }
                            ]);
                            setCanUndo(true);
                            
                            const fixedDoc = fixAllSecurityIssues(doc);
                            
                            // Update the data and re-scan for issues
                            setYamlData(fixedDoc);
                            setYamlString(yamlDataToString(fixedDoc, false));
                            const remainingIssues = scanForSecurityIssues(fixedDoc, false);
                            setSecurityIssues(remainingIssues);
                            
                            // Show feedback
                            setFixSuccess(true);
                            setTimeout(() => setFixSuccess(false), 3000);
                          }
                        }}
                        onUndo={handleUndo}
                        canUndo={canUndo}
                      />
                    )}
                  </>
                )}
              </div>
            </div>
          ) : (
            <DropZone 
              isDragging={isDragging}
              error={error}
              onDrop={handleDrop}
              onPaste={handlePaste}
              onClickDemo={handleDemoSelect}
              onClickDocs={() => setShowDocumentation(true)}
            />
          )}
        </div>
        
        {/* Security Issue Sidebar */}
        {yamlData && (
          <div 
            id="security-sidebar" 
            className={`transition-all duration-300 ${
              selectedIssue ? 'opacity-100' : 'opacity-30'
            }`}
            style={selectedIssue && selectedIssue.element ? {
              position: 'fixed',
              right: '20px',
              left: 'auto',
              width: '360px',
              top: `${selectedIssue.element.getBoundingClientRect().top}px`,
              maxHeight: 'calc(100vh - 40px)',
              overflowY: 'auto',
              zIndex: 40,
              backgroundColor: 'rgba(17, 24, 39, 0.95)',
              backdropFilter: 'blur(8px)',
              borderLeft: '1px solid rgba(75, 85, 99, 0.5)',
              borderRadius: '8px',
              padding: '20px',
              paddingTop: '16px',
              margin: 0
            } : {
              position: 'sticky',
              top: '0px',
              right: '20px',
              alignSelf: 'flex-start',
              width: '360px',
              maxHeight: 'calc(100vh - 40px)',
              overflowY: 'auto'
            }}
          >
            <div>
              <h2 className="text-xl font-semibold text-red-400 mb-4 flex items-center">
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                Security Details
              </h2>
              
              {selectedIssue ? (
                <SecurityIssueDetails 
                  selectedIssue={selectedIssue}
                  onFixIssue={handleFixSingleIssue}
                />
              ) : (
                <div className="p-4 rounded bg-gray-800/50 border border-gray-700 text-gray-400 text-sm italic">
                  Hover over highlighted items in the YAML to see security details and fix individual issues.
                </div>
              )}
            </div>
          </div>
        )}
      </div>
      
      {/* Connection line for selected issue */}
      <ConnectionLine selectedIssue={selectedIssue} />
      
      {/* Footer */}
      <div className="text-center text-gray-500 text-sm relative z-5 pb-4">
        <p>Supports .yaml and .yml files • Multiple YAML documents • RBAC security scanning • Drag and drop or paste YAML content</p>
        <p className="mt-2">
          <button 
            onClick={() => setShowDocumentation(true)}
            className="text-blue-400 hover:text-blue-300 underline bg-transparent border-none cursor-pointer p-0"
          >
            View Documentation
          </button>
        </p>
      </div>
    </div>
  );
}

export default App;
