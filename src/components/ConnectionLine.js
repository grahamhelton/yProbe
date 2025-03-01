import React, { useState, useEffect } from 'react';
import { getSeverityColors } from '../utils/severityUtils';

/**
 * Component for drawing the connection line between security issues and the details panel
 */
const ConnectionLine = ({ selectedIssue }) => {
  const [line, setLine] = useState({ x1: 0, y1: 0, x2: 0, y2: 0 });
  const [isVisible, setIsVisible] = useState(false);
  
  // Get color based on issue severity
  const getLineColors = (severity) => {
    const colors = getSeverityColors(severity);
    return {
      color: colors.color,
      shadow: colors.shadow,
      fill: colors.fill
    };
  };

  // Set initial line position when selected issue changes
  useEffect(() => {
    if (selectedIssue && selectedIssue.element && selectedIssue.issue) {
      const elementRect = selectedIssue.element.getBoundingClientRect();
      
      // Calculate position for the element (source)
      const x1 = elementRect.right;
      const y1 = elementRect.top + elementRect.height / 2;
      
      // Position for sidebar (target) - fixed on the right side of the screen
      const sidebarElement = document.getElementById('security-sidebar');
      if (sidebarElement) {
        const sidebarRect = sidebarElement.getBoundingClientRect();
        const x2 = sidebarRect.left;
        
        // Always keep the line horizontal for visual consistency
        const y2 = y1;
        
        setLine({ x1, y1, x2, y2 });
        setIsVisible(true);
      }
    } else {
      setIsVisible(false);
    }
  }, [selectedIssue]);
  
  // Update line positions on window resize and scroll
  useEffect(() => {
    const handleVisualUpdate = () => {
      // Re-calculate line positions on window resize or scroll if visible
      if (isVisible && selectedIssue && selectedIssue.element) {
        const elementRect = selectedIssue.element.getBoundingClientRect();
        const x1 = elementRect.right;
        const y1 = elementRect.top + elementRect.height / 2;
        
        const sidebarElement = document.getElementById('security-sidebar');
        if (sidebarElement) {
          const sidebarRect = sidebarElement.getBoundingClientRect();
          const x2 = sidebarRect.left;
          
          // Always keep the line horizontal - key requirement
          const y2 = y1;
          
          setLine({ x1, y1, x2, y2 });
        }
      }
    };

    // Listen for both resize and scroll events for real-time updates
    window.addEventListener('resize', handleVisualUpdate);
    window.addEventListener('scroll', handleVisualUpdate, true);
    
    // For smoother updates, use animation frames
    let animationFrameId;
    const updateOnAnimationFrame = () => {
      handleVisualUpdate();
      animationFrameId = requestAnimationFrame(updateOnAnimationFrame);
    };
    
    animationFrameId = requestAnimationFrame(updateOnAnimationFrame);
    
    return () => {
      window.removeEventListener('resize', handleVisualUpdate);
      window.removeEventListener('scroll', handleVisualUpdate, true);
      cancelAnimationFrame(animationFrameId);
    };
  }, [isVisible, selectedIssue]);

  if (!isVisible || !selectedIssue || !selectedIssue.issue) return null;
  
  // Get color based on issue severity
  const { color, shadow, fill } = getLineColors(selectedIssue.issue.severity);
  const arrowheadId = `arrowhead-${selectedIssue.issue.severity || 'default'}`;

  return (
    <svg 
      className="fixed top-0 left-0 w-full h-full pointer-events-none z-20"
      style={{ 
        filter: `drop-shadow(0 0 1px ${shadow})` 
      }}
    >
      <defs>
        {/* Severity-colored arrowhead */}
        <marker
          id={arrowheadId}
          markerWidth="10"
          markerHeight="7"
          refX="9"
          refY="3.5"
          orient="auto"
        >
          <polygon points="0 0, 10 3.5, 0 7" fill={fill} />
        </marker>
      </defs>
      {/* Draw a straight horizontal line with color matching the severity */}
      <path
        d={`M ${line.x1} ${line.y1} L ${line.x2} ${line.y2}`}
        stroke={color}
        strokeWidth="1.5"
        fill="none"
        strokeDasharray="4 2"
        markerEnd={`url(#${arrowheadId})`}
      />
    </svg>
  );
};

export default ConnectionLine;