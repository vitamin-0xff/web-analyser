"""
Example: Security headers analysis

This example demonstrates how to use the SecurityHeadersAnalyzer
to identify security issues in a website.
"""
import asyncio
import json
from core.engine import Engine


async def main():
    """Scan a website and display security findings."""
    
    # Initialize the engine
    engine = Engine()
    
    # Scan a website
    url = "https://example.com"
    print(f"Scanning {url} for security issues...\n")
    
    # Fetch data and create scan context
    context = await engine.scan_url(url)
    
    # Analyze the context
    detections = await engine.analyze_context(context)
    
    # Filter for security-related detections
    security_detections = [d for d in detections if d.category == "Security"]
    
    if not security_detections:
        print("No security issues detected!")
        return
    
    print(f"Found {len(security_detections)} security findings:\n")
    
    # Group by severity (based on confidence)
    critical = [d for d in security_detections if d.confidence >= 0.90]
    high = [d for d in security_detections if 0.80 <= d.confidence < 0.90]
    medium = [d for d in security_detections if 0.70 <= d.confidence < 0.80]
    low = [d for d in security_detections if d.confidence < 0.70]
    
    def print_findings(findings, severity_label, marker):
        if findings:
            print(f"[{marker}] {severity_label} ({len(findings)} findings)")
            print("-" * 60)
            for detection in findings:
                print(f"  - {detection.name}")
                print(f"    Confidence: {detection.confidence:.2f}")
                print(f"    Evidence: {detection.evidence.name} = {detection.evidence.value[:80]}")
                if detection.evidence.pattern:
                    print(f"    Details: {detection.evidence.pattern}")
                print()
    
    print_findings(critical, "CRITICAL", "!")
    print_findings(high, "HIGH", "*")
    print_findings(medium, "MEDIUM", "+")
    print_findings(low, "LOW", "-")
    
    # Summary
    print("\n" + "=" * 60)
    print("SECURITY SUMMARY")
    print("=" * 60)
    print(f"Critical: {len(critical)}")
    print(f"High:     {len(high)}")
    print(f"Medium:   {len(medium)}")
    print(f"Low:      {len(low)}")
    print(f"Total:    {len(security_detections)}")
    
    # Export to JSON
    output = [
        {
            "name": d.name,
            "category": d.category,
            "confidence": d.confidence,
            "evidence_type": d.evidence.type,
            "evidence_name": d.evidence.name,
            "evidence_value": d.evidence.value,
            "description": d.evidence.pattern
        }
        for d in security_detections
    ]
    
    with open("security_report.json", "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\nFull report saved to security_report.json")


if __name__ == "__main__":
    asyncio.run(main())
