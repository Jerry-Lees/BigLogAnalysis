#!/usr/bin/env python3
"""
BIG-IP Log Analysis Tool
Analyzes F5 Networks BIG-IP LTM log files and provides detailed statistics
"""

import sys
import os
import re
import textwrap
from collections import defaultdict
from datetime import datetime
try:
    import urllib.request
    import urllib.error
    from html.parser import HTMLParser
    WEB_FETCH_AVAILABLE = True
except ImportError:
    WEB_FETCH_AVAILABLE = False


# ANSI color codes
class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def colorize_value(display_value, numeric_value, threshold_yellow=20.0, threshold_red=40.0):
    """
    Colorize a display value based on numeric thresholds
    20% threshold = yellow, 40% threshold = red
    """
    if numeric_value >= threshold_red:
        return f"{Colors.RED}{display_value}{Colors.RESET}"
    elif numeric_value >= threshold_yellow:
        return f"{Colors.YELLOW}{display_value}{Colors.RESET}"
    else:
        return str(display_value)


def wrap_text(text, width=80, indent=0):
    """
    Wrap text to specified width with indentation for continuation lines
    """
    wrapper = textwrap.TextWrapper(
        width=width,
        initial_indent=' ' * indent,
        subsequent_indent=' ' * indent,
        break_long_words=False,
        break_on_hyphens=False
    )
    return wrapper.fill(text)


class F5ErrorCodeParser(HTMLParser):
    """Simple HTML parser to extract error code descriptions from F5 docs"""
    def __init__(self):
        super().__init__()
        self.error_codes = {}
        self.current_code = None
        self.capturing = False
        
    def handle_starttag(self, tag, attrs):
        # Look for error code patterns in the HTML
        pass
    
    def handle_data(self, data):
        # Capture error code descriptions
        if self.capturing:
            self.current_description = data.strip()


def parse_log_line(line):
    """
    Parse a BIG-IP log line into components
    Format: Month Day Year Hostname Error-level Process-name/ID Error-code Message
    OR for iRules: Month Day Year Hostname Error-level Process-name/ID Rule /Partition/iRule_name <EVENT>: Message
    """
    # Remove leading/trailing whitespace
    line = line.strip()
    if not line:
        return None
    
    parts = line.split(None, 6)  # Split on whitespace, max 7 parts
    if len(parts) < 7:
        return None
    
    try:
        # Check if this is an iRule log entry
        # The 7th element starts with "Rule "
        if parts[6].startswith('Rule '):
            # This is an iRule entry
            # Parse: Rule /Partition/iRule_name <EVENT>: Message
            remaining = parts[6][5:]  # Remove "Rule " prefix
            
            # Extract iRule name (path format) and event
            # Format: /Common/Log_SSL_Cipher <EVENT>: Message
            irule_match = re.match(r'(/[^ ]+)\s+<([^>]+)>:\s*(.*)', remaining)
            if irule_match:
                irule_name = irule_match.group(1)
                irule_event = irule_match.group(2)
                message = irule_match.group(3)
                
                entry = {
                    'month': parts[0],
                    'day': parts[1],
                    'year': parts[2],
                    'hostname': parts[3],
                    'level': parts[4],
                    'process': parts[5],
                    'error_code': 'Rule',
                    'irule_name': irule_name,
                    'irule_event': irule_event,
                    'message': message,
                    'raw': line,
                    'is_irule': True
                }
                return entry
        
        # Standard log entry - need to split one more time to get error code
        final_parts = parts[6].split(None, 1)
        if len(final_parts) < 2:
            return None
            
        # Standard log entry
        entry = {
            'month': parts[0],
            'day': parts[1],
            'year': parts[2],
            'hostname': parts[3],
            'level': parts[4],
            'process': parts[5],
            'error_code': final_parts[0],  # Keep full error code including trailing colon
            'message': final_parts[1],
            'raw': line,
            'is_irule': False
        }
        return entry
    except (IndexError, ValueError):
        return None


def format_bytes(bytes_size):
    """Format bytes into human-readable format"""
    kb = bytes_size / 1024
    mb = kb / 1024
    gb = mb / 1024
    return {
        'bytes': bytes_size,
        'kb': kb,
        'mb': mb,
        'gb': gb
    }


# Cache for error code explanations to avoid repeated web requests
_error_code_cache = {}


def get_error_code_explanation(error_code):
    """
    Fetch the error code explanation from F5 documentation
    Uses caching to avoid repeated requests for the same error code
    """
    # Check cache first
    if error_code in _error_code_cache:
        return _error_code_cache[error_code]
    
    base_uri = 'https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/releasenotes/related/log-messages.html'
    
    # Extract just the message ID (first part before colon)
    message_id = error_code.split(':')[0] if ':' in error_code else error_code
    
    result = {
        'explanation': f'Error code {error_code}: Check F5 documentation for detailed explanation',
        'uri': f'{base_uri}#A{message_id}'
    }
    
    # Attempt to fetch actual documentation if web fetch is available
    if WEB_FETCH_AVAILABLE:
        try:
            # Construct search URL for specific error code
            search_url = f'{base_uri}'
            
            req = urllib.request.Request(
                search_url,
                headers={'User-Agent': 'BIG-IP Log Analysis Tool'}
            )
            
            with urllib.request.urlopen(req, timeout=5) as response:
                html_content = response.read().decode('utf-8', errors='ignore')
                
                # Simple pattern matching for error code descriptions
                # Look for the error code in the HTML
                pattern = rf'{re.escape(message_id)}[^<]*<[^>]*>([^<]+)'
                match = re.search(pattern, html_content, re.IGNORECASE)
                
                if match:
                    description = match.group(1).strip()
                    if description and len(description) > 10:
                        result['explanation'] = description
                        
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            # If web fetch fails, use default message
            pass
        except Exception as e:
            # Catch any other exceptions and continue
            pass
    
    # Cache the result
    _error_code_cache[error_code] = result
    return result


def analyze_log_file(filepath):
    """Analyze the BIG-IP log file and return statistics"""
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found")
        sys.exit(1)
    
    # Get file size
    file_size = os.path.getsize(filepath)
    
    # Initialize counters
    total_entries = 0
    level_counts = defaultdict(int)
    level_bytes = defaultdict(int)
    error_code_counts = defaultdict(int)
    error_code_examples = {}
    error_code_bytes = defaultdict(int)
    
    # iRule specific tracking
    irule_counts = defaultdict(lambda: defaultdict(int))  # {irule_name: {event: count}}
    irule_examples = defaultdict(lambda: {})  # {irule_name: {event: example_message}}
    irule_total_counts = defaultdict(int)  # {irule_name: total_count}
    
    # Parse the log file
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            entry = parse_log_line(line)
            if entry:
                total_entries += 1
                line_bytes = len(line.encode('utf-8'))
                
                # Count by level
                level = entry['level'].lower()
                level_counts[level] += 1
                level_bytes[level] += line_bytes
                
                # Check if this is an iRule entry
                if entry.get('is_irule', False):
                    irule_name = entry['irule_name']
                    irule_event = entry['irule_event']
                    
                    # Track iRule statistics
                    irule_counts[irule_name][irule_event] += 1
                    irule_total_counts[irule_name] += 1
                    
                    # Also count in error_code_counts for detection and track size
                    error_code_counts['Rule'] += 1
                    error_code_bytes['Rule'] = error_code_bytes.get('Rule', 0) + line_bytes
                    
                    # Store first example of each event for each iRule
                    if irule_event not in irule_examples[irule_name]:
                        irule_examples[irule_name][irule_event] = entry['message']
                else:
                    # Count by error code (standard entries)
                    error_code = entry['error_code']
                    error_code_counts[error_code] += 1
                    error_code_bytes[error_code] += line_bytes
                    
                    # Store first example of each error code
                    if error_code not in error_code_examples:
                        error_code_examples[error_code] = entry['message']
    
    return {
        'filepath': filepath,
        'file_size': file_size,
        'total_entries': total_entries,
        'level_counts': dict(level_counts),
        'level_bytes': dict(level_bytes),
        'error_code_counts': dict(error_code_counts),
        'error_code_examples': error_code_examples,
        'error_code_bytes': dict(error_code_bytes),
        'rule_size_bytes': error_code_bytes.get('Rule', 0),
        'irule_counts': dict(irule_counts),
        'irule_examples': dict(irule_examples),
        'irule_total_counts': dict(irule_total_counts)
    }


def print_separator(char='=', length=80):
    """Print a separator line"""
    print(char * length)


def print_section_header(title):
    """Print a formatted section header"""
    print()
    print_separator('=')
    print(f"  {title}")
    print_separator('=')
    print()


def display_results(stats):
    """Display the analysis results in a formatted manner"""
    
    # Header
    print_separator('=')
    print(f"  BIG-IP LOG ANALYSIS REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_separator('=')
    
    # Section 1: Basic Statistics
    print_section_header("1. LOG FILE OVERVIEW")
    print(f"File Path:        {stats['filepath']}")
    print(f"Total Entries:    {stats['total_entries']:,}")
    
    sizes = format_bytes(stats['file_size'])
    print(f"\nFile Size:")
    print(f"  Bytes:          {sizes['bytes']:,}")
    print(f"  Megabytes:      {sizes['mb']:.2f} MB")
    print(f"  Gigabytes:      {sizes['gb']:.4f} GB")
    
    # Section 2: Error Level Summary
    print_section_header("2. ERROR LEVEL SUMMARY")
    
    # Ensure standard levels are shown even if count is 0
    standard_levels = ['err', 'info', 'warning', 'crit']
    all_levels = set(standard_levels) | set(stats['level_counts'].keys())
    
    # Sort levels by count (descending)
    sorted_levels = sorted(all_levels, 
                          key=lambda x: stats['level_counts'].get(x, 0), 
                          reverse=True)
    
    print(f"{'Level':<15} {'Count':>10} {'Percentage':>12} {'Size (MB)':>12}")
    print_separator('-')
    
    # Calculate max values for thresholds
    max_count = max([stats['level_counts'].get(level, 0) for level in all_levels]) if all_levels else 1
    max_size = max([stats['level_bytes'].get(level, 0) for level in all_levels]) if all_levels else 1
    
    for level in sorted_levels:
        count = stats['level_counts'].get(level, 0)
        percentage = (count / stats['total_entries'] * 100) if stats['total_entries'] > 0 else 0
        level_size_bytes = stats['level_bytes'].get(level, 0)
        level_size_mb = level_size_bytes / (1024 * 1024)
        
        # Calculate percentages of max for coloring
        count_pct_of_max = (count / max_count * 100) if max_count > 0 else 0
        size_pct_of_max = (level_size_bytes / max_size * 100) if max_size > 0 else 0
        
        # Format the values first
        count_str = f"{count:,}"
        percentage_str = f"{percentage:.2f}%"
        size_str = f"{level_size_mb:.2f}"
        
        # Apply coloring based on thresholds
        colored_count = colorize_value(count_str, count_pct_of_max)
        colored_percentage = colorize_value(percentage_str, percentage)
        colored_size = colorize_value(size_str, size_pct_of_max)
        
        # Calculate padding to maintain alignment (account for ANSI codes)
        # The visible width should be 10, 12, and 12 characters respectively
        count_padding = 10 - len(count_str)
        percentage_padding = 12 - len(percentage_str)
        size_padding = 12 - len(size_str)
        
        print(f"{level:<15} {' ' * count_padding}{colored_count} {' ' * percentage_padding}{colored_percentage} {' ' * size_padding}{colored_size}")
    
    # Section 3: Error Code Analysis
    print_section_header("3. ERROR CODE ANALYSIS")
    
    # Check if there are Rule entries
    has_rule_entries = 'Rule' in stats['error_code_counts']
    rule_entry_count = stats['error_code_counts'].get('Rule', 0)
    
    # Filter out 'Rule' entries from error codes
    sorted_codes = sorted([(code, count) for code, count in stats['error_code_counts'].items() if code != 'Rule'], 
                         key=lambda x: x[1], 
                         reverse=True)
    
    if not sorted_codes and not has_rule_entries:
        print("No error codes found in log file.")
    else:
        # Calculate max values for error code thresholds (excluding Rule entries)
        max_error_count = max([count for _, count in sorted_codes]) if sorted_codes else 1
        max_error_size = max([stats['error_code_bytes'].get(code, 0) for code, _ in sorted_codes]) if sorted_codes else 1
        
        for error_code, count in sorted_codes:
            percentage = (count / stats['total_entries'] * 100) if stats['total_entries'] > 0 else 0
            code_size_bytes = stats['error_code_bytes'].get(error_code, 0)
            code_size_mb = code_size_bytes / (1024 * 1024)
            
            # Calculate percentages of max for coloring
            count_pct_of_max = (count / max_error_count * 100) if max_error_count > 0 else 0
            size_pct_of_max = (code_size_bytes / max_error_size * 100) if max_error_size > 0 else 0
            
            print_separator('-')
            print(f"Error Code:     {error_code}")
            
            # Apply coloring to occurrences
            count_str = f"{count:,}"
            colored_count = colorize_value(count_str, count_pct_of_max)
            print(f"Occurrences:    {colored_count} ({percentage:.2f}%)")
            
            # Apply coloring to data size
            size_str = f"{code_size_mb:.4f}"
            colored_size = colorize_value(size_str, size_pct_of_max)
            print(f"Data Size:      {colored_size} MB")
            
            # Show full example message with wrapping
            example = stats['error_code_examples'].get(error_code, 'N/A')
            # Check if message needs wrapping (longer than remaining space on first line)
            first_line_space = 64  # Space after "Example:        "
            if len(example) <= first_line_space:
                # Fits on one line
                print(f"Example:        {example}")
            else:
                # Needs wrapping - print first part, then wrap rest with indentation
                print(f"Example:        {example[:first_line_space]}")
                remaining = example[first_line_space:]
                wrapped_lines = textwrap.wrap(remaining, width=64, 
                                             initial_indent=' ' * 16,
                                             subsequent_indent=' ' * 16)
                for line in wrapped_lines:
                    print(line)
            
            # Get explanation from F5 docs
            explanation = get_error_code_explanation(error_code)
            print(f"Reference:      {explanation['explanation']}")
            
            # Extract message ID (first part) for F5 documentation anchor
            message_id = error_code.split(':')[0] if ':' in error_code else error_code
            
            # F5 Documentation link with prefix
            print(f"Documentation:  For basic information about this entry see: {explanation['uri']}")
            
            # Google Search link - use FULL error code including severity level
            google_search_url = f"https://www.google.com/search?q=F5+error+{error_code}"
            print(f"Google Search:  {google_search_url}")
            print()
        
        # Add notice about Rule entries if they exist
        if has_rule_entries:
            print_separator('-')
            
            # Calculate statistics for iRule entries
            rule_percentage = (rule_entry_count / stats['total_entries'] * 100) if stats['total_entries'] > 0 else 0
            rule_size_bytes = stats.get('rule_size_bytes', 0)
            rule_size_mb = rule_size_bytes / (1024 * 1024)
            
            print(f"\nNote: {rule_entry_count:,} iRule log entries were found in this file, representing")
            print(f"{rule_percentage:.1f}% of all log entries and totaling {rule_size_mb:.2f} MB in size.")
            print()
            print("These entries are logged by custom iRules and are detailed in Section 4 below.")
            print()
            print("F5 Recommended Practices for iRule Logging:")
            print("  • Use logging sparingly - excessive logging can impact system performance")
            print("  • Log at appropriate severity levels (info for normal operations, warning for issues)")
            print("  • Avoid logging in high-frequency events (e.g., every HTTP request) in production")
            print("  • Use 'log local0.' for iRule logs to separate them from system logs")
            print("  • Consider using High-Speed Logging (HSL) for high-volume logging requirements")
            print("  • Include relevant context (client IP, virtual server, pool member) in log messages")
            print("  • Use conditional logging based on debug flags or specific conditions")
            print("  • Regularly review and remove unnecessary logging statements")
            print("  • Reference: https://my.f5.com/manage/s/article/K13080")
            print()
    
    # Section 4: iRule Analysis (if any iRule entries exist)
    if has_rule_entries:
        # Check if we actually have irule data
        if stats.get('irule_total_counts'):
            print_section_header("4. iRULE ANALYSIS")
            
            print("Note: These log entries are generated by custom iRules configured on the BIG-IP system.")
            print()
            
            # Sort iRules by total count (descending)
            sorted_irules = sorted(stats['irule_total_counts'].items(), 
                                  key=lambda x: x[1], 
                                  reverse=True)
            
            for irule_name, total_count in sorted_irules:
                print_separator('-')
                print(f"iRule Name:     {irule_name}")
                print(f"Total Entries:  {total_count:,}")
                print()
                
                # Get events for this iRule and sort by count
                events = stats['irule_counts'].get(irule_name, {})
                sorted_events = sorted(events.items(), key=lambda x: x[1], reverse=True)
                
                print(f"  {'Event':<30} {'Count':>10} {'Percentage':>12}")
                print(f"  {'-' * 54}")
                
                for event, count in sorted_events:
                    event_percentage = (count / total_count * 100) if total_count > 0 else 0
                    print(f"  {event:<30} {count:>10,} {event_percentage:>11.2f}%")
                    
                    # Show example message on a new line
                    example = stats['irule_examples'].get(irule_name, {}).get(event, 'N/A')
                    print(f"  Example Log Entry:")
                    if len(example) <= 66:
                        print(f"    {example}")
                    else:
                        print(f"    {example[:66]}")
                        remaining = example[66:]
                        wrapped_lines = textwrap.wrap(remaining, width=66,
                                                     initial_indent='    ',
                                                     subsequent_indent='    ')
                        for line in wrapped_lines:
                            print(line)
                    print()
                print()
        else:
            # We detected Rule entries but couldn't parse them - show debug info
            print_section_header("4. iRULE ANALYSIS")
            print(f"Warning: {rule_entry_count:,} iRule entries were detected but could not be parsed.")
            print("This may indicate an unexpected log format. Please check the log file format.")
            print()
    
    # Footer
    print_separator('=')
    print(f"  END OF REPORT")
    print_separator('=')


def main():
    """Main function"""
    if len(sys.argv) != 2:
        print("Usage: bigloganalysis <logfile>")
        print("\nExample:")
        print("  bigloganalysis /var/log/ltm.log")
        sys.exit(1)
    
    logfile = sys.argv[1]
    
    print("Analyzing log file...")
    stats = analyze_log_file(logfile)
    
    display_results(stats)


if __name__ == "__main__":
    main()
