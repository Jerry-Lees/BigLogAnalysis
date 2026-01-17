# bigloganalysis.py

## Description

`bigloganalysis.py` is a Python utility for parsing and analyzing F5 Networks BIG-IP LTM log files. The script processes log entries to generate statistical reports on error codes, severity levels, and custom iRule logging activity.

**Disclaimer:** This tool is not affiliated with, endorsed by, or supported by F5 Networks, Inc. It is an independent utility created for analyzing BIG-IP log files.

## System Requirements

- Python 3.6 or higher
- Standard Python library (no external dependencies)
- Optional: Network connectivity for F5 documentation references

## Installation

1. Download `bigloganalysis.py`
2. Set execute permissions:
   ```bash
   chmod +x bigloganalysis.py
   ```
3. Optional - Install to system PATH:
   ```bash
   sudo cp bigloganalysis.py /usr/local/bin/
   ```

---

## Usage

### Basic Syntax

```bash
./bigloganalysis.py <path-to-logfile>
```

### Examples

Analyze a log file:
```bash
./bigloganalysis.py /var/log/ltm.log
```

Save output to file:
```bash
./bigloganalysis.py /var/log/ltm.log > report.txt
```

View with pagination:
```bash
./bigloganalysis.py /var/log/ltm.log | less
```

---

## Log Format Requirements

The script expects BIG-IP log entries in the following space-delimited format:

**Standard entries:**
```
Month Day Year Hostname Level Process[PID]: ErrorCode: Message
```

**iRule entries:**
```
Month Day Year Hostname Level Process[PID]: Rule /Partition/iRule_name <EVENT>: Message
```

### Example Entries

Standard error code:
```
Jan 16 2025 HOMELAB-01.lees-family.io warning tmm2[11609]: 01200015:4: Warning, ICMP error limit reached.
```

iRule entry:
```
Jan 16 2025 HOMELAB-01.lees-family.io info tmm2[11609]: Rule /Common/Log_SSL_Cipher <CLIENTSSL_HANDSHAKE>: Client 10.100.100.250 offered ciphers: TLS_AES_256_GCM_SHA384
```

---

## Report Output

The script generates a formatted report with the following sections:

### Section 1: Log File Overview

- File path
- Total log entries (line count)
- File size in bytes, megabytes, and gigabytes

```
================================================================================
  1. LOG FILE OVERVIEW
================================================================================

File Path:        /var/log/ltm.log
Total Entries:    55,310

File Size:
  Bytes:          9,111,739
  Megabytes:      8.69 MB
  Gigabytes:      0.0085 GB
```

### Section 2: Error Level Summary

Breakdown of log entries by severity level with color-coded thresholds:
- Count and percentage of each severity level
- Data size consumed by each level
- Standard levels: `err`, `info`, `warning`, `crit`, `notice`

**Color coding:**
- Red: Values ≥40% of maximum
- Yellow: Values ≥20% of maximum  
- No color: Values <20% of maximum

Thresholds are calculated independently for count, percentage, and data size.

```
================================================================================
  2. ERROR LEVEL SUMMARY
================================================================================

Level                Count   Percentage    Size (MB)
--------------------------------------------------------------------------------
warning             31,975       57.81%          4.79
info                22,126       40.00%          3.58
notice               1,060        1.92%          0.29
err                    149        0.27%          0.03
crit                     0        0.00%          0.00
```

### Section 3: Error Code Analysis

Detailed analysis of each unique error code (excluding iRule entries):
- Occurrence count and percentage (color-coded)
- Data size consumed (color-coded)
- Example log message with text wrapping
- Reference explanation
- Link to F5 documentation
- Google search URL

```
--------------------------------------------------------------------------------
Error Code:     01200015:4:
Occurrences:    4,234 (7.65%)
Data Size:      0.6234 MB
Example:        Warning, ICMP error limit reached.
Reference:      Error code 01200015:4:: Check F5 documentation for detailed explanation
Documentation:  For basic information about this entry see: https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/releasenotes/related/log-messages.html#01200015
Google Search:  https://www.google.com/search?q=F5+error+01200015:4:
```

If iRule entries are present, a note appears at the end of this section:
```
Note: 22,125 iRule log entries were found in this file, representing
40.0% of all log entries and totaling 300.00 MB in size.

These entries are logged by custom iRules and are detailed in Section 4 below.

F5 Recommended Practices for iRule Logging:
  • Use logging sparingly - excessive logging can impact system performance
  • Log at appropriate severity levels (info for normal operations, warning for issues)
  • Avoid logging in high-frequency events (e.g., every HTTP request) in production
  • Use 'log local0.' for iRule logs to separate them from system logs
  • Consider using High-Speed Logging (HSL) for high-volume logging requirements
  • Include relevant context (client IP, virtual server, pool member) in log messages
  • Use conditional logging based on debug flags or specific conditions
  • Regularly review and remove unnecessary logging statements
  • Reference: https://my.f5.com/manage/s/article/K13080
```

### Section 4: iRule Analysis

Appears only when iRule entries are detected. Groups entries by iRule name (sorted by frequency):
- Total entries per iRule
- Breakdown by event type with counts and percentages
- Example log message for each event

```
================================================================================
  4. iRULE ANALYSIS
================================================================================

Note: These log entries are generated by custom iRules configured on the BIG-IP system.

--------------------------------------------------------------------------------
iRule Name:     /Common/Log_SSL_Cipher
Total Entries:  8,572

  Event                               Count   Percentage
  ------------------------------------------------------
  CLIENTSSL_HANDSHAKE                 5,143       60.00%
  Example Log Entry:
    Client 10.100.100.250 offered ciphers: TLS_AES_256_GCM_SHA384

  HTTP_REQUEST                        3,429       40.00%
  Example Log Entry:
    Client 10.100.100.250 SSL handshake complete - Final cipher: 
    ECDHE-RSA-AES128-GCM-SHA256
```

---

## Color Coding Reference

### Purpose

Color coding identifies high-impact items requiring attention. Values are compared against the maximum value in each category.

### Thresholds

| Color  | Range | Meaning |
|--------|-------|---------|
| None   | <20%  | Normal operation |
| Yellow | 20-39% | Warrants monitoring |
| Red    | ≥40%  | High priority for investigation |

### Application

Each metric type uses independent thresholds:
- **Count**: Based on error code or level with most occurrences
- **Percentage**: Based on percentage value (20%, 40%)
- **Size**: Based on error code or level consuming most space

A single item may have different colors across metrics (e.g., high count but low size).

### Interpretation Example

```
Level                Count   Percentage    Size (MB)
warning             [RED]    [YELLOW]      [RED]
info                [RED]    [YELLOW]      [NORMAL]
err                 [YELLOW] [NORMAL]      [NORMAL]
```

- `warning`: Most frequent (red), high percentage (yellow), large size (red) → Priority: High
- `info`: High frequency (red), high percentage (yellow), small size → Priority: Medium
- `err`: Moderate frequency (yellow), low percentage, small size → Priority: Medium

### Terminal Compatibility

ANSI color codes work on:
- Linux terminals (bash, zsh, fish)
- macOS Terminal and iTerm2
- Windows Terminal, Windows Subsystem for Linux (WSL)
- PowerShell 7+
- SSH sessions with color support enabled

Colors may not display correctly in:
- Windows Command Prompt (cmd.exe)
- Very old terminal emulators
- Text file output (colors are automatically stripped)

---

## Troubleshooting

### Script Execution Issues

**Permission denied**
```bash
chmod +x bigloganalysis.py
```

**Python not found**
```bash
# RHEL/CentOS/Fedora
sudo yum install python3

# Debian/Ubuntu
sudo apt-get install python3

# macOS
brew install python3
```

### File Access Issues

**Cannot read log file**
```bash
# Use sudo
sudo ./bigloganalysis.py /var/log/ltm.log

# Or copy to accessible location
cp /var/log/ltm.log ~/ltm.log
./bigloganalysis.py ~/ltm.log
```

**File not found**
```bash
# Verify file exists
ls -la /var/log/ltm.log

# Use absolute path
./bigloganalysis.py /full/path/to/logfile.log
```

### Display Issues

**Colors display as escape codes (e.g., `^[[91m`)**

Terminal does not support ANSI codes. Redirect to file to remove color codes:
```bash
./bigloganalysis.py /var/log/ltm.log > report.txt
```

### Performance Issues

**Large file processing**

For files >500MB, consider filtering before analysis:
```bash
# Filter by date
grep "Jan 16" /var/log/ltm.log > filtered.log
./bigloganalysis.py filtered.log

# Filter by severity
grep -E " (err|crit) " /var/log/ltm.log > errors.log
./bigloganalysis.py errors.log

# Process compressed logs
zcat /var/log/ltm.log.gz | head -100000 > sample.log
./bigloganalysis.py sample.log
```

**Out of memory errors**

Split large files:
```bash
split -l 100000 /var/log/ltm.log chunk_
for file in chunk_*; do
    ./bigloganalysis.py $file > analysis_$file.txt
done
```

### Parse Errors

**Entries not counted**

The script requires strict format compliance. Malformed entries are skipped. Verify format matches:
```
Month Day Year Hostname Level Process[PID]: ErrorCode: Message
```

Missing fields (year, hostname, process ID) will cause parsing failures.

**iRule entries not detected**

Section 4 only appears if the script can successfully parse iRule format:
```
Month Day Year Hostname Level Process[PID]: Rule /Partition/iRule_name <EVENT>: Message
```

If the warning message appears, the format does not match expectations.

### Network Issues

**F5 documentation lookup fails**

Documentation fetching is optional. The script continues without it. If lookups fail:
- Check network connectivity
- Verify firewall allows HTTPS to `techdocs.f5.com`
- Note: Documentation text extraction may not work for all error codes

---

## Advanced Usage

### Automated Daily Analysis

Create a shell script:
```bash
#!/bin/bash
DATE=$(date +%Y-%m-%d)
LOGFILE="/var/log/ltm.log"
REPORT_DIR="/var/reports"

/usr/local/bin/bigloganalysis.py $LOGFILE > $REPORT_DIR/analysis_$DATE.txt

# Email report
if [ -f "$REPORT_DIR/analysis_$DATE.txt" ]; then
    mail -s "BIG-IP Log Analysis - $DATE" admin@example.com < $REPORT_DIR/analysis_$DATE.txt
fi
```

### Scheduled Execution

Add to crontab:
```bash
# Daily analysis at 1:00 AM
0 1 * * * /usr/local/bin/bigloganalysis.py /var/log/ltm.log > /var/reports/daily_$(date +\%Y\%m\%d).txt 2>&1

# Weekly summary every Monday at 6:00 AM  
0 6 * * 1 /usr/local/bin/bigloganalysis.py /var/log/ltm.log > /var/reports/weekly_$(date +\%Y\%m\%d).txt 2>&1
```

### Processing Compressed Logs

```bash
# Decompress and analyze
zcat /var/log/ltm.log.gz > /tmp/ltm.log
./bigloganalysis.py /tmp/ltm.log
rm /tmp/ltm.log

# Or use process substitution (Linux/macOS)
./bigloganalysis.py <(zcat /var/log/ltm.log.gz)
```

### Combining Multiple Log Files

```bash
# Concatenate multiple files
cat /var/log/ltm.log* > combined.log
./bigloganalysis.py combined.log

# Sort by timestamp after combining
cat /var/log/ltm-2025-01-*.log | sort > january.log
./bigloganalysis.py january.log
```

### Filtering Before Analysis

```bash
# Specific error code
grep "01200015" /var/log/ltm.log > icmp_errors.log
./bigloganalysis.py icmp_errors.log

# Specific severity levels
grep -E " (err|crit) " /var/log/ltm.log > critical_errors.log
./bigloganalysis.py critical_errors.log

# Time window (last 24 hours using find)
find /var/log -name "ltm.log" -mtime -1 -exec cat {} \; > recent.log
./bigloganalysis.py recent.log

# Specific virtual server (in iRule logs)
grep "vs_production" /var/log/ltm.log > vs_production.log
./bigloganalysis.py vs_production.log
```

---

## Common Error Codes

Reference for frequently encountered BIG-IP error codes:

| Error Code | Severity | Description |
|------------|----------|-------------|
| 01010028 | Critical/Info | Pool member availability issues |
| 01010029 | Error | No pool members available |
| 01070638 | Info | Pool member monitor status down |
| 01070727 | Info | Pool member monitor status up |
| 01200015 | Warning | ICMP error limit reached |
| 01260009 | Warning | TCP connection timeout |
| 01260013 | Warning | SSL handshake failure |
| 01490505 | Info | Disk usage threshold |
| 01170001 | Error | Configuration load failure |
| 01070734 | Info | Pool member enabled/disabled |

For detailed information, refer to:
- F5 Log Messages Reference: https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/releasenotes/related/log-messages.html
- F5 Support Portal: https://my.f5.com

---

## Performance Characteristics

- Processing speed: ~100,000 entries per second on modern hardware
- Memory usage: Minimal (streaming file reader)
- File size handling: Tested with files up to 2GB
- Typical processing time: 30-60 seconds per 1GB log file

---

## Limitations

1. Requires exact BIG-IP log format compliance
2. Non-standard log entries are skipped without notification
3. iRule entries must follow specific format to be detected
4. Color output requires ANSI-compatible terminal
5. F5 documentation lookup depends on network availability and may not retrieve all error codes
6. No support for real-time log monitoring (file input only)
7. Does not parse or analyze traffic statistics beyond log entries

---

## Version History

**v1.2** (2025-01-17)
- Added support for iRule log entry analysis
- Updated iRule format parser to handle path-style names
- Added Section 4 for iRule analysis with event breakdown
- Added F5 recommended practices for iRule logging
- Modified example display format in iRule section
- Added iRule entry statistics to Section 3 notice

**v1.1** (2025-01-17)
- Added color coding with 20%/40% thresholds
- Added text wrapping for long messages
- Added Google Search links for error codes
- Modified documentation links with descriptive prefix
- Fixed column alignment with color codes

**v1.0** (2025-01-17)
- Initial release
- Log parsing and analysis
- Error level and error code statistics
- File size calculations
- F5 documentation references

---

## References

- F5 BIG-IP Log Messages: https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/releasenotes/related/log-messages.html
- F5 BIG-IP LTM Documentation: https://techdocs.f5.com/en-us/bigip-15-0-0/big-ip-local-traffic-manager-ltm-implementations.html
- F5 iRule Logging Best Practices: https://my.f5.com/manage/s/article/K13080

---

## License

This utility is provided as-is without warranty of any kind. Use at your own discretion.

## Disclaimer

This tool is not affiliated with, endorsed by, or supported by F5 Networks, Inc. F5, BIG-IP, and iRules are trademarks or registered trademarks of F5 Networks, Inc. in the U.S. and other countries.

---

## Support

### Tool Issues and Questions

For issues or questions about this tool, you can:

1. **Open a GitHub Issue** with the following information:

**Issue Template:**
```
**Description:**
Brief description of the issue or feature request

**Environment:**
- Python version: (output of `python3 --version`)
- Operating system: (e.g., Ubuntu 22.04, RHEL 8, macOS 13)
- BIG-IP version: (if known)

**Steps to Reproduce:** (for bugs)
1. Command executed
2. Expected behavior
3. Actual behavior

**Log Sample:** (for parsing issues)
Provide 5-10 lines from your log file that demonstrate the issue.
Redact sensitive information (IP addresses, hostnames) if necessary.

**Error Output:**
Include any error messages or unexpected output
```

2. **Contact your system administrator** for internal support and deployment questions

### Contributing

Contributions are welcome. To contribute:

1. Fork the repository
2. Create a feature branch
3. Make your changes with clear commit messages
4. Test with various log file formats
5. Submit a pull request with:
   - Description of changes
   - Test cases or examples
   - Documentation updates (if applicable)

