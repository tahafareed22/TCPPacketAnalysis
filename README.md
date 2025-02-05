# **TCP Analysis Tool**

## **Overview**

The **TCP Analysis Tool** parses a `.cap` file and provides detailed insights into TCP connections, including:

- **Summary Information**:
  - Total number of connections.
  - Packet counts and data transferred.
- **Detailed Connection Statistics**:
  - Start and end times.
  - Connection duration.
  - RTTs (Round-Trip Times).
  - Window sizes.
- **Overall Statistics**:
  - Minimum, maximum, and mean values for RTTs, packet counts, connection durations, and window sizes.

---

## **How to Use**

1. Open a terminal.
2. Navigate to the directory where `TCPAnalysisTool.py` is located.

3. Run the program using the following command:
   ```bash
   python TCPAnalysisTool.py path/to/cap-file.cap
   ```
   - Replace `path/to/cap-file.cap` with the actual path to your `.cap` file.

---

## **Example Usage**

### Input:
```bash
python TCPAnalysisTool sample-capture-file.cap
```

### Output:
- Total number of connections.
- Individual connection details (source/destination addresses, ports, duration, etc.).
- Aggregate statistics for all analyzed TCP connections.

---

## **Important Notes**

- Ensure the `.cap` file you provide is in a valid format supported by the script.
