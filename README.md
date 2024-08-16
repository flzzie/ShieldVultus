# ShieldVultus 🛡️

**ShieldVultus** is a cybersecurity application developed for the GIIS IDEATE 3.0 event, AppElevate, as part of a school project. This tool is designed to offer robust protection by scanning files and URLs for potential threats. The project showcases practical skills in security application development and aims to demonstrate effective techniques for threat detection and management.

## Project Overview

ShieldVultus provides three main functionalities:

1. **File Scan**: 
   - **Purpose**: Detect potential security threats in files and directories.
   - **How**: By integrating with VirusTotal’s API, the application scans selected files or directories for malicious content and provides a safety report.

2. **URL Check**:
   - **Purpose**: Analyze URLs to determine if they are safe and to uncover the final destination of shortened URLs.
   - **How**: Input a URL to receive a safety assessment and resolution of any shortened links to their original form.

3. **Quarantine Management**:
   - **Purpose**: Isolate potentially dangerous files to prevent them from causing harm, and manage these files effectively.
   - **How**: Move files to a quarantine directory, list quarantined items, and restore them if they are verified as safe.

## Features

- **File Scan**: Scan individual files or entire directories for malware using VirusTotal.
- **URL Check**: Evaluate the safety of URLs and resolve shortened URLs to their original destinations.
- **Quarantine Management**: Manage quarantined files by isolating, listing, and restoring them as needed.

## Installation

To set up and run ShieldVultus, follow these steps:

1. **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/shieldvultus.git
    cd shieldvultus
    ```

2. **Install dependencies**:
    - You need to install the required Python libraries. Run the following command:
      ```bash
      pip install PyQt5
      pip install requests
      ```

3. **Obtain VirusTotal API Key**:
    - To use the file and URL scanning features, you need a VirusTotal API key. Get your API key from [VirusTotal](https://www.virustotal.com/gui/my-apikey).

4. **Run the application**:
    ```bash
    python shieldvultus.py
    ```

Ensure you have Python 3.x installed. The VirusTotal API also install the following library, including PyQt5 and Requests.

## Usage


- **File Scan**: 
  - Enter the file path or directory to scan.
  - Click "Scan" to check for threats.

- **URL Check**: 
  - Enter a URL to analyze and resolve any short links.

- **Quarantine Management**: 
  - Browse and select files to quarantine.
  - View and manage quarantined files, with options to restore if safe.

## Contributing

As this project is part of a school assignment, contributions are primarily for educational purposes. However, suggestions for improvements, issue reports, and code enhancements are welcome. Please fork the repository and submit a pull request with your contributions.

## License

This project is licensed under the MIT License. For details, see the [LICENSE](LICENSE) file.

## Contact

For questions or feedback, please contact [rishitsrivastava.official@gmail.com](mailto:rishitsrivastava.official@gmail.com).

---

**ShieldVultus** - A school project developed to enhance cybersecurity by providing tools for thorough file and URL scanning.
