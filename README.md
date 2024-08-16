# ShieldVultus 🛡️

**ShieldVultus** is a cybersecurity application developed as part of a school project for the GIIS IDEATE 3.0 event, AppElevate. This tool offers robust protection by scanning files and URLs for potential threats, showcasing practical skills in security application development and demonstrating effective techniques for threat detection and management.

## Table of Contents

- [Project Overview](#project-overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Project Overview

ShieldVultus provides three main functionalities:

1. **File Scan**: 
   - **Purpose**: Detect potential security threats in files and directories.
   - **How**: Integrates with VirusTotal’s API to scan selected files or directories for malicious content and provide a safety report.

2. **URL Check**:
   - **Purpose**: Analyze URLs to determine if they are safe and uncover the final destination of shortened URLs.
   - **How**: Input a URL to receive a safety assessment and resolve any shortened links to their original form.

3. **Quarantine Management**:
   - **Purpose**: Isolate potentially dangerous files to prevent harm and manage these files effectively.
   - **How**: Move files to a quarantine directory, list quarantined items, and restore them if verified as safe.

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

2. **Set up Python**:
    - Ensure Python 3.x is installed. If not, download and install it from [python.org](https://www.python.org/).

3. **Install dependencies**:
    - Install the required Python libraries by running:
      ```bash
      pip install PyQt5 requests
      ```
    - Dependencies are listed in the `requirements.txt` file, which also includes PyQt5 and Requests.

4. **Obtain VirusTotal API Key**:
    - To use the file and URL scanning features, you need a VirusTotal API key. Obtain your API key from [VirusTotal](https://www.virustotal.com/gui/my-apikey).

5. **Run the application**:
    ```bash
    python shieldvultus.py
    ```

## Usage

- **File Scan**: 
  - Enter the file path or directory to scan.
  - Click "Scan" to check for threats.
  - Example: Scan `C:\Users\Example\Documents` for malicious files.

- **URL Check**: 
  - Enter a URL to analyze and resolve any short links.
  - Example: Check `http://bit.ly/example` to find its final destination and safety status.

- **Quarantine Management**: 
  - Browse and select files to quarantine.
  - View and manage quarantined files, with options to restore if safe.
  - Example: Quarantine files from `C:\Users\Example\Downloads`.

## Contributing

As this project is part of a school assignment, contributions are primarily for educational purposes. Suggestions for improvements, issue reports, and code enhancements are welcome. Please fork the repository and submit a pull request with your contributions.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or feedback, please contact [your-email@example.com](mailto:your-email@example.com).

---

**ShieldVultus** - A school project developed to enhance cybersecurity by providing tools for thorough file and URL scanning.
