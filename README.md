# 🛡️ ShieldVultus
# ShieldVultus 🛡️

**ShieldVultus** is a robust security application designed for comprehensive file and URL scanning. Developed as part of the GIIS IDEATE 3.0 event AppElevate, this tool focuses on identifying potentially dangerous files and URLs, and managing quarantined items effectively.

## Features

- **File Scan**: Analyze files or directories to detect potential security threats using VirusTotal integration.
- **URL Check**: Validate URLs to identify malicious content and determine the final destination of shortened URLs.
- **Quarantine Management**: Move suspicious files to quarantine, list quarantined items, and restore files if deemed safe.

## Installation

To run the ShieldVultus application, you need Python and the required libraries. Follow these steps to set up:

1. **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/shieldvultus.git
    cd shieldvultus
    ```

2. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3. **Run the application**:
    ```bash
    python shieldvultus.py
    ```

## Requirements

- Python 3.x
- PyQt5
- Requests

Make sure to replace `yourusername` with your actual GitHub username and include the `requirements.txt` file in your repository with the necessary dependencies listed.

## Usage

1. **File Scan**:
   - Enter a file path or directory.
   - Click "Scan" to check for threats.

2. **URL Check**:
   - Enter a URL to check its safety and resolve redirections.

3. **Quarantine Management**:
   - Browse for files to quarantine.
   - List and restore quarantined files as needed.

## Contributing

Contributions are welcome! Please fork the repository, make your changes, and submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For any questions or feedback, please contact [your-email@example.com](mailto:your-email@example.com).

---

**ShieldVultus** - Your security companion for thorough file and URL checking.
