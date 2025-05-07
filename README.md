
# Secure and Robust File Upload with Backend Processing (.NET Core)

## Features

- **Antivirus Scanning (Simulated)**: Simulated antivirus scanning with configurable delay.
- **Content Analysis (Basic)**: Basic content analysis based on file headers to detect unexpected file types.
- **Filename Sanitization**: Prevent directory traversal or injection vulnerabilities by sanitizing the uploaded file's name.
- **Rate Limiting**: Limits the number of uploads from a single IP address or user within a specific timeframe.
- **Robust Error Handling**: Handles various error scenarios such as file size limits, invalid types, or rate limit exceeded.
- **Asynchronous Processing**: Files are processed asynchronously after passing initial checks.
- **Status Tracking**: Track the status of the uploaded file through a unique processing ID (e.g., Pending, Scanning, Completed).
- **File Storage**: Files are stored securely in the server's `wwwroot` or temporary directory.

## Setup Instructions

1. **Clone the repository:**
   ```bash
   git clone  https://github.com/shadiaal/FileUpload_Task-.git
   cd FileUpload_Task
   ```

2. **Install dependencies:**
   ```bash
   dotnet restore
   ```

3. **Configure settings in `appsettings.json`:**
   Example configuration:
   ```json
   {
     "SimulateAntivirusScan": true,
     "ScanDelayMilliseconds": 3000,
   }
   ```

4. **Run the application:**
   ```bash
   dotnet run
   ```

5. **Frontend Example**:
   A basic file upload form using JavaScript to interact with the backend API.

## Security Considerations

- Antivirus simulation can be enabled or disabled.
- Rate limiting is implemented to prevent abuse.
- Filename sanitization is performed to avoid directory traversal attacks.
- Only allowed file types and sizes are accepted.


