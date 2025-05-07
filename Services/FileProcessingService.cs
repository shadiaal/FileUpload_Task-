using System.Threading.Channels;
using System.Collections.Concurrent;

public class FileProcessingService : BackgroundService
{
	private readonly Channel<FileUploadTask> _uploadChannel;
	private readonly ILogger<FileProcessingService> _logger;

	public FileProcessingService(Channel<FileUploadTask> uploadChannel, ILogger<FileProcessingService> logger)
	{
		_uploadChannel = uploadChannel;
		_logger = logger;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		await foreach (var task in _uploadChannel.Reader.ReadAllAsync(stoppingToken))
		{
			try
			{
				_logger.LogInformation("Processing file: {FileName}", task.OriginalFileName);
				UploadStatusTracker.StatusMap[task.ProcessingId] = "Scanning";

				// Simulate antivirus scan
				if (task.SimulateScan)
				{
					await Task.Delay(task.ScanDelayMs, stoppingToken);
				}

				// Basic header/content check (simulate)
				if (!IsFileHeaderValid(task.FileContent))
				{
					UploadStatusTracker.StatusMap[task.ProcessingId] = "VirusDetected";
					continue;
				}

				UploadStatusTracker.StatusMap[task.ProcessingId] = "Processing";

				// Ensure the target directory exists
				Directory.CreateDirectory(task.StoragePath);

				// Upload the file
				var filePath = Path.Combine(task.StoragePath, task.OriginalFileName);
				await File.WriteAllBytesAsync(filePath, task.FileContent, stoppingToken);

				UploadStatusTracker.StatusMap[task.ProcessingId] = "Completed";
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Failed to process file {FileName}", task.OriginalFileName);
				UploadStatusTracker.StatusMap[task.ProcessingId] = "Failed";
			}
		}
	}

	private bool IsFileHeaderValid(byte[] content)
	{
		if (content.Length >= 4)
		{
			var pdfMagic = new byte[] { 0x25, 0x50, 0x44, 0x46 }; // %PDF
			var jpgMagic = new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 }; // JPEG
			var docxMagic = new byte[] { 0x50, 0x4B, 0x03, 0x04 }; // DOCX/ZIP
			var utf8Bom = new byte[] { 0xEF, 0xBB, 0xBF }; // TXT with BOM

			if (pdfMagic.SequenceEqual(content.Take(4)) ||
				jpgMagic.SequenceEqual(content.Take(4)) ||
				docxMagic.SequenceEqual(content.Take(4)) ||
				content.Take(3).SequenceEqual(utf8Bom) ||
				content.All(b => b >= 0x09 && b <= 0x7E)) // ASCII heuristic
			{
				return true;
			}
		}

		return false;
	}
}
