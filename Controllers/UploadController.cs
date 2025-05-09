using Microsoft.AspNetCore.Mvc;
using System.Collections.Concurrent;
using System.Threading.Channels;

[ApiController]
[Route("[controller]")]
public class UploadController : ControllerBase
{
	private readonly Channel<FileUploadTask> _uploadChannel;
	private readonly IConfiguration _config;
	private readonly IWebHostEnvironment _env;
	private readonly ConcurrentDictionary<string, string> _statusMap;

	private static readonly Dictionary<string, List<DateTime>> UploadLog = new();

	public UploadController(Channel<FileUploadTask> uploadChannel, IConfiguration config,
							IWebHostEnvironment env, ConcurrentDictionary<string, string> statusMap)
	{
		_uploadChannel = uploadChannel;
		_config = config;
		_env = env;
		_statusMap = statusMap;
	}

	[HttpPost("upload")]
	public async Task<IActionResult> Upload(IFormFile file)
	{
		if (file == null || file.Length == 0)
			return BadRequest("File is empty.");

		if (file.Length > 10 * 1024 * 1024) // 10 MB
			return BadRequest("File too large.");

		var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
		if (ip != null && IsRateLimitExceeded(ip))
			return StatusCode(429, "Rate limit exceeded. Please try again later.");

		if (IsExecutableFile(file))
			return BadRequest("Executable files are not allowed.");

		var id = Guid.NewGuid().ToString();
		var sanitized = SanitizeFileName(file.FileName);

		byte[] fileBytes;
		using (var ms = new MemoryStream())
		{
			await file.CopyToAsync(ms);
			fileBytes = ms.ToArray();
		}

		_statusMap[id] = "Pending";

		bool simulateScan = _config.GetValue<bool>("SimulateAntivirusScan");
		int scanDelay = _config.GetValue<int>("ScanDelayMilliseconds");

		var storagePath = Path.Combine(_env.WebRootPath, "uploads");

		await _uploadChannel.Writer.WriteAsync(new FileUploadTask
		{
			ProcessingId = id,
			FileContent = fileBytes,
			OriginalFileName = sanitized,
			SimulateScan = simulateScan,
			ScanDelayMs = scanDelay,
			StoragePath = storagePath
		});

		return Ok(new { processingId = id });
	}

	[HttpGet("status/{id}")]
	public IActionResult Status(string id)
	{
		if (!_statusMap.TryGetValue(id, out var status))
			return NotFound("Invalid ID");

		return Ok(new { status });
	}

	private bool IsRateLimitExceeded(string ip, int maxUploads = 5, int intervalSeconds = 60)
	{
		lock (UploadLog)
		{
			if (!UploadLog.ContainsKey(ip))
				UploadLog[ip] = new List<DateTime>();

			var now = DateTime.UtcNow;
			UploadLog[ip] = UploadLog[ip].Where(t => (now - t).TotalSeconds <= intervalSeconds).ToList();

			if (UploadLog[ip].Count >= maxUploads)
				return true;

			UploadLog[ip].Add(now);
			return false;
		}
	}

	private bool IsExecutableFile(IFormFile file)
	{
		using var reader = new BinaryReader(file.OpenReadStream());
		var headerBytes = reader.ReadBytes(2);
		return headerBytes.SequenceEqual(new byte[] { 0x4D, 0x5A }); // 'MZ' header
	}

	private string SanitizeFileName(string fileName)
	{
		return Path.GetFileName(fileName)
				   .Replace("..", "")
				   .Replace("//", "")
				   .Replace("\\", "")
				   .Replace(":", "");
	}
}
