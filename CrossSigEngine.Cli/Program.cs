using CrossSigEngine.Core.Models;
using CrossSigEngine.Core.Serialization;
using CrossSigEngine.Core.Generators;
using CrossSigEngine.Generators.Yara;
using CrossSigEngine.Generators.SnortSuricata;
using CrossSigEngine.Generators.Sigma;
using CrossSigEngine.Generators.ClamAV;
using CrossSigEngine.Generators.IOC;
using CrossSigEngine.Generators.PEiD;
using CrossSigEngine.Generators.CustomPattern;
using CrossSigEngine.Generators.Zeek;
using CrossSigEngine.Core.Validation;
using CrossSigEngine.Core.Detection;
using CrossSigEngine.Core.Alerts;

static int PrintUsage()
{
	Console.WriteLine("CrossSigEngine CLI");
	Console.WriteLine("Commands:");
	Console.WriteLine("  generate --family <yara|snort|suricata|sigma|clamav|ioc|peid|custom|zeek|all> --in <threat.json> --out <dir>");
	Console.WriteLine("  validate --in <threat.json>");
	Console.WriteLine("  scan --in <threat.json> --path <file|dir> [--out <alerts.jsonl>] [--recursive] [--parallel <N>] [--exclude <glob>] [--max-file-size <bytes>] [--webhook <url>] [--webhook-header <k:v>] [--webhook-format <json|slack>] [--webhook-delay-ms <ms>] [--eventlog <source>] [--fail-on-match]");
	Console.WriteLine("  serve-webhook [--port <8080>] [--path </>] [--out <webhook.jsonl>]");
	Console.WriteLine("  sandbox --provider <vt|cuckoo> --file <path>|--url <url> [--api-key <key>] [--base-url <http://cuckoo:8090/api/]> [--out <result.json>]");
	return 1;
}

if (args.Length == 0) return PrintUsage();

var cmd = args[0].ToLowerInvariant();
if (cmd == "generate")
{
	string? family = null;
	string? input = null;
	string? output = null;
	for (int i = 1; i < args.Length; i++)
	{
		switch (args[i])
		{
			case "--family": family = i + 1 < args.Length ? args[++i] : null; break;
			case "--in": input = i + 1 < args.Length ? args[++i] : null; break;
			case "--out": output = i + 1 < args.Length ? args[++i] : null; break;
		}
	}

	if (string.IsNullOrWhiteSpace(family) || string.IsNullOrWhiteSpace(input) || string.IsNullOrWhiteSpace(output))
	{
		Console.Error.WriteLine("Missing required options.");
		return PrintUsage();
	}

	if (!File.Exists(input))
	{
		Console.Error.WriteLine($"Input file not found: {input}");
		return 2;
	}
	Directory.CreateDirectory(output);

	var json = File.ReadAllText(input);
	var threat = ThreatSerializer.FromJson(json);

	IEnumerable<IRuleGenerator> GetGenerators(string fam)
	{
		switch (fam)
		{
			case "yara":
				return new IRuleGenerator[] { new YaraGenerator() };
			case "snort":
			case "suricata":
				return new IRuleGenerator[] { new SnortSuricataGenerator() };
			case "sigma":
				return new IRuleGenerator[] { new SigmaGenerator() };
			case "all":
				return new IRuleGenerator[] { new YaraGenerator(), new SnortSuricataGenerator(), new SigmaGenerator(), new ClamAvGenerator(), new IOCGenerator(), new PeidGenerator(), new CustomPatternGenerator(), new ZeekGenerator() };
			case "clamav":
				return new IRuleGenerator[] { new ClamAvGenerator() };
			case "ioc":
				return new IRuleGenerator[] { new IOCGenerator() };
			case "peid":
				return new IRuleGenerator[] { new PeidGenerator() };
			case "custom":
				return new IRuleGenerator[] { new CustomPatternGenerator() };
			case "zeek":
				return new IRuleGenerator[] { new ZeekGenerator() };
			default:
				return Array.Empty<IRuleGenerator>();
		}
	}

	var gens = GetGenerators(family.ToLowerInvariant());
	if (!gens.Any())
	{
		Console.Error.WriteLine($"Unknown family: {family}");
		return 3;
	}
	foreach (var g in gens)
	{
		var artifacts = g.Generate(threat);
		foreach (var kv in artifacts)
		{
			var path = Path.Combine(output, kv.Key);
			File.WriteAllText(path, kv.Value);
			Console.WriteLine($"Wrote {path}");
		}
	}
	return 0;
}

if (cmd == "validate")
{
	string? input = null;
	for (int i = 1; i < args.Length; i++)
	{
		switch (args[i])
		{
			case "--in": input = i + 1 < args.Length ? args[++i] : null; break;
		}
	}
	if (string.IsNullOrWhiteSpace(input))
	{
		Console.Error.WriteLine("Missing required option --in <file>");
		return PrintUsage();
	}
	if (!File.Exists(input))
	{
		Console.Error.WriteLine($"Input file not found: {input}");
		return 2;
	}

	var json = File.ReadAllText(input);
	var threat = ThreatSerializer.FromJson(json);
	var issues = ThreatValidator.Validate(threat);
	if (issues.Count == 0)
	{
		Console.WriteLine("Validation OK: no issues found.");
		return 0;
	}
	foreach (var issue in issues)
	{
		var prefix = issue.Severity == ValidationSeverity.Error ? "ERROR" : "WARN";
		Console.WriteLine($"{prefix}: {issue.Path} - {issue.Message}");
	}
	var hadErrors = issues.Any(i => i.Severity == ValidationSeverity.Error);
	return hadErrors ? 4 : 0;
}

if (cmd == "scan")
{
	string? input = null;
	string? targetPath = null;
	string? outFile = null;
	bool recursive = false;
	string? webhookUrl = null;
	string? eventLogSource = null;
	int parallelism = 1;
	int webhookDelayMs = 0;
	var exclude = new List<string>();
	long maxFileSize = 0;
	var webhookHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
	string webhookFormat = "json";
	bool failOnMatch = false;
	for (int i = 1; i < args.Length; i++)
	{
		switch (args[i])
		{
			case "--in": input = i + 1 < args.Length ? args[++i] : null; break;
			case "--path": targetPath = i + 1 < args.Length ? args[++i] : null; break;
			case "--out": outFile = i + 1 < args.Length ? args[++i] : null; break;
			case "--recursive": recursive = true; break;
			case "--parallel": parallelism = i + 1 < args.Length && int.TryParse(args[i+1], out var p) ? (i++, Math.Max(1, p)).Item2 : 1; break;
			case "--exclude": if (i + 1 < args.Length) exclude.Add(args[++i]); break;
			case "--max-file-size": if (i + 1 < args.Length && long.TryParse(args[i+1], out var m)) { maxFileSize = (i++, Math.Max(0, m)).Item2; } break;
			case "--webhook": webhookUrl = i + 1 < args.Length ? args[++i] : null; break;
			case "--webhook-header":
				if (i + 1 < args.Length)
				{
					var raw = args[++i];
					var idx = raw.IndexOf(':');
					if (idx > 0)
					{
						var k = raw.Substring(0, idx).Trim();
						var v = raw.Substring(idx + 1).Trim();
						if (!string.IsNullOrEmpty(k)) webhookHeaders[k] = v;
					}
				}
				break;
			case "--webhook-format": webhookFormat = i + 1 < args.Length ? args[++i] : "json"; break;
			case "--webhook-delay-ms": webhookDelayMs = i + 1 < args.Length && int.TryParse(args[i+1], out var d) ? (i++, Math.Max(0, d)).Item2 : 0; break;
			case "--eventlog": eventLogSource = i + 1 < args.Length ? args[++i] : null; break;
			case "--fail-on-match": failOnMatch = true; break;
		}
	}
	if (string.IsNullOrWhiteSpace(input) || string.IsNullOrWhiteSpace(targetPath))
	{
		Console.Error.WriteLine("Missing required options: --in <file> and --path <file|dir>");
		return PrintUsage();
	}
	if (!File.Exists(input))
	{
		Console.Error.WriteLine($"Input file not found: {input}");
		return 2;
	}
	var json = File.ReadAllText(input);
	var threat = ThreatSerializer.FromJson(json);
	var issues = ThreatValidator.Validate(threat);
	if (issues.Any(i => i.Severity == ValidationSeverity.Error))
	{
		Console.Error.WriteLine("Validation errors present. Refusing to scan.");
		foreach (var issue in issues.Where(i => i.Severity == ValidationSeverity.Error))
			Console.Error.WriteLine($"ERROR: {issue.Path} - {issue.Message}");
		return 4;
	}

	var events = FileScanner.ScanPath(threat, targetPath, recursive, parallelism, exclude, maxFileSize).ToList();
	Console.WriteLine($"Scan complete. Matches: {events.Count}");

	// Prepare sinks
	var sinks = new List<IAlertSink>();
	if (!string.IsNullOrWhiteSpace(webhookUrl)) sinks.Add(new WebhookAlertSink(webhookUrl, webhookHeaders.Count > 0 ? webhookHeaders : null, webhookFormat));
	if (!string.IsNullOrWhiteSpace(eventLogSource)) sinks.Add(new WindowsEventLogAlertSink(eventLogSource));

	// Optional JSONL output
	StreamWriter? sw = null;
	if (!string.IsNullOrWhiteSpace(outFile)) sw = new StreamWriter(outFile, false, System.Text.Encoding.UTF8);

	foreach (var e in events)
	{
		// console
		Console.WriteLine($"{e.IndicatorType} match: {e.Indicator} at {e.Offset} in {e.FilePath}");

		// jsonl
		if (sw != null)
		{
			var line = System.Text.Json.JsonSerializer.Serialize(e);
			sw.WriteLine(line);
		}

		// sinks
		if (sinks.Count > 0)
		{
			var record = new AlertRecord(
				RuleName: threat.Name,
				Family: threat.Family,
				Source: "scan",
				Timestamp: DateTimeOffset.UtcNow,
				Event: e);
			foreach (var sink in sinks)
			{
				try { sink.WriteAsync(record).GetAwaiter().GetResult(); }
				catch { /* ignore sink errors */ }
			}
			if (webhookDelayMs > 0 && !string.IsNullOrWhiteSpace(webhookUrl))
			{
				try { Thread.Sleep(webhookDelayMs); } catch { }
			}
		}
	}

	if (sw != null)
	{
		sw.Flush();
		sw.Dispose();
		Console.WriteLine($"Wrote alerts: {outFile}");
	}
	if (failOnMatch && events.Count > 0) return 5;
	return 0;
}

if (cmd == "serve-webhook")
{
	int port = 8080;
	string path = "/";
	string? outFile = null;
	for (int i = 1; i < args.Length; i++)
	{
		switch (args[i])
		{
			case "--port":
				if (i + 1 < args.Length && int.TryParse(args[i+1], out var pPort)) { i++; port = pPort; }
				else { port = 8080; }
				break;
			case "--path": path = i + 1 < args.Length ? args[++i] : "/"; break;
			case "--out": outFile = i + 1 < args.Length ? args[++i] : null; break;
		}
	}
	var cts = new CancellationTokenSource();
	Console.CancelKeyPress += (s, e) => { e.Cancel = true; cts.Cancel(); };
	var server = new CrossSigEngine.Core.Alerts.LocalWebhookServer(port, path, outFile);
	server.RunAsync(cts.Token).GetAwaiter().GetResult();
	return 0;
}

if (cmd == "sandbox")
{
	string provider = "vt";
	string? file = null;
	string? url = null;
	string? apiKey = Environment.GetEnvironmentVariable("VT_API_KEY");
	string? baseUrl = null;
	string? outFile = null;
	for (int i = 1; i < args.Length; i++)
	{
		switch (args[i])
		{
			case "--provider": provider = i + 1 < args.Length ? args[++i] : provider; break;
			case "--file": file = i + 1 < args.Length ? args[++i] : null; break;
			case "--url": url = i + 1 < args.Length ? args[++i] : null; break;
			case "--api-key": apiKey = i + 1 < args.Length ? args[++i] : apiKey; break;
			case "--base-url": baseUrl = i + 1 < args.Length ? args[++i] : baseUrl; break;
			case "--out": outFile = i + 1 < args.Length ? args[++i] : null; break;
		}
	}
	if (provider == "vt" && string.IsNullOrWhiteSpace(apiKey))
	{
		Console.Error.WriteLine("Missing API key. Provide --api-key or set VT_API_KEY environment variable.");
		return 1;
	}
	if (string.IsNullOrWhiteSpace(file) && string.IsNullOrWhiteSpace(url))
	{
		Console.Error.WriteLine("Provide --file <path> or --url <url>.");
		return 1;
	}

	CrossSigEngine.Core.Sandbox.ISandboxClient client;
	if (provider == "vt") client = new CrossSigEngine.Core.Sandbox.VirusTotalSandboxClient(apiKey!);
	else if (provider == "cuckoo")
	{
		if (string.IsNullOrWhiteSpace(baseUrl)) { Console.Error.WriteLine("For provider=cuckoo, provide --base-url <http://host:port/api/>"); return 1; }
		client = new CrossSigEngine.Core.Sandbox.CuckooSandboxClient(baseUrl!, apiKey);
	}
	else { Console.Error.WriteLine($"Unknown provider: {provider}"); return 1; }
	CrossSigEngine.Core.Sandbox.SandboxResult result;
	try
	{
		if (!string.IsNullOrWhiteSpace(file))
			result = client.AnalyzeFileAsync(file!).GetAwaiter().GetResult();
		else
			result = client.AnalyzeUrlAsync(url!).GetAwaiter().GetResult();
	}
	catch (Exception ex)
	{
		Console.Error.WriteLine("Sandbox error: " + ex.Message);
		return 1;
	}

	var jsonOut = System.Text.Json.JsonSerializer.Serialize(result, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
	if (!string.IsNullOrWhiteSpace(outFile))
	{
		File.WriteAllText(outFile, jsonOut, System.Text.Encoding.UTF8);
		Console.WriteLine($"Wrote sandbox result: {outFile}");
	}
	else
	{
		Console.WriteLine(jsonOut);
	}
	return 0;
}

return PrintUsage();
