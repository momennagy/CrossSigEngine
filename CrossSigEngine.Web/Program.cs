using System.Text;
using CrossSigEngine.Core.Generators;
using CrossSigEngine.Core.Serialization;
using CrossSigEngine.Core.Validation;
using CrossSigEngine.Core.Detection;
using CrossSigEngine.Core.Alerts;
using CrossSigEngine.Web;
using CrossSigEngine.Generators.Yara;
using CrossSigEngine.Generators.SnortSuricata;
using CrossSigEngine.Generators.Sigma;
using CrossSigEngine.Generators.ClamAV;
using CrossSigEngine.Generators.IOC;
using CrossSigEngine.Generators.PEiD;
using CrossSigEngine.Generators.CustomPattern;
using CrossSigEngine.Generators.Zeek;
using CrossSigEngine.Core.Sandbox;
using Microsoft.EntityFrameworkCore;
using CrossSigEngine.Web.Data;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddCors(opts =>
{
    opts.AddDefaultPolicy(p => p
        .AllowAnyOrigin()
        .AllowAnyHeader()
        .AllowAnyMethod());
});

// EF Core SQLite for Threats DB (fixed data folder)
// Prefer environment override CSE_DATA_DIR, otherwise use a stable 'data' folder under the content root
var dataDir = Environment.GetEnvironmentVariable("CSE_DATA_DIR");
if (string.IsNullOrWhiteSpace(dataDir))
{
    // builder.Environment.ContentRootPath points to the app's content root (project dir when running via `dotnet run`)
    dataDir = Path.Combine(builder.Environment.ContentRootPath, "data");
}
try { Directory.CreateDirectory(dataDir); } catch { /* ignore */ }
var dbPath = Path.Combine(dataDir, "cse.sqlite");
builder.Services.AddDbContext<AppDbContext>(opt => opt.UseSqlite($"Data Source={dbPath}"));

var app = builder.Build();
app.UseExceptionHandler(appErr =>
{
    appErr.Run(async ctx =>
    {
        ctx.Response.StatusCode = 500;
        ctx.Response.ContentType = "application/json";
        var problem = new { title = "Internal Server Error", status = 500 };
        await ctx.Response.WriteAsJsonAsync(problem);
    });
});
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseCors();
app.UseSwagger();
app.UseSwaggerUI();

// Ensure DB and seed from samples if empty
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await db.Database.EnsureCreatedAsync();
    if (!await db.Threats.AnyAsync())
    {
        try
        {
            var root = AppContext.BaseDirectory;
            var repoRoot = Path.GetFullPath(Path.Combine(root, "..", "..", ".."));
            var samplesDir = Path.Combine(repoRoot, "samples", "threats");
            if (Directory.Exists(samplesDir))
            {
                foreach (var file in Directory.EnumerateFiles(samplesDir, "*.json"))
                {
                    try
                    {
                        var json = await File.ReadAllTextAsync(file);
                        var model = ThreatSerializer.FromJson(json);
                        var issues = ThreatValidator.Validate(model);
                        if (issues.Any(i => i.Severity == CrossSigEngine.Core.Validation.ValidationSeverity.Error)) continue;
                        var name = model.Name ?? Path.GetFileNameWithoutExtension(file);
                        var family = model.Family ?? string.Empty;
                        var exists = await db.Threats.AnyAsync(t => t.Name == name && t.Family == family);
                        if (exists) continue;
                        var tagsCsv = (model.Tags != null && model.Tags.Count > 0) ? string.Join(",", model.Tags) : null;
                        db.Threats.Add(new ThreatEntity { Name = name, Family = family, TagsCsv = tagsCsv, Json = json });
                    }
                    catch { }
                }
                await db.SaveChangesAsync();
            }
        }
        catch { }
    }
}

IRuleGenerator[] AllGenerators() => new IRuleGenerator[]
{
    new YaraGenerator(), new SnortSuricataGenerator(), new SigmaGenerator(), new ClamAvGenerator(), new IOCGenerator(), new PeidGenerator(), new CustomPatternGenerator(), new ZeekGenerator()
};

IRuleGenerator[] FamilyGenerators(string fam) => fam.ToLowerInvariant() switch
{
    "yara" => new IRuleGenerator[] { new YaraGenerator() },
    "snort" or "suricata" => new IRuleGenerator[] { new SnortSuricataGenerator() },
    "sigma" => new IRuleGenerator[] { new SigmaGenerator() },
    "clamav" => new IRuleGenerator[] { new ClamAvGenerator() },
    "ioc" => new IRuleGenerator[] { new IOCGenerator() },
    "peid" => new IRuleGenerator[] { new PeidGenerator() },
    "custom" => new IRuleGenerator[] { new CustomPatternGenerator() },
    "zeek" => new IRuleGenerator[] { new ZeekGenerator() },
    "all" => AllGenerators(),
    _ => Array.Empty<IRuleGenerator>()
};

app.MapPost("/api/validate", async (HttpRequest req) =>
{
    using var reader = new StreamReader(req.Body, Encoding.UTF8);
    var json = await reader.ReadToEndAsync();
    var model = ThreatSerializer.FromJson(json);
    var issues = ThreatValidator.Validate(model);
    return Results.Json(issues);
});

app.MapPost("/api/generate", async (HttpRequest req) =>
{
    var fam = req.Query["family"].FirstOrDefault() ?? "all";
    using var reader = new StreamReader(req.Body, Encoding.UTF8);
    var json = await reader.ReadToEndAsync();
    var model = ThreatSerializer.FromJson(json);
    var issues = ThreatValidator.Validate(model);
    if (issues.Any(i => i.Severity == CrossSigEngine.Core.Validation.ValidationSeverity.Error))
        return Results.BadRequest(new { message = "Validation errors", issues });

    var gens = FamilyGenerators(fam);
    if (gens.Length == 0) return Results.BadRequest(new { message = $"Unknown family: {fam}" });

    var files = new Dictionary<string, string>();
    foreach (var g in gens)
        foreach (var kv in g.Generate(model)) files[kv.Key] = kv.Value;

    return Results.Json(files);
});

app.MapPost("/api/scan/upload", async (HttpRequest req) =>
{
    // multipart/form-data with fields: model (json), file (binary)
    if (!req.HasFormContentType) return Results.BadRequest(new { message = "Expected multipart/form-data" });
    var form = await req.ReadFormAsync();
    var modelJson = form["model"].FirstOrDefault();
    if (string.IsNullOrWhiteSpace(modelJson)) return Results.BadRequest(new { message = "Missing model" });
    var model = ThreatSerializer.FromJson(modelJson!);
    var issues = ThreatValidator.Validate(model);
    if (issues.Any(i => i.Severity == CrossSigEngine.Core.Validation.ValidationSeverity.Error))
        return Results.BadRequest(new { message = "Validation errors", issues });

    var file = form.Files["file"];
    if (file is null) return Results.BadRequest(new { message = "Missing file" });
    byte[] bytes;
    using (var ms = new MemoryStream())
    {
        await file.CopyToAsync(ms);
        bytes = ms.ToArray();
    }
    var tmp = Path.GetTempFileName();
    await File.WriteAllBytesAsync(tmp, bytes);
    try
    {
        var events = FileScanner.ScanFile(model, tmp).ToList();
        return Results.Json(new { matches = events });
    }
    finally { try { File.Delete(tmp); } catch { } }
});

app.MapPost("/api/scan/path", async (HttpRequest http) =>
{
    DirScanRequest? req;
    try
    {
        req = await System.Text.Json.JsonSerializer.DeserializeAsync<DirScanRequest>(http.Body);
    }
    catch
    {
        return Results.BadRequest(new { message = "Invalid JSON" });
    }
    if (req is null || string.IsNullOrWhiteSpace(req.Model) || string.IsNullOrWhiteSpace(req.Path))
        return Results.BadRequest(new { message = "Missing Model or Path" });

    var model = ThreatSerializer.FromJson(req.Model!);
    var issues = ThreatValidator.Validate(model);
    if (issues.Any(i => i.Severity == CrossSigEngine.Core.Validation.ValidationSeverity.Error))
        return Results.BadRequest(new { message = "Validation errors", issues });

    // Perform scan
    var events = FileScanner
        .ScanPath(model, req.Path!, req.Recursive, Math.Max(1, req.Parallel), req.Exclude, Math.Max(0, req.MaxFileSizeBytes))
        .ToList();

    // Optional alert sinks
    var sinks = new List<IAlertSink>();
    if (!string.IsNullOrWhiteSpace(req.Webhook))
        sinks.Add(new WebhookAlertSink(req.Webhook!, req.WebhookHeaders, req.WebhookFormat));
    if (!string.IsNullOrWhiteSpace(req.EventLogSource))
        sinks.Add(new WindowsEventLogAlertSink(req.EventLogSource!));

    if (sinks.Count > 0)
    {
        foreach (var e in events)
        {
            var record = new AlertRecord(
                RuleName: model.Name,
                Family: model.Family,
                Source: "web-scan",
                Timestamp: DateTimeOffset.UtcNow,
                Event: e);
            foreach (var sink in sinks)
            {
                try { await sink.WriteAsync(record); } catch { }
            }
            if (!string.IsNullOrWhiteSpace(req.Webhook) && req.WebhookDelayMs > 0)
            {
                try { await Task.Delay(req.WebhookDelayMs); } catch { }
            }
        }
    }

    var status = (req.FailOnMatch && events.Count > 0) ? 409 : 200;
    return Results.Json(new { count = events.Count, matches = events }, statusCode: status);
});

// Threats API
app.MapGet("/api/threats/{id:int}", async (AppDbContext db, int id) =>
{
    var e = await db.Threats.FindAsync(id);
    return e is null ? Results.NotFound() : Results.Json(e);
});

app.MapDelete("/api/threats/{id:int}", async (AppDbContext db, int id) =>
{
    var e = await db.Threats.FindAsync(id);
    if (e is null) return Results.NotFound();
    db.Threats.Remove(e);
    await db.SaveChangesAsync();
    return Results.NoContent();
});

app.MapPost("/api/threats", async (AppDbContext db, HttpRequest req) =>
{
    using var reader = new StreamReader(req.Body, Encoding.UTF8);
    var json = await reader.ReadToEndAsync();
    var model = ThreatSerializer.FromJson(json);
    var issues = ThreatValidator.Validate(model);
    if (issues.Any(i => i.Severity == CrossSigEngine.Core.Validation.ValidationSeverity.Error))
        return Results.BadRequest(new { message = "Validation errors", issues });
    var nm = model.Name ?? "Untitled"; var fam = model.Family ?? string.Empty;
    if (await db.Threats.AnyAsync(t => t.Name == nm && t.Family == fam))
        return Results.Conflict(new { message = "Duplicate (name+family)" });
    var tagsCsv = (model.Tags != null && model.Tags.Count > 0) ? string.Join(",", model.Tags) : null;
    var ent = new ThreatEntity { Name = nm, Family = fam, TagsCsv = tagsCsv, Json = json };
    db.Threats.Add(ent);
    await db.SaveChangesAsync();
    return Results.Created($"/api/threats/{ent.Id}", ent);
});

app.MapGet("/api/threats", async (AppDbContext db, string? q, string? query, string? family, string? tag, int page = 1, int pageSize = 20) =>
{
    // Support both 'q' and 'query' for search term
    var term = string.IsNullOrWhiteSpace(q) ? query : q;

    var qset = db.Threats.AsQueryable();

    // Case-insensitive contains across Name, Family, and JSON
    if (!string.IsNullOrWhiteSpace(term))
    {
        var termLower = term.ToLower();
        qset = qset.Where(t =>
            (t.Name != null && t.Name.ToLower().Contains(termLower)) ||
            (t.Family != null && t.Family.ToLower().Contains(termLower)) ||
            (t.Json != null && t.Json.ToLower().Contains(termLower))
        );
    }

    // Family filter (case-insensitive). Allow partial contains for convenience.
    if (!string.IsNullOrWhiteSpace(family))
    {
        var familyLower = family.ToLower();
        qset = qset.Where(t => t.Family != null && t.Family.ToLower().Contains(familyLower));
    }

    // Tag filter (case-insensitive) across CSV and JSON
    if (!string.IsNullOrWhiteSpace(tag))
    {
        var tagLower = tag.ToLower();
        qset = qset.Where(t => (t.TagsCsv != null && t.TagsCsv.ToLower().Contains(tagLower)) || (t.Json != null && t.Json.ToLower().Contains(tagLower)));
    }

    var total = await qset.CountAsync();
    var items = await qset
        .OrderByDescending(t => t.Id)
        .Skip(Math.Max(0, (page - 1) * pageSize))
        .Take(Math.Max(1, pageSize))
        .ToListAsync();
    return Results.Json(new { total, items });
});

// Export all threats to CSV (id,name,family,tags,createdUtc)
app.MapGet("/api/threats/export", async (AppDbContext db) =>
{
    var items = await db.Threats.OrderBy(t => t.Id).ToListAsync();
    var sb = new StringBuilder();
    sb.AppendLine("id,name,family,tags,createdUtc");
    foreach (var t in items)
    {
        string esc(string s) => s.Contains(',') ? $"\"{s.Replace("\"", "\"\"")}\"" : s;
        sb.AppendLine(string.Join(',', new[]
        {
            t.Id.ToString(),
            esc(t.Name ?? string.Empty),
            esc(t.Family ?? string.Empty),
            esc(t.TagsCsv ?? string.Empty),
            esc(t.CreatedUtc.ToString("o"))
        }));
    }
    var bytes = Encoding.UTF8.GetBytes(sb.ToString());
    return Results.File(bytes, "text/csv", fileDownloadName: $"threats_{DateTime.UtcNow:yyyyMMddHHmmss}.csv");
});

// Bulk import JSON ThreatModels (multipart form: files[])
app.MapPost("/api/threats/import", async (AppDbContext db, HttpRequest req) =>
{
    if (!req.HasFormContentType) return Results.BadRequest(new { message = "Expected multipart/form-data" });
    var form = await req.ReadFormAsync();
    var files = form.Files.Where(f => f.FileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase)).ToList();
    if (files.Count == 0) return Results.BadRequest(new { message = "No .json files provided" });
    int ok = 0, bad = 0;
    foreach (var f in files)
    {
        try
        {
            using var sr = new StreamReader(f.OpenReadStream(), Encoding.UTF8);
            var json = await sr.ReadToEndAsync();
            var model = ThreatSerializer.FromJson(json);
            var issues = ThreatValidator.Validate(model);
            if (issues.Any(i => i.Severity == CrossSigEngine.Core.Validation.ValidationSeverity.Error)) { bad++; continue; }
            var nm = model.Name ?? f.FileName; var fam = model.Family ?? string.Empty;
            if (await db.Threats.AnyAsync(t => t.Name == nm && t.Family == fam)) { bad++; continue; }
            var tagsCsv = (model.Tags != null && model.Tags.Count > 0) ? string.Join(",", model.Tags) : null;
            db.Threats.Add(new ThreatEntity { Name = nm, Family = fam, TagsCsv = tagsCsv, Json = json });
            ok++;
        }
        catch { bad++; }
    }
    await db.SaveChangesAsync();
    return Results.Ok(new { imported = ok, skipped = bad });
});

// Import JSON ThreatModels from a server directory
app.MapPost("/api/threats/import-path", async (AppDbContext db, HttpRequest req) =>
{
    try
    {
        var body = await System.Text.Json.JsonSerializer.DeserializeAsync<Dictionary<string, object>>(req.Body) ?? new();
        var path = body.TryGetValue("path", out var p) ? Convert.ToString(p) : null;
        var recursive = body.TryGetValue("recursive", out var r) && bool.TryParse(Convert.ToString(r), out var b) ? b : false;
        var pattern = body.TryGetValue("pattern", out var pat) ? (Convert.ToString(pat) ?? "*.json") : "*.json";
        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path)) return Results.BadRequest(new { message = "Invalid or missing path" });
        var files = Directory.EnumerateFiles(path, pattern, recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly)
            .Where(f => f.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (files.Count == 0) return Results.Ok(new { imported = 0, skipped = 0, message = "No files" });
        int ok = 0, bad = 0;
        foreach (var file in files)
        {
            try
            {
                var json = await File.ReadAllTextAsync(file);
                var model = ThreatSerializer.FromJson(json);
                var issues = ThreatValidator.Validate(model);
                if (issues.Any(i => i.Severity == CrossSigEngine.Core.Validation.ValidationSeverity.Error)) { bad++; continue; }
                var nm = model.Name ?? Path.GetFileNameWithoutExtension(file); var fam = model.Family ?? string.Empty;
                if (await db.Threats.AnyAsync(t => t.Name == nm && t.Family == fam)) { bad++; continue; }
                var tagsCsv = (model.Tags != null && model.Tags.Count > 0) ? string.Join(",", model.Tags) : null;
                db.Threats.Add(new ThreatEntity { Name = nm, Family = fam, TagsCsv = tagsCsv, Json = json });
                ok++;
            }
            catch { bad++; }
        }
        await db.SaveChangesAsync();
        return Results.Ok(new { imported = ok, skipped = bad, total = files.Count });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { message = ex.Message });
    }
});

// Sandbox endpoints (free tier via VirusTotal)
app.MapPost("/api/sandbox/upload", async (HttpRequest req) =>
{
    if (!req.HasFormContentType) return Results.BadRequest(new { message = "Expected multipart/form-data" });
    var form = await req.ReadFormAsync();
    var provider = (form["provider"].FirstOrDefault() ?? "vt").ToLowerInvariant();
    ISandboxClient client;
    if (provider == "vt")
    {
        var apiKey = form["apiKey"].FirstOrDefault() ?? Environment.GetEnvironmentVariable("VT_API_KEY");
        if (string.IsNullOrWhiteSpace(apiKey)) return Results.BadRequest(new { message = "Missing apiKey (or set VT_API_KEY env var)" });
        client = new VirusTotalSandboxClient(apiKey);
    }
    else if (provider == "cuckoo")
    {
        var baseUrl = form["baseUrl"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(baseUrl)) return Results.BadRequest(new { message = "Missing baseUrl for Cuckoo (e.g., http://localhost:8090/api/)" });
        var apiKey = form["apiKey"].FirstOrDefault();
        client = new CuckooSandboxClient(baseUrl!, apiKey);
    }
    else return Results.BadRequest(new { message = "Unsupported provider" });
    var file = form.Files["file"];
    if (file is null) return Results.BadRequest(new { message = "Missing file" });
    // Save temp file
    var tmp = Path.GetTempFileName();
    await using (var fs = File.OpenWrite(tmp)) { await file.CopyToAsync(fs); }
    try
    {
    var res = await client.AnalyzeFileAsync(tmp);
        return Results.Json(res);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { message = ex.Message });
    }
    finally { try { File.Delete(tmp); } catch { } }
});

app.MapPost("/api/sandbox/url", async (HttpRequest req) =>
{
    using var reader = new StreamReader(req.Body, Encoding.UTF8);
    var json = await reader.ReadToEndAsync();
    if (string.IsNullOrWhiteSpace(json)) return Results.BadRequest(new { message = "Missing body" });
    try
    {
        var obj = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? new();
        var provider = (obj.TryGetValue("provider", out var p) ? p : "vt").ToLowerInvariant();
        if (!obj.TryGetValue("url", out var target) || string.IsNullOrWhiteSpace(target)) return Results.BadRequest(new { message = "Missing url" });
        ISandboxClient client;
        if (provider == "vt")
        {
            var apiKey = (obj.TryGetValue("apiKey", out var k) ? k : null) ?? Environment.GetEnvironmentVariable("VT_API_KEY");
            if (string.IsNullOrWhiteSpace(apiKey)) return Results.BadRequest(new { message = "Missing apiKey (or set VT_API_KEY env var)" });
            client = new VirusTotalSandboxClient(apiKey);
        }
        else if (provider == "cuckoo")
        {
            if (!obj.TryGetValue("baseUrl", out var baseUrl) || string.IsNullOrWhiteSpace(baseUrl)) return Results.BadRequest(new { message = "Missing baseUrl for Cuckoo (e.g., http://localhost:8090/api/)" });
            var apiKey = (obj.TryGetValue("apiKey", out var k2) ? k2 : null);
            client = new CuckooSandboxClient(baseUrl!, apiKey);
        }
        else return Results.BadRequest(new { message = "Unsupported provider" });
        var res = await client.AnalyzeUrlAsync(target);
        return Results.Json(res);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { message = ex.Message });
    }
});

// Liveness and version info
app.MapGet("/healthz", () => Results.Ok(new { status = "ok" }));
app.MapGet("/version", () => Results.Ok(new { version = System.Reflection.Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "unknown" }));

app.Run();
