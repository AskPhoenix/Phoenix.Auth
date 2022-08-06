using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Phoenix.DataHandle.Identity;
using Phoenix.DataHandle.Main.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Configure Web Host Defaults
builder.WebHost.ConfigureKestrel(options => options.AddServerHeader = false);

// Add services to the container.
Action<DbContextOptionsBuilder> buildDbContextOptions = o => o
    .UseLazyLoadingProxies()
    .UseSqlServer(builder.Configuration.GetConnectionString("PhoenixConnection"));

builder.Services.AddDbContext<ApplicationContext>(buildDbContextOptions);
builder.Services.AddDbContext<PhoenixContext>(buildDbContextOptions);

builder.Services.AddIdentity<ApplicationUser, ApplicationRole>()
    .AddRoles<ApplicationRole>()
    .AddUserStore<ApplicationStore>()
    .AddUserManager<ApplicationUserManager>()
    .AddEntityFrameworkStores<ApplicationContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateLifetime = true,
            ValidateAudience = false,
            ValidateIssuer = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
        };
    });

builder.Services.AddApplicationInsightsTelemetry(
    o => o.ConnectionString = builder.Configuration["ApplicationInsights:ConnectionString"]);

builder.Services.AddControllers();
builder.Services.AddHttpsRedirection(options => options.HttpsPort = 443);
builder.Services.AddRouting(o => o.LowercaseUrls = true);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGenNewtonsoftSupport();
builder.Services.AddSwaggerGen(o =>
{
    o.EnableAnnotations();

    // SwaggerDoc name refers to the name of the documention and is included in the endpoint path
    o.SwaggerDoc("v3", new OpenApiInfo()
    {
        Title = "Sphinx API",
        Description = "An authentication API for the Phoenix backend",
        Version = "3.0"
    });
});

// Configure Logging
// TODO: Create File Logging & on app insights
builder.Logging.ClearProviders()
    .AddConfiguration(builder.Configuration.GetSection("Logging"))
    .SetMinimumLevel(LogLevel.Trace)
    .AddSimpleConsole()
    .AddDebug();


var app = builder.Build();


// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    // app.UseDatabaseErrorPage();
}
else
{
    app.UseHsts();
}

// Configure the HTTP request pipeline.
// if (app.Environment.IsDevelopment() || app.Environment.IsStaging())
app.UseSwagger(o => o.RouteTemplate = "/doc/{documentname}/swagger.json");
app.UseSwaggerUI(o => 
{
    o.SwaggerEndpoint("/doc/v3/swagger.json", "Sphinx v3");
    o.RoutePrefix = "doc";
});

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
