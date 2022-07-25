using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Phoenix.DataHandle.Api;
using Phoenix.DataHandle.Identity;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Configure Web Host Defaults
builder.WebHost.ConfigureKestrel(options => options.AddServerHeader = false);

// Add services to the container.

builder.Services.AddDbContext<ApplicationContext>(o =>
    o.UseLazyLoadingProxies()
    .UseSqlServer(builder.Configuration.GetConnectionString("PhoenixConnection")));

builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(o =>
{
    o.User.AllowedUserNameCharacters = null;
    o.Password.RequireDigit = false;
    o.Password.RequireLowercase = false;
    o.Password.RequireNonAlphanumeric = false;
    o.Password.RequireUppercase = false;
    o.Password.RequiredLength = 6;
})
    .AddRoles<ApplicationRole>()
    .AddUserStore<ApplicationStore>()
    .AddUserManager<ApplicationUserManager>()
    .AddEntityFrameworkStores<ApplicationContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            //ValidAudiences = builder.Configuration.GetSection("Jwt:Audiences").Get<string[]>(),
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
        };
    });

builder.Services.AddApplicationInsightsTelemetry(
    o => o.ConnectionString = builder.Configuration["ApplicationInsights:ConnectionString"]);

builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();
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

    var jwtSecurityScheme = new OpenApiSecurityScheme
    {
        Scheme = "bearer",
        BearerFormat = "JWT",
        Description = "Enter the JWT Bearer token.",
        In = ParameterLocation.Header,
        Name = "JWT Authentication",
        Type = SecuritySchemeType.Http,

        Reference = new OpenApiReference
        {
            Id = JwtBearerDefaults.AuthenticationScheme,
            Type = ReferenceType.SecurityScheme
        }
    };
    o.AddSecurityDefinition(jwtSecurityScheme.Reference.Id, jwtSecurityScheme);

    o.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        { jwtSecurityScheme, Array.Empty<string>() }
    });

    o.SchemaFilter<SwaggerExcludeFilter>();
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

// TODO: Hide Swagger documentation
app.UseSwagger();
app.UseSwaggerUI(o => o.SwaggerEndpoint("/swagger/v3/swagger.json", "Sphinx v3"));

app.UseHttpsRedirection();

app.UseCors(builder => builder.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();