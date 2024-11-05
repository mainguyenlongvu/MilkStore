using dotenv.net;
using MilkStore.API;
using MilkStore.API.Middleware;
using MilkStore.Services.Configs;


DotEnv.Load();

WebApplicationBuilder? builder = WebApplication.CreateBuilder(args);

// config appsettings by env
builder.Services.AddConfig(builder.Configuration);
builder.Configuration
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables();

builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        //options.JsonSerializerOptions.ReferenceHandler = System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles;
        options.JsonSerializerOptions.DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull;
        options.JsonSerializerOptions.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter());

    });



builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
WebApplication? app = builder.Build();

// Configure the HTTP request pipeline.
app.UseCors("AllowAllOrigins");
app.UseSwagger();
app.UseSwaggerUI();

app.UseMiddleware<ExceptionMiddleware>();

app.UseHttpsRedirection();


app.UseAuthentication();
app.UseAuthorization();

app.MapHub<ChatHub>("/chathub").RequireAuthorization();

app.UseSession();

app.MapControllers();

////Seed Data
//using (IServiceScope scope = app.Services.CreateScope())
//{
//    IServiceProvider? services = scope.ServiceProvider;
//    SeedDataAccount.SeedAsync(services).Wait();
//}
app.Run();
